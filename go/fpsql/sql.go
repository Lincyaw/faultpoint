// Package fpsql places store_read and store_write points on a database/sql driver.
package fpsql

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"

	"faultpoint"

	"github.com/DataDog/go-sqllexer"
	"github.com/ngrok/sqlmw"
)

// ErrInjected is the error of a store point under a fail or fail_after rule.
var ErrInjected = errors.New("faultpoint: injected store failure")

type statement struct {
	kind    faultpoint.Kind
	locator string
}

var (
	statements sync.Map
	obfuscator = sqllexer.NewObfuscator()
	normalizer = sqllexer.NewNormalizer(sqllexer.WithCollectTables(true), sqllexer.WithCollectCommands(true))
)

// statementPoint is the kind and locator of a statement: the tables it touches and the hash of
// its shape with literals removed.
func statementPoint(query string) statement {
	if known, found := statements.Load(query); found {
		return known.(statement)
	}
	shape, metadata, err := sqllexer.ObfuscateAndNormalize(query, obfuscator, normalizer)
	if err != nil {
		panic("faultpoint: cannot normalize a statement: " + err.Error())
	}
	kind := faultpoint.KindStoreRead
	for _, command := range metadata.Commands {
		if !strings.EqualFold(command, "SELECT") {
			kind = faultpoint.KindStoreWrite
		}
	}
	if len(metadata.Commands) == 0 {
		kind = faultpoint.KindStoreWrite
	}
	tables := append([]string{}, metadata.Tables...)
	sort.Strings(tables)
	tableList := strings.Join(tables, "+")
	if tableList == "" {
		tableList = "-"
	}
	digest := sha256.Sum256([]byte(shape))
	known := statement{kind: kind, locator: tableList + "#" + hex.EncodeToString(digest[:])[:8]}
	statements.Store(query, known)
	return known
}

type queryKey struct{}

type query struct {
	point string
	rule  *faultpoint.Rule
	empty bool
	rows  int
}

type interceptor struct{ sqlmw.NullInterceptor }

// Wrap returns a driver whose statements are store points; register it with sql.Register.
func Wrap(base driver.Driver) driver.Driver { return sqlmw.Driver(base, interceptor{}) }

func begin(ctx context.Context, sql string) (string, *faultpoint.Rule, faultpoint.Action) {
	known := statementPoint(sql)
	point := faultpoint.PointID(faultpoint.Service(), known.kind, known.locator)
	rule := faultpoint.Decide(ctx, point)
	if rule == nil {
		return point, nil, faultpoint.Action{}
	}
	faultpoint.Hold(rule.Action)
	return point, rule, rule.Action
}

func exec(ctx context.Context, sql string, run func() (driver.Result, error)) (driver.Result, error) {
	if !faultpoint.Enabled() {
		return run()
	}
	point, rule, action := begin(ctx, sql)
	switch action.Kind {
	case faultpoint.ActionFail:
		faultpoint.Record(ctx, point, "error", 0, rule)
		return nil, ErrInjected
	case faultpoint.ActionDrop:
		faultpoint.Record(ctx, point, "ok", 1, rule)
		return driver.RowsAffected(1), nil
	}
	result, err := run()
	if err == nil && action.Kind == faultpoint.ActionDuplicate {
		result, err = run()
	}
	if err == nil && action.Kind == faultpoint.ActionFailAfter {
		err = ErrInjected
	}
	if err != nil {
		faultpoint.Record(ctx, point, "error", 0, rule)
		return nil, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		affected = 0
	}
	faultpoint.Record(ctx, point, "ok", float64(affected), rule)
	return result, nil
}

func read(ctx context.Context, sql string, run func() (context.Context, driver.Rows, error)) (context.Context, driver.Rows, error) {
	if !faultpoint.Enabled() {
		return run()
	}
	point, rule, action := begin(ctx, sql)
	if action.Kind == faultpoint.ActionFail {
		faultpoint.Record(ctx, point, "error", 0, rule)
		return ctx, nil, ErrInjected
	}
	ctx, rows, err := run()
	if err != nil {
		faultpoint.Record(ctx, point, "error", 0, rule)
		return ctx, nil, err
	}
	return context.WithValue(ctx, queryKey{}, &query{point: point, rule: rule, empty: action.Kind == faultpoint.ActionEmpty}), rows, nil
}

func (interceptor) ConnExecContext(ctx context.Context, conn driver.ExecerContext, sql string, args []driver.NamedValue) (driver.Result, error) {
	return exec(ctx, sql, func() (driver.Result, error) { return conn.ExecContext(ctx, sql, args) })
}

func (interceptor) StmtExecContext(ctx context.Context, stmt driver.StmtExecContext, sql string, args []driver.NamedValue) (driver.Result, error) {
	return exec(ctx, sql, func() (driver.Result, error) { return stmt.ExecContext(ctx, args) })
}

func (interceptor) ConnQueryContext(ctx context.Context, conn driver.QueryerContext, sql string, args []driver.NamedValue) (context.Context, driver.Rows, error) {
	return read(ctx, sql, func() (context.Context, driver.Rows, error) {
		rows, err := conn.QueryContext(ctx, sql, args)
		return ctx, rows, err
	})
}

func (interceptor) StmtQueryContext(ctx context.Context, stmt driver.StmtQueryContext, sql string, args []driver.NamedValue) (context.Context, driver.Rows, error) {
	return read(ctx, sql, func() (context.Context, driver.Rows, error) {
		rows, err := stmt.QueryContext(ctx, args)
		return ctx, rows, err
	})
}

func (interceptor) RowsNext(ctx context.Context, rows driver.Rows, dest []driver.Value) error {
	state, found := ctx.Value(queryKey{}).(*query)
	if found && state.empty {
		return io.EOF
	}
	err := rows.Next(dest)
	if found && err == nil {
		state.rows++
	}
	return err
}

// RowsClose records a read's outcome once its rows are counted.
func (interceptor) RowsClose(ctx context.Context, rows driver.Rows) error {
	if state, found := ctx.Value(queryKey{}).(*query); found {
		outcome := "empty"
		if state.rows > 0 {
			outcome = "rows"
		}
		faultpoint.Record(ctx, state.point, outcome, float64(state.rows), state.rule)
	}
	return rows.Close()
}
