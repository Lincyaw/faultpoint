// Package fpsql is the adapter plugin of database/sql: store_read and store_write points on the statements of a
// wrapped driver, classified by their SQL commands.
package fpsql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"slices"
	"sync"

	"faultpoint"
	"faultpoint/internal/action"
	"faultpoint/internal/sqlpoint"

	"github.com/ngrok/sqlmw"
)

const instrumentedPrefix = "faultpoint:"

var (
	enabled    bool
	classifier *sqlpoint.Classifier
	drivers    sync.Mutex
)

func init() {
	options := struct {
		ReadCommands []string `json:"read_commands"`
	}{ReadCommands: []string{"SELECT"}}
	enabled = faultpoint.Register(faultpoint.Plugin{Name: "sql", Options: &options, Actions: map[string][]string{
		"store_read":  {"fail", "empty", "delay", "crash"},
		"store_write": {"fail", "fail_after", "drop", "duplicate", "delay", "crash"},
	}})
	classifier = sqlpoint.NewClassifier(options.ReadCommands)
}

// DriverName is the name of a driver whose statements are store points, wrapping the driver registered under
// name; it returns name unchanged when the plugin is not enabled.
func DriverName(name string) string {
	if !enabled {
		return name
	}
	drivers.Lock()
	defer drivers.Unlock()
	instrumented := instrumentedPrefix + name
	if slices.Contains(sql.Drivers(), instrumented) {
		return instrumented
	}
	// An unknown driver name is left for the caller's sql.Open to report as it would without faultpoint.
	database, err := sql.Open(name, "")
	if err != nil {
		return name
	}
	defer database.Close()
	sql.Register(instrumented, sqlmw.Driver(database.Driver(), interceptor{}))
	return instrumented
}

// begin decides the rule of a statement's point and performs its delay or crash.
func begin(ctx context.Context, query string) (string, *faultpoint.Rule, string) {
	known := classifier.Classify(query)
	point := faultpoint.PointID(faultpoint.Service(), known.Kind, known.Locator)
	rule := faultpoint.Decide(ctx, point)
	if rule == nil {
		return point, nil, ""
	}
	action.Hold(rule)
	return point, rule, rule.Action.Kind
}

func exec(ctx context.Context, query string, run func() (driver.Result, error)) (driver.Result, error) {
	point, rule, kind := begin(ctx, query)
	var result driver.Result
	var err error
	switch kind {
	case "fail":
		err = action.Failure(rule)
	case "drop":
		result = driver.RowsAffected(1)
	default:
		result, err = run()
	}
	if err == nil && kind == "duplicate" {
		result, err = run()
	}
	if err == nil && kind == "fail_after" {
		err = action.Failure(rule)
	}
	if err != nil {
		faultpoint.Observe(ctx, point, "error", 0, rule)
		return nil, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		affected = 0
	}
	faultpoint.Observe(ctx, point, "ok", float64(affected), rule)
	return result, nil
}

type queryKey struct{}

// query is a read in progress, whose outcome is observed when its rows are closed.
type query struct {
	point string
	rule  *faultpoint.Rule
	empty bool
	rows  int
}

func read(ctx context.Context, sql string, run func() (driver.Rows, error)) (context.Context, driver.Rows, error) {
	point, rule, kind := begin(ctx, sql)
	var rows driver.Rows
	var err error
	if kind == "fail" {
		err = action.Failure(rule)
	} else {
		rows, err = run()
	}
	if err != nil {
		faultpoint.Observe(ctx, point, "error", 0, rule)
		return ctx, nil, err
	}
	return context.WithValue(ctx, queryKey{}, &query{point: point, rule: rule, empty: kind == "empty"}), rows, nil
}

type interceptor struct{ sqlmw.NullInterceptor }

func (interceptor) ConnExecContext(ctx context.Context, conn driver.ExecerContext, sql string, args []driver.NamedValue) (driver.Result, error) {
	return exec(ctx, sql, func() (driver.Result, error) { return conn.ExecContext(ctx, sql, args) })
}

func (interceptor) StmtExecContext(ctx context.Context, stmt driver.StmtExecContext, sql string, args []driver.NamedValue) (driver.Result, error) {
	return exec(ctx, sql, func() (driver.Result, error) { return stmt.ExecContext(ctx, args) })
}

func (interceptor) ConnQueryContext(ctx context.Context, conn driver.QueryerContext, sql string, args []driver.NamedValue) (context.Context, driver.Rows, error) {
	return read(ctx, sql, func() (driver.Rows, error) { return conn.QueryContext(ctx, sql, args) })
}

func (interceptor) StmtQueryContext(ctx context.Context, stmt driver.StmtQueryContext, sql string, args []driver.NamedValue) (context.Context, driver.Rows, error) {
	return read(ctx, sql, func() (driver.Rows, error) { return stmt.QueryContext(ctx, args) })
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

// RowsClose observes a read's outcome once its rows are counted.
func (interceptor) RowsClose(ctx context.Context, rows driver.Rows) error {
	if state, found := ctx.Value(queryKey{}).(*query); found {
		outcome := "empty"
		if state.rows > 0 {
			outcome = "rows"
		}
		faultpoint.Observe(ctx, state.point, outcome, float64(state.rows), state.rule)
	}
	return rows.Close()
}
