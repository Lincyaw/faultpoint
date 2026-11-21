// Package fpsql is the adapter plugin of database/sql: store_read and store_write points on the statements of a
// wrapped driver, classified by their SQL commands.
package fpsql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
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
	// uncoded are the wrapped drivers without a builder in sqlpoint.CodedErrors, by package and type name.
	uncoded sync.Map
)

func init() {
	options := struct {
		ReadCommands []string `json:"read_commands"`
	}{ReadCommands: []string{"SELECT"}}
	enabled = faultpoint.Register(faultpoint.Plugin{Name: "sql", Options: &options, Refuse: refuse,
		Serves: sqlpoint.StatementLocator.MatchString, Actions: map[string][]string{
			"store_read":  {"fail", "empty", "delay", "crash"},
			"store_write": {"fail", "fail_after", "drop", "duplicate", "delay", "crash"},
		}})
	classifier = sqlpoint.NewClassifier(options.ReadCommands)
}

// refuse is why a fail rule at a statement's point cannot name a code in this process: a driver it wraps has no error
// the plugin can build with one, and a statement's point does not tell which driver, or pgx, runs it.
func refuse(rule *faultpoint.Rule) error {
	if rule.Action.Kind != "fail" && rule.Action.Kind != "fail_after" {
		return nil
	}
	var params struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rule.Action.Params, &params); err != nil {
		return err
	}
	var names []string
	uncoded.Range(func(name, _ any) bool {
		names = append(names, name.(string))
		return true
	})
	if params.Code == "" || len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	return fmt.Errorf("the database/sql driver %s of this process has no error faultpoint can build with code %s",
		strings.Join(names, ", "), params.Code)
}

// DriverName is the name of a driver whose statements are store points, wrapping the driver registered under
// name; it returns name unchanged when the plugin is not enabled. A driver without a builder in
// sqlpoint.CodedErrors makes the rules in force, and those installed later, refuse a code.
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
	wrapped := database.Driver()
	driverType := reflect.TypeOf(wrapped)
	if driverType.Kind() == reflect.Pointer {
		driverType = driverType.Elem()
	}
	coded, known := sqlpoint.CodedErrors[driverType.PkgPath()]
	if !known {
		uncoded.Store(driverType.PkgPath()+"."+driverType.Name(), true)
		faultpoint.Recheck()
	}
	sql.Register(instrumented, sqlmw.Driver(wrapped, interceptor{coded: coded}))
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

func (i interceptor) exec(ctx context.Context, query string, run func() (driver.Result, error)) (driver.Result, error) {
	point, rule, kind := begin(ctx, query)
	var result driver.Result
	var err error
	switch kind {
	case "fail":
		err = action.Failure(rule, i.coded)
	case "drop":
		result = driver.RowsAffected(1)
	default:
		result, err = run()
	}
	if err == nil && kind == "duplicate" {
		result, err = run()
	}
	if err == nil && kind == "fail_after" {
		err = action.Failure(rule, i.coded)
	}
	if err != nil {
		faultpoint.Observe(ctx, point, "error", 0, rule, sqlpoint.ErrorDetail(err))
		return nil, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		affected = 0
	}
	faultpoint.Observe(ctx, point, "ok", float64(affected), rule, nil)
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

func (i interceptor) read(ctx context.Context, sql string, run func() (driver.Rows, error)) (context.Context, driver.Rows, error) {
	point, rule, kind := begin(ctx, sql)
	var rows driver.Rows
	var err error
	if kind == "fail" {
		err = action.Failure(rule, i.coded)
	} else {
		rows, err = run()
	}
	if err != nil {
		faultpoint.Observe(ctx, point, "error", 0, rule, sqlpoint.ErrorDetail(err))
		return ctx, nil, err
	}
	return context.WithValue(ctx, queryKey{}, &query{point: point, rule: rule, empty: kind == "empty"}), rows, nil
}

// interceptor makes the statements of one wrapped driver store points; coded builds that driver's error with a code,
// nil for a driver without a builder in sqlpoint.CodedErrors.
type interceptor struct {
	sqlmw.NullInterceptor
	coded func(code string) error
}

func (i interceptor) ConnExecContext(ctx context.Context, conn driver.ExecerContext, sql string, args []driver.NamedValue) (driver.Result, error) {
	return i.exec(ctx, sql, func() (driver.Result, error) { return conn.ExecContext(ctx, sql, args) })
}

func (i interceptor) StmtExecContext(ctx context.Context, stmt driver.StmtExecContext, sql string, args []driver.NamedValue) (driver.Result, error) {
	return i.exec(ctx, sql, func() (driver.Result, error) { return stmt.ExecContext(ctx, args) })
}

func (i interceptor) ConnQueryContext(ctx context.Context, conn driver.QueryerContext, sql string, args []driver.NamedValue) (context.Context, driver.Rows, error) {
	return i.read(ctx, sql, func() (driver.Rows, error) { return conn.QueryContext(ctx, sql, args) })
}

func (i interceptor) StmtQueryContext(ctx context.Context, stmt driver.StmtQueryContext, sql string, args []driver.NamedValue) (context.Context, driver.Rows, error) {
	return i.read(ctx, sql, func() (driver.Rows, error) { return stmt.QueryContext(ctx, args) })
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
		faultpoint.Observe(ctx, state.point, outcome, float64(state.rows), state.rule, nil)
	}
	return rows.Close()
}
