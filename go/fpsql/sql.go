// Package fpsql is the adapter plugin of database/sql: store_read and store_write points on the statements of a
// wrapped driver, classified by their SQL commands.
package fpsql

import (
	"cmp"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

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
	defer faultpoint.Guard()
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
	sql.Register(instrumented, sqlmw.Driver(wrapped,
		interceptor{coded: coded, driverReached: sqlpoint.Reached[driverType.PkgPath()]}))
	return instrumented
}

// begin decides the rule of a statement's point that acts before it runs and performs its wait or crash; besides the
// point, the rule and its action, it returns the error the statement gets without being sent: the context's when
// the caller gave up during the wait, a fail rule's, or nil.
func (i interceptor) begin(ctx context.Context, query string) (string, *faultpoint.Rule, string, error) {
	defer faultpoint.Guard()
	known := classifier.Classify(query)
	point := faultpoint.PointID(faultpoint.Service(), known.Kind, known.Locator)
	rule := faultpoint.Decide(ctx, point, action.Before...)
	if rule == nil {
		return point, nil, "", nil
	}
	ended := action.Wait(ctx, rule)
	if ended == nil && rule.Action.Kind == "fail" {
		ended = action.Failure(rule, i.coded)
	}
	return point, rule, rule.Action.Kind, ended
}

func (i interceptor) exec(ctx context.Context, query string, run func() (driver.Result, error)) (driver.Result, error) {
	defer faultpoint.Guard()
	started := time.Now()
	point, rule, kind, err := i.begin(ctx, query)
	cut := err != nil
	var result driver.Result
	switch {
	case err == nil && kind == "drop":
		result = driver.RowsAffected(1)
	case err == nil:
		faultpoint.Outside(func() { result, err = run() })
	}
	if err == nil && kind == "duplicate" {
		faultpoint.Outside(func() { result, err = run() })
	}
	if err == nil && rule == nil {
		rule = faultpoint.Decide(ctx, point, "fail_after")
	}
	if err == nil && rule != nil && rule.Action.Kind == "fail_after" {
		err = action.Failure(rule, i.coded)
	}
	if err != nil {
		faultpoint.Observe(ctx, point, "error", 0, faultpoint.Elapsed(started), rule,
			action.Sent(sqlpoint.ErrorDetail(err), rule, cut, err, i.reached))
		return nil, err
	}
	var affected int64
	faultpoint.Outside(func() { affected, err = result.RowsAffected() })
	if err != nil {
		affected = 0
	}
	faultpoint.Observe(ctx, point, "ok", float64(affected), faultpoint.Elapsed(started), rule, nil)
	return result, nil
}

type queryKey struct{}

// query is a statement whose rows are being read, whose outcome is observed when its rows are closed; ended is
// whether reading them reached their end or an error, err is the error that ended them, the statement's own or a
// fail_after rule's, and started is when the statement entered its point.
type query struct {
	point   string
	rule    *faultpoint.Rule
	empty   bool
	rows    int
	ended   bool
	err     error
	started time.Time
}

// advance records what reading a row gave: a row, or the end of the rows, where a fail_after rule may give its error
// instead, as a statement that returned its rows and then failed would, or an error of the statement's own.
func (q *query) advance(ctx context.Context, err error, coded func(code string) error) error {
	defer faultpoint.Guard()
	switch {
	case err == nil:
		q.rows++
	case errors.Is(err, io.EOF):
		q.ended = true
		err = cmp.Or(q.failAfter(ctx, coded), err)
	default:
		q.ended, q.err = true, err
	}
	return err
}

// failAfter decides, once a statement's rows ended or closed without an error and no rule acted on it before,
// whether a fail_after rule replaces its result, and returns the error that rule gives, nil without one.
func (q *query) failAfter(ctx context.Context, coded func(code string) error) error {
	defer faultpoint.Guard()
	if q.rule != nil {
		return nil
	}
	q.rule = faultpoint.Decide(ctx, q.point, "fail_after")
	if q.rule == nil {
		return nil
	}
	q.err = action.Failure(q.rule, coded)
	return q.err
}

func (i interceptor) read(ctx context.Context, sql string, run func() (driver.Rows, error)) (context.Context, driver.Rows, error) {
	defer faultpoint.Guard()
	started := time.Now()
	point, rule, kind, err := i.begin(ctx, sql)
	cut := err != nil
	var rows driver.Rows
	if err == nil {
		faultpoint.Outside(func() { rows, err = run() })
	}
	if err != nil {
		faultpoint.Observe(ctx, point, "error", 0, faultpoint.Elapsed(started), rule,
			action.Sent(sqlpoint.ErrorDetail(err), rule, cut, err, i.reached))
		return ctx, nil, err
	}
	state := &query{point: point, rule: rule, empty: kind == "empty", started: started}
	return context.WithValue(ctx, queryKey{}, state), rows, nil
}

// interceptor makes the statements of one wrapped driver store points; coded builds that driver's error with a code,
// nil for a driver without a builder in sqlpoint.CodedErrors, and driverReached is the driver's own in
// sqlpoint.Reached, nil without one.
type interceptor struct {
	sqlmw.NullInterceptor
	coded         func(code string) error
	driverReached func(err error) (sent, known bool)
}

// reached tells whether a statement that the driver failed reached the database: driver.ErrBadConn says it did not,
// as a driver returns it only when the database cannot have run the statement, and the driver's own tells the rest.
func (i interceptor) reached(err error) (sent, known bool) {
	switch {
	case errors.Is(err, driver.ErrBadConn):
		return false, true
	case i.driverReached != nil:
		return i.driverReached(err)
	}
	return false, false
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

func (i interceptor) RowsNext(ctx context.Context, rows driver.Rows, dest []driver.Value) (err error) {
	defer faultpoint.Guard()
	state, found := ctx.Value(queryKey{}).(*query)
	if found && state.empty {
		return io.EOF
	}
	faultpoint.Outside(func() { err = rows.Next(dest) })
	if found {
		err = state.advance(ctx, err, i.coded)
	}
	return err
}

// RowsClose closes a statement's rows and observes its outcome once they are counted; rows the caller closes before
// their end without an error, as Row.Scan does, may still take a fail_after rule's error here.
func (i interceptor) RowsClose(ctx context.Context, rows driver.Rows) (err error) {
	defer faultpoint.Guard()
	faultpoint.Outside(func() { err = rows.Close() })
	state, found := ctx.Value(queryKey{}).(*query)
	if found && err == nil && !state.ended {
		err = state.failAfter(ctx, i.coded)
	}
	switch {
	case found && state.err != nil:
		faultpoint.Observe(ctx, state.point, "error", 0, faultpoint.Elapsed(state.started), state.rule,
			action.Sent(sqlpoint.ErrorDetail(state.err), state.rule, false, state.err, i.reached))
	case found && state.rows > 0:
		faultpoint.Observe(ctx, state.point, "rows", float64(state.rows), faultpoint.Elapsed(state.started), state.rule, nil)
	case found:
		faultpoint.Observe(ctx, state.point, "empty", 0, faultpoint.Elapsed(state.started), state.rule, nil)
	}
	return err
}
