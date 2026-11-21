// Package fppgx is the adapter plugin of pgx: store_read and store_write points on the statements that rewritten
// call sites send through a pgx pool, connection or transaction, or through any interface with their methods; it
// also gives the SQL adapter the errors of pgx's database/sql driver.
package fppgx

import (
	"context"
	"errors"
	"slices"
	"strings"

	"faultpoint"
	"faultpoint/internal/action"
	"faultpoint/internal/sqlpoint"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// pgxDriver is the package of pgx's database/sql driver, which returns the errors of pgconn unchanged.
const pgxDriver = "github.com/jackc/pgx/v5/stdlib"

var (
	enabled    bool
	classifier *sqlpoint.Classifier
)

func init() {
	options := struct {
		ReadCommands []string `json:"read_commands"`
	}{ReadCommands: []string{"SELECT"}}
	enabled = faultpoint.Register(faultpoint.Plugin{Name: "pgx", Options: &options,
		Serves: sqlpoint.StatementLocator.MatchString, Actions: map[string][]string{
			"store_read":  {"fail", "empty", "delay", "crash"},
			"store_write": {"fail", "fail_after", "drop", "duplicate", "delay", "crash"},
		}})
	classifier = sqlpoint.NewClassifier(options.ReadCommands)
	sqlpoint.CodedErrors[pgxDriver] = postgresError
}

// postgresError is the error pgx gives for a statement PostgreSQL refused with a SQLSTATE, as a fail rule injects it.
func postgresError(code string) error {
	return &pgconn.PgError{Severity: "ERROR", Code: code, Message: action.ErrInjected.Error()}
}

type ownerKey struct{}

// passes is whether a call goes straight to pgx: the plugin is off, or an outer call of the plugin already owns
// the statement, as when a wrapper's method calls the pool it wraps.
func passes(ctx context.Context) bool { return !enabled || ctx.Value(ownerKey{}) != nil }

// statement is one execution of a statement at its point; inner is the context handed to pgx, which marks the
// statement as owned.
type statement struct {
	ctx     context.Context
	inner   context.Context
	point   string
	kind    string
	command string
	rule    *faultpoint.Rule
	action  string
}

// decide classifies a statement, decides its rule that acts before it runs and performs the rule's delay or crash.
func decide(ctx context.Context, query string) statement {
	defer faultpoint.Guard()
	known := classifier.Classify(query)
	s := statement{ctx: ctx, inner: context.WithValue(ctx, ownerKey{}, true), kind: known.Kind, command: known.Command,
		point: faultpoint.PointID(faultpoint.Service(), known.Kind, known.Locator)}
	s.rule = faultpoint.Decide(ctx, s.point, action.Before...)
	if s.rule != nil {
		action.Hold(s.rule)
		s.action = s.rule.Action.Kind
	}
	return s
}

// failAfter decides, once the statement completed normally and no rule acted on it before, whether a fail_after
// rule replaces its result, and returns the error that rule gives, nil without one.
func (s *statement) failAfter() error {
	defer faultpoint.Guard()
	if s.rule != nil {
		return nil
	}
	s.rule = faultpoint.Decide(s.ctx, s.point, "fail_after")
	if s.rule == nil {
		return nil
	}
	s.action = s.rule.Action.Kind
	return action.Failure(s.rule, postgresError)
}

// refuse ends the process for an action this call cannot perform, such as dropping a statement whose rows the
// caller reads.
func (s statement) refuse(call string, actions ...string) {
	for _, refused := range actions {
		if s.action == refused {
			faultpoint.Abort("rule %s: %s cannot %s at %s", s.rule.ID, call, refused, s.point)
		}
	}
}

// observe records an outcome: error, with its name and SQLSTATE, rows or empty for a read, ok for a write, with the
// rows read or affected.
func (s statement) observe(rows int64, err error) {
	defer faultpoint.Guard()
	if err != nil {
		faultpoint.Observe(s.ctx, s.point, "error", 0, s.rule, sqlpoint.ErrorDetail(err))
		return
	}
	outcome := "ok"
	switch {
	case s.kind == "store_read" && rows > 0:
		outcome = "rows"
	case s.kind == "store_read":
		outcome = "empty"
	}
	faultpoint.Observe(s.ctx, s.point, outcome, float64(rows), s.rule, nil)
}

type execer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// Exec is db.Exec under the rule of the statement's point.
func Exec(db execer, ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	if passes(ctx) {
		return db.Exec(ctx, sql, arguments...)
	}
	defer faultpoint.Guard()
	s := decide(ctx, sql)
	run := func() (tag pgconn.CommandTag, err error) {
		faultpoint.Outside(func() { tag, err = db.Exec(s.inner, sql, arguments...) })
		return tag, err
	}
	var tag pgconn.CommandTag
	var err error
	switch s.action {
	case "fail":
		err = action.Failure(s.rule, postgresError)
	case "drop":
		tag = pgconn.NewCommandTag(s.command + " 1")
	default:
		tag, err = run()
	}
	if err == nil && s.action == "duplicate" {
		tag, err = run()
	}
	if err == nil {
		err = s.failAfter()
	}
	if err != nil && s.action == "fail_after" {
		tag = pgconn.CommandTag{}
	}
	if err == nil && s.action == "empty" {
		tag = pgconn.NewCommandTag(s.command + " 0")
	}
	s.observe(tag.RowsAffected(), err)
	return tag, err
}

type querier interface {
	Query(ctx context.Context, sql string, arguments ...any) (pgx.Rows, error)
}

// Query is db.Query under the rule of the statement's point; the outcome is observed when the rows end.
func Query(db querier, ctx context.Context, sql string, arguments ...any) (pgx.Rows, error) {
	if passes(ctx) {
		return db.Query(ctx, sql, arguments...)
	}
	defer faultpoint.Guard()
	s := decide(ctx, sql)
	s.refuse("Query", "drop")
	if s.action == "fail" {
		err := action.Failure(s.rule, postgresError)
		s.observe(0, err)
		return failedRows{err: err}, err
	}
	var rows pgx.Rows
	var err error
	faultpoint.Outside(func() { rows, err = db.Query(s.inner, sql, arguments...) })
	if err == nil && s.action == "duplicate" {
		faultpoint.Outside(func() {
			rows.Close()
			err = rows.Err()
		})
	}
	if err == nil && s.action == "duplicate" {
		faultpoint.Outside(func() { rows, err = db.Query(s.inner, sql, arguments...) })
	}
	if err != nil {
		s.observe(0, err)
		return rows, err
	}
	return &observedRows{Rows: rows, statement: s, empty: s.action == "empty"}, nil
}

// observedRows counts the rows a caller reads and observes the outcome once, when the rows end or are closed; err is
// the error a fail_after rule gave once the rows ended normally, as a statement that wrote and returned rows before
// failing would.
type observedRows struct {
	pgx.Rows
	statement statement
	empty     bool
	read      int64
	done      bool
	err       error
}

// Err is the error of the rows: a fail_after rule's, or pgx's.
func (r *observedRows) Err() (err error) {
	defer faultpoint.Guard()
	if r.err != nil {
		return r.err
	}
	faultpoint.Outside(func() { err = r.Rows.Err() })
	return err
}

func (r *observedRows) Next() (more bool) {
	defer faultpoint.Guard()
	if !r.empty {
		faultpoint.Outside(func() { more = r.Rows.Next() })
	}
	if more {
		r.read++
		return true
	}
	r.finish()
	return false
}

func (r *observedRows) Close() {
	defer faultpoint.Guard()
	faultpoint.Outside(r.Rows.Close)
	r.finish()
}

// finish closes the rows, which releases the connection of an emptied read, and observes the outcome once.
func (r *observedRows) finish() {
	if r.done {
		return
	}
	r.done = true
	var err error
	var tag pgconn.CommandTag
	faultpoint.Outside(func() {
		r.Rows.Close()
		err, tag = r.Rows.Err(), r.Rows.CommandTag()
	})
	if err == nil {
		r.err = r.statement.failAfter()
	}
	rows := r.read
	if r.statement.kind == "store_write" {
		rows = tag.RowsAffected()
	}
	r.statement.observe(rows, r.Err())
}

type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row
}

// QueryRow is db.QueryRow under the rule of the statement's point; the outcome is observed when the row is scanned.
func QueryRow(db rowQuerier, ctx context.Context, sql string, arguments ...any) pgx.Row {
	if passes(ctx) {
		return db.QueryRow(ctx, sql, arguments...)
	}
	defer faultpoint.Guard()
	s := decide(ctx, sql)
	s.refuse("QueryRow", "drop")
	row := &observedRow{statement: s, query: func() (row pgx.Row) {
		faultpoint.Outside(func() { row = db.QueryRow(s.inner, sql, arguments...) })
		return row
	}}
	if s.action != "fail" {
		row.row = row.query()
	}
	return row
}

type observedRow struct {
	statement statement
	query     func() pgx.Row
	row       pgx.Row
}

// Scan reads the row; a missing row is the empty outcome of a read, not an error.
func (r *observedRow) Scan(dest ...any) (err error) {
	defer faultpoint.Guard()
	s := r.statement
	if s.action == "fail" {
		err = action.Failure(s.rule, postgresError)
	} else {
		faultpoint.Outside(func() { err = r.row.Scan(dest...) })
	}
	if err == nil && s.action == "duplicate" {
		faultpoint.Outside(func() { err = r.query().Scan(dest...) })
	}
	if err == nil {
		err = s.failAfter()
	}
	if err == nil && s.action == "empty" {
		err = pgx.ErrNoRows
	}
	if errors.Is(err, pgx.ErrNoRows) {
		s.observe(0, nil)
		return err
	}
	s.observe(1, err)
	return err
}

type batchSender interface {
	SendBatch(ctx context.Context, batch *pgx.Batch) pgx.BatchResults
}

// SendBatch is db.SendBatch under the rule of one point for the whole batch, classified by its distinct statements,
// so that the point does not depend on how many times a batch repeats a statement; the outcome is observed when the
// results are closed.
func SendBatch(db batchSender, ctx context.Context, batch *pgx.Batch) pgx.BatchResults {
	if passes(ctx) {
		return db.SendBatch(ctx, batch)
	}
	defer faultpoint.Guard()
	var queries []string
	for _, queued := range batch.QueuedQueries {
		if !slices.Contains(queries, queued.SQL) {
			queries = append(queries, queued.SQL)
		}
	}
	s := decide(ctx, strings.Join(queries, ";\n"))
	s.refuse("SendBatch", "drop", "empty")
	var err error
	var results pgx.BatchResults
	if s.action == "fail" {
		err = action.Failure(s.rule, postgresError)
	} else {
		faultpoint.Outside(func() { results = db.SendBatch(s.inner, batch) })
	}
	if err == nil && s.action == "duplicate" {
		faultpoint.Outside(func() { err = results.Close() })
	}
	if err == nil && s.action == "duplicate" {
		faultpoint.Outside(func() { results = db.SendBatch(s.inner, batch) })
	}
	if err != nil {
		s.observe(0, err)
		return failedResults{err: err}
	}
	return &observedResults{BatchResults: results, statement: s, queued: int64(len(batch.QueuedQueries))}
}

// observedResults observe a batch once, when its results are closed, where a fail_after rule gives its error once
// the batch completed normally; every later Close returns the same error, as pgx's does.
type observedResults struct {
	pgx.BatchResults
	statement statement
	queued    int64
	closed    bool
	err       error
}

func (r *observedResults) Close() error {
	defer faultpoint.Guard()
	if r.closed {
		return r.err
	}
	r.closed = true
	faultpoint.Outside(func() { r.err = r.BatchResults.Close() })
	if r.err == nil {
		r.err = r.statement.failAfter()
	}
	r.statement.observe(r.queued, r.err)
	return r.err
}

type beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

type optionsBeginner interface {
	BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error)
}

// Begin is db.Begin under the rule of the point of the BEGIN statement.
func Begin(db beginner, ctx context.Context) (pgx.Tx, error) {
	if passes(ctx) {
		return db.Begin(ctx)
	}
	return begin(ctx, func(inner context.Context) (pgx.Tx, error) { return db.Begin(inner) })
}

// BeginTx is db.BeginTx under the rule of the point of the BEGIN statement.
func BeginTx(db optionsBeginner, ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	if passes(ctx) {
		return db.BeginTx(ctx, options)
	}
	return begin(ctx, func(inner context.Context) (pgx.Tx, error) { return db.BeginTx(inner, options) })
}

// begin starts a transaction unless a fail rule refuses it; nothing else can be injected where no statement runs.
func begin(ctx context.Context, run func(context.Context) (pgx.Tx, error)) (tx pgx.Tx, err error) {
	defer faultpoint.Guard()
	s := decide(ctx, "BEGIN")
	s.refuse("Begin", "drop", "duplicate")
	if s.action == "fail" {
		err = action.Failure(s.rule, postgresError)
	} else {
		faultpoint.Outside(func() { tx, err = run(s.inner) })
	}
	if err == nil && s.failAfter() != nil {
		s.refuse("Begin", "fail_after")
	}
	s.observe(0, err)
	return tx, err
}

// failedRows are the rows of a statement that failed, which pgx callers may read without checking the error first.
type failedRows struct{ err error }

func (r failedRows) Close()                                       {}
func (r failedRows) Err() error                                   { return r.err }
func (r failedRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r failedRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r failedRows) Next() bool                                   { return false }
func (r failedRows) Scan(...any) error                            { return r.err }
func (r failedRows) Values() ([]any, error)                       { return nil, r.err }
func (r failedRows) RawValues() [][]byte                          { return nil }
func (r failedRows) Conn() *pgx.Conn                              { return nil }

// failedResults are the results of a batch that failed.
type failedResults struct{ err error }

func (r failedResults) Exec() (pgconn.CommandTag, error) { return pgconn.CommandTag{}, r.err }
func (r failedResults) Query() (pgx.Rows, error)         { return failedRows(r), r.err }
func (r failedResults) QueryRow() pgx.Row                { return failedRows(r) }
func (r failedResults) Close() error                     { return r.err }
