// Package fppgx is the adapter plugin of pgx: store_read and store_write points on the statements that rewritten
// call sites send through a pgx pool, connection or transaction, or through any interface with their methods.
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

var (
	enabled    bool
	classifier *sqlpoint.Classifier
)

func init() {
	options := struct {
		ReadCommands []string `json:"read_commands"`
	}{ReadCommands: []string{"SELECT"}}
	enabled = faultpoint.Register(faultpoint.Plugin{Name: "pgx", Options: &options, Actions: map[string][]string{
		"store_read":  {"fail", "empty", "delay", "crash"},
		"store_write": {"fail", "fail_after", "drop", "duplicate", "delay", "crash"},
	}})
	classifier = sqlpoint.NewClassifier(options.ReadCommands)
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

// decide classifies a statement, decides its rule and performs the rule's delay or crash.
func decide(ctx context.Context, query string) statement {
	known := classifier.Classify(query)
	s := statement{ctx: ctx, inner: context.WithValue(ctx, ownerKey{}, true), kind: known.Kind, command: known.Command,
		point: faultpoint.PointID(faultpoint.Service(), known.Kind, known.Locator)}
	s.rule = faultpoint.Decide(ctx, s.point)
	if s.rule != nil {
		action.Hold(s.rule)
		s.action = s.rule.Action.Kind
	}
	return s
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
	s := decide(ctx, sql)
	run := func() (pgconn.CommandTag, error) { return db.Exec(s.inner, sql, arguments...) }
	var tag pgconn.CommandTag
	var err error
	switch s.action {
	case "fail":
		err = action.Failure(s.rule)
	case "drop":
		tag = pgconn.NewCommandTag(s.command + " 1")
	default:
		tag, err = run()
	}
	if err == nil && s.action == "duplicate" {
		tag, err = run()
	}
	if err == nil && s.action == "fail_after" {
		tag, err = pgconn.CommandTag{}, action.Failure(s.rule)
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
	s := decide(ctx, sql)
	s.refuse("Query", "drop")
	if s.action == "fail" {
		err := action.Failure(s.rule)
		s.observe(0, err)
		return failedRows{err: err}, err
	}
	rows, err := db.Query(s.inner, sql, arguments...)
	if err == nil && (s.action == "duplicate" || s.action == "fail_after") {
		rows.Close()
		err = rows.Err()
	}
	if err == nil && s.action == "duplicate" {
		rows, err = db.Query(s.inner, sql, arguments...)
	}
	if err == nil && s.action == "fail_after" {
		err = action.Failure(s.rule)
		rows = failedRows{err: err}
	}
	if err != nil {
		s.observe(0, err)
		return rows, err
	}
	return &observedRows{Rows: rows, statement: s, empty: s.action == "empty"}, nil
}

// observedRows counts the rows a caller reads and observes the outcome once, when the rows end or are closed.
type observedRows struct {
	pgx.Rows
	statement statement
	empty     bool
	read      int64
	done      bool
}

func (r *observedRows) Next() bool {
	if !r.empty && r.Rows.Next() {
		r.read++
		return true
	}
	r.finish()
	return false
}

func (r *observedRows) Close() {
	r.Rows.Close()
	r.finish()
}

// finish closes the rows, which releases the connection of an emptied read, and observes the outcome once.
func (r *observedRows) finish() {
	if r.done {
		return
	}
	r.done = true
	r.Rows.Close()
	rows := r.read
	if r.statement.kind == "store_write" {
		rows = r.Rows.CommandTag().RowsAffected()
	}
	r.statement.observe(rows, r.Rows.Err())
}

type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row
}

// QueryRow is db.QueryRow under the rule of the statement's point; the outcome is observed when the row is scanned.
func QueryRow(db rowQuerier, ctx context.Context, sql string, arguments ...any) pgx.Row {
	if passes(ctx) {
		return db.QueryRow(ctx, sql, arguments...)
	}
	s := decide(ctx, sql)
	s.refuse("QueryRow", "drop")
	row := &observedRow{statement: s, query: func() pgx.Row { return db.QueryRow(s.inner, sql, arguments...) }}
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
func (r *observedRow) Scan(dest ...any) error {
	s := r.statement
	var err error
	if s.action == "fail" {
		err = action.Failure(s.rule)
	} else {
		err = r.row.Scan(dest...)
	}
	if err == nil && s.action == "duplicate" {
		err = r.query().Scan(dest...)
	}
	if err == nil && s.action == "fail_after" {
		err = action.Failure(s.rule)
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
		err = action.Failure(s.rule)
	} else {
		results = db.SendBatch(s.inner, batch)
	}
	if err == nil && (s.action == "duplicate" || s.action == "fail_after") {
		err = results.Close()
	}
	if err == nil && s.action == "duplicate" {
		results = db.SendBatch(s.inner, batch)
	}
	if err == nil && s.action == "fail_after" {
		err = action.Failure(s.rule)
	}
	if err != nil {
		s.observe(0, err)
		return failedResults{err: err}
	}
	return &observedResults{BatchResults: results, statement: s, queued: int64(len(batch.QueuedQueries))}
}

type observedResults struct {
	pgx.BatchResults
	statement statement
	queued    int64
}

func (r *observedResults) Close() error {
	err := r.BatchResults.Close()
	r.statement.observe(r.queued, err)
	return err
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
func begin(ctx context.Context, run func(context.Context) (pgx.Tx, error)) (pgx.Tx, error) {
	s := decide(ctx, "BEGIN")
	s.refuse("Begin", "drop", "duplicate", "fail_after")
	var tx pgx.Tx
	var err error
	if s.action == "fail" {
		err = action.Failure(s.rule)
	} else {
		tx, err = run(s.inner)
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
