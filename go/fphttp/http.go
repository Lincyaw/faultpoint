// Package fphttp is the adapter plugin of net/http: rpc_server points on handlers and rpc_client points on
// round trippers, which also carry trace context and baggage for services without OpenTelemetry.
package fphttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"faultpoint"
	"faultpoint/internal/action"

	"github.com/felixge/httpsnoop"
	"go.opentelemetry.io/otel/propagation"
)

const (
	defaultFailureStatus     = http.StatusServiceUnavailable
	defaultIdentifierSegment = `^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$`
)

var (
	enabled           bool
	identifierSegment *regexp.Regexp
	propagator        = propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
)

func init() {
	options := struct {
		IdentifierSegment string `json:"identifier_segment"`
	}{IdentifierSegment: defaultIdentifierSegment}
	enabled = faultpoint.Register(faultpoint.Plugin{Name: "http", Options: &options, Actions: map[string][]string{
		"rpc_server": {"fail", "fail_after", "delay", "crash"},
		"rpc_client": {"fail", "fail_after", "duplicate", "delay", "crash"},
	}})
	pattern, err := regexp.Compile(options.IdentifierSegment)
	if err != nil {
		faultpoint.Abort("option identifier_segment of http: %v", err)
	}
	identifierSegment = pattern
}

// pathTemplate replaces the identifier segments of a path, so that one route is one point.
func pathTemplate(path string) string {
	segments := strings.Split(path, "/")
	for index, segment := range segments {
		if identifierSegment.MatchString(segment) {
			segments[index] = "{}"
		}
	}
	return strings.Join(segments, "/")
}

func statusOutcome(status int) string { return strconv.Itoa(status/100) + "xx" }

func milliseconds(started time.Time) float64 {
	return float64(time.Since(started).Microseconds()) / 1000
}

type takenKey struct{}

// ServerCall is one request a server point took, with the rule decided for it; a framework adapter such as the gin
// plugin uses it for the requests its framework serves.
type ServerCall struct {
	Request *http.Request
	Rule    *faultpoint.Rule
	point   string
	started time.Time
}

// Take takes a request at its rpc_server point: it restores the caller's trace and baggage, decides the rule that
// acts before the handler runs and performs its delay or crash. It returns nil when a server point around this one
// already took the request, as when a wrapped http.Server serves an instrumented framework, so that a request is
// one execution of one point.
func Take(request *http.Request) *ServerCall {
	defer faultpoint.Guard()
	if request.Context().Value(takenKey{}) != nil {
		return nil
	}
	ctx := propagator.Extract(request.Context(), propagation.HeaderCarrier(request.Header))
	call := &ServerCall{Request: request.WithContext(context.WithValue(ctx, takenKey{}, true)), started: time.Now(),
		point: faultpoint.PointID(faultpoint.Service(), "rpc_server", request.Method+" "+pathTemplate(request.URL.Path))}
	call.Rule = faultpoint.Decide(ctx, call.point, action.Before...)
	if call.Rule != nil {
		action.Hold(call.Rule)
	}
	return call
}

// Answer is the status to send once the handler's is known: the handler's, or a fail_after rule's, which is decided
// only for a 2xx or 3xx status of a request no rule acted on before.
func (c *ServerCall) Answer(status int) int {
	defer faultpoint.Guard()
	if c.Rule != nil || !succeeded(status) {
		return status
	}
	c.Rule = faultpoint.Decide(c.Request.Context(), c.point, "fail_after")
	if c.Rule == nil {
		return status
	}
	return c.FailureStatus()
}

// succeeded is whether a status is a 2xx or 3xx answer, the normal completion of an rpc point that a fail_after rule
// replaces.
func succeeded(status int) bool { return status >= http.StatusOK && status < http.StatusBadRequest }

// Action is the kind of the call's rule, empty without one.
func (c *ServerCall) Action() string {
	if c.Rule == nil {
		return ""
	}
	return c.Rule.Action.Kind
}

// FailureStatus is the status a fail or fail_after rule answers with.
func (c *ServerCall) FailureStatus() int {
	defer faultpoint.Guard()
	params := struct {
		Status int `json:"status"`
	}{Status: defaultFailureStatus}
	c.Rule.DecodeParams(&params)
	return params.Status
}

// abandoned is whether the client went away before the server finished, which cancels the request's context.
func (c *ServerCall) abandoned() string {
	return strconv.FormatBool(errors.Is(c.Request.Context().Err(), context.Canceled))
}

// Finish observes the status the server answered.
func (c *ServerCall) Finish(status int) {
	defer faultpoint.Guard()
	faultpoint.Observe(c.Request.Context(), c.point, statusOutcome(status), milliseconds(c.started), c.Rule,
		map[string]string{"status": strconv.Itoa(status), "abandoned": c.abandoned()})
}

// Panicked observes a request whose handler panicked with a value, named by its type or its registered name.
func (c *ServerCall) Panicked(recovered any) {
	defer faultpoint.Guard()
	name := fmt.Sprintf("%T", recovered)
	if err, isError := recovered.(error); isError {
		name = faultpoint.ErrorName(err)
	}
	faultpoint.Observe(c.Request.Context(), c.point, "error", milliseconds(c.started), c.Rule,
		map[string]string{"error": name, "abandoned": c.abandoned()})
}

type server struct{ next http.Handler }

// Handler is the rpc_server point of every route of a handler, nil meaning http.DefaultServeMux as for an
// http.Server; it returns the handler unchanged when the plugin is not enabled.
func Handler(next http.Handler) http.Handler {
	if _, wrapped := next.(server); !enabled || wrapped {
		return next
	}
	return server{next: next}
}

// answer passes a handler's response through until its status is known, when a fail_after rule may replace a 2xx
// or 3xx status with its own, whose body is empty; status is the status sent, 0 before it is known.
type answer struct {
	call   *ServerCall
	writer http.ResponseWriter
	status int
}

func (a *answer) replaced() bool { return a.call.Action() == "fail_after" }

// settle settles the status once the handler's is known, dropping the headers the handler set when a rule replaces
// its answer, so that they do not describe a body that is not sent.
func (a *answer) settle(code int) {
	a.status = a.call.Answer(code)
	if a.replaced() {
		clear(a.writer.Header())
	}
}

// header settles the first final status the handler writes and writes the status settled on.
func (a *answer) header(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
	return func(code int) {
		if a.status == 0 && code >= http.StatusOK {
			a.settle(code)
			code = a.status
		}
		next(code)
	}
}

// implicit settles the 200 that net/http sends for a handler that writes, flushes or returns without a status, and
// writes the status of a rule that replaces it.
func (a *answer) implicit() {
	if a.status != 0 {
		return
	}
	a.settle(http.StatusOK)
	if a.replaced() {
		a.writer.WriteHeader(a.status)
	}
}

func (a *answer) write(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
	return func(body []byte) (int, error) {
		a.implicit()
		if a.replaced() {
			return len(body), nil
		}
		return next(body)
	}
}

func (a *answer) writeString(next httpsnoop.WriteStringFunc) httpsnoop.WriteStringFunc {
	return func(body string) (int, error) {
		a.implicit()
		if a.replaced() {
			return len(body), nil
		}
		return next(body)
	}
}

func (a *answer) readFrom(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
	return func(source io.Reader) (int64, error) {
		a.implicit()
		if a.replaced() {
			return io.Copy(io.Discard, source)
		}
		return next(source)
	}
}

func (a *answer) flush(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
	return func() {
		a.implicit()
		next()
	}
}

func (a *answer) flushError(next httpsnoop.FlushErrorFunc) httpsnoop.FlushErrorFunc {
	return func() error {
		a.implicit()
		return next()
	}
}

// hijack leaves a hijacked connection's answer to the handler, observed as 200 as net/http reports it.
func (a *answer) hijack(next httpsnoop.HijackFunc) httpsnoop.HijackFunc {
	return func() (net.Conn, *bufio.ReadWriter, error) {
		if a.status == 0 {
			a.status = http.StatusOK
		}
		return next()
	}
}

func (s server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	next := s.next
	if next == nil {
		next = http.DefaultServeMux
	}
	call := Take(request)
	if call == nil {
		next.ServeHTTP(writer, request)
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			call.Panicked(recovered)
			panic(recovered)
		}
	}()
	var status int
	if call.Action() == "fail" {
		status = call.FailureStatus()
		writer.WriteHeader(status)
	} else {
		answered := &answer{call: call, writer: writer}
		next.ServeHTTP(httpsnoop.Wrap(writer, httpsnoop.Hooks{WriteHeader: answered.header, Write: answered.write,
			WriteString: answered.writeString, ReadFrom: answered.readFrom, Flush: answered.flush,
			FlushError: answered.flushError, Hijack: answered.hijack}), call.Request)
		answered.implicit()
		status = answered.status
	}
	call.Finish(status)
}

type client struct{ base http.RoundTripper }

// Transport is the rpc_client point of every request a round tripper sends, nil meaning http.DefaultTransport as
// for an http.Client; it returns the round tripper unchanged when the plugin is not enabled.
func Transport(base http.RoundTripper) http.RoundTripper {
	if _, wrapped := base.(client); !enabled || wrapped {
		return base
	}
	return client{base: base}
}

func errorOutcome(err error) string {
	var netError net.Error
	switch {
	case errors.As(err, &netError) && netError.Timeout():
		return action.Timeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return action.Refused
	}
	return "error"
}

func syntheticResponse(request *http.Request, status int) *http.Response {
	return &http.Response{
		Status: strconv.Itoa(status) + " " + http.StatusText(status), StatusCode: status, Proto: "HTTP/1.1",
		ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{}, Body: http.NoBody, Request: request,
	}
}

// failure is what a fail or fail_after rule gives the caller instead of the peer's response: a response with its
// status, or the error of a peer that timed out, the default, or refused the connection.
func failure(request *http.Request, rule *faultpoint.Rule) (*http.Response, error) {
	defer faultpoint.Guard()
	params := struct {
		Status int    `json:"status"`
		Error  string `json:"error"`
	}{Error: action.Timeout}
	rule.DecodeParams(&params)
	if params.Status != 0 {
		return syntheticResponse(request, params.Status), nil
	}
	return nil, action.PeerError(rule, params.Error)
}

// RoundTrip sends a request under the rule of its point, a fail_after rule replacing only a 2xx or 3xx response of
// the peer; a failure's detail tells whether the request was written completely, that is whether the peer may have
// acted on it.
func (c client) RoundTrip(request *http.Request) (*http.Response, error) {
	base := c.base
	if base == nil {
		base = http.DefaultTransport
	}
	ctx := request.Context()
	var wrote atomic.Bool
	request = request.Clone(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) { wrote.Store(info.Err == nil) },
	}))
	propagator.Inject(ctx, propagation.HeaderCarrier(request.Header))
	point := faultpoint.PointID(faultpoint.Service(), "rpc_client",
		request.Method+" "+request.URL.Host+pathTemplate(request.URL.Path))
	rule := faultpoint.Decide(ctx, point, action.Before...)
	started := time.Now()
	kind := ""
	if rule != nil {
		action.Hold(rule)
		kind = rule.Action.Kind
	}
	if kind == "duplicate" && request.Body != nil && request.GetBody == nil {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	var response *http.Response
	var err error
	if kind == "fail" {
		response, err = failure(request, rule)
	} else {
		response, err = base.RoundTrip(request)
	}
	if err == nil && rule == nil && succeeded(response.StatusCode) {
		rule = faultpoint.Decide(ctx, point, "fail_after")
	}
	if err == nil && rule != nil {
		kind = rule.Action.Kind
	}
	if err == nil && (kind == "duplicate" || kind == "fail_after") {
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	if err == nil && kind == "duplicate" && request.GetBody != nil {
		request.Body, err = request.GetBody()
	}
	if err == nil && kind == "duplicate" {
		response, err = base.RoundTrip(request)
	}
	if err == nil && kind == "fail_after" {
		response, err = failure(request, rule)
	}
	if err != nil {
		faultpoint.Observe(ctx, point, errorOutcome(err), milliseconds(started), rule,
			map[string]string{"error": faultpoint.ErrorName(err), "sent": strconv.FormatBool(wrote.Load())})
		return nil, err
	}
	detail := map[string]string{"status": strconv.Itoa(response.StatusCode)}
	if kind == "fail" || kind == "fail_after" {
		detail["sent"] = strconv.FormatBool(kind == "fail_after")
	}
	faultpoint.Observe(ctx, point, statusOutcome(response.StatusCode), milliseconds(started), rule, detail)
	return response, nil
}
