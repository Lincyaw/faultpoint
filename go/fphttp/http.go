// Package fphttp is the adapter plugin of net/http: rpc_server points on handlers and rpc_client points on
// round trippers, which also carry trace context and baggage for services without OpenTelemetry.
package fphttp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"faultpoint"
	"faultpoint/fpaction"

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

type server struct{ next http.Handler }

// Handler is the rpc_server point of every route of a handler, nil meaning http.DefaultServeMux as for an
// http.Server; it returns the handler unchanged when the plugin is not enabled.
func Handler(next http.Handler) http.Handler {
	if _, wrapped := next.(server); !enabled || wrapped {
		return next
	}
	return server{next: next}
}

type discardWriter struct{ header http.Header }

func (d discardWriter) Header() http.Header            { return d.header }
func (d discardWriter) Write(body []byte) (int, error) { return len(body), nil }
func (d discardWriter) WriteHeader(int)                {}

func (s server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	next := s.next
	if next == nil {
		next = http.DefaultServeMux
	}
	ctx := propagator.Extract(request.Context(), propagation.HeaderCarrier(request.Header))
	request = request.WithContext(ctx)
	point := faultpoint.PointID(faultpoint.Service(), "rpc_server", request.Method+" "+pathTemplate(request.URL.Path))
	rule := faultpoint.Decide(ctx, point)
	started := time.Now()
	defer func() {
		if recovered := recover(); recovered != nil {
			faultpoint.Observe(ctx, point, "error", milliseconds(started), rule)
			panic(recovered)
		}
	}()
	action := ""
	if rule != nil {
		fpaction.Hold(rule)
		action = rule.Action.Kind
	}
	var status int
	switch action {
	case "fail", "fail_after":
		params := struct {
			Status int `json:"status"`
		}{Status: defaultFailureStatus}
		rule.DecodeParams(&params)
		if action == "fail_after" {
			next.ServeHTTP(discardWriter{header: http.Header{}}, request)
		}
		status = params.Status
		writer.WriteHeader(status)
	default:
		status = httpsnoop.CaptureMetricsFn(writer, func(captured http.ResponseWriter) {
			next.ServeHTTP(captured, request)
		}).Code
	}
	faultpoint.Observe(ctx, point, statusOutcome(status), milliseconds(started), rule)
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
		return fpaction.Timeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return fpaction.Refused
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
	params := struct {
		Status int    `json:"status"`
		Error  string `json:"error"`
	}{Error: fpaction.Timeout}
	rule.DecodeParams(&params)
	if params.Status != 0 {
		return syntheticResponse(request, params.Status), nil
	}
	return nil, fpaction.PeerError(rule, params.Error)
}

// RoundTrip sends a request under the rule of its point.
func (c client) RoundTrip(request *http.Request) (*http.Response, error) {
	base := c.base
	if base == nil {
		base = http.DefaultTransport
	}
	ctx := request.Context()
	request = request.Clone(ctx)
	propagator.Inject(ctx, propagation.HeaderCarrier(request.Header))
	point := faultpoint.PointID(faultpoint.Service(), "rpc_client",
		request.Method+" "+request.URL.Host+pathTemplate(request.URL.Path))
	rule := faultpoint.Decide(ctx, point)
	started := time.Now()
	action := ""
	if rule != nil {
		fpaction.Hold(rule)
		action = rule.Action.Kind
	}
	if action == "duplicate" && request.Body != nil && request.GetBody == nil {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	var response *http.Response
	var err error
	if action == "fail" {
		response, err = failure(request, rule)
	} else {
		response, err = base.RoundTrip(request)
	}
	if err == nil && (action == "duplicate" || action == "fail_after") {
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	if err == nil && action == "duplicate" && request.GetBody != nil {
		request.Body, err = request.GetBody()
	}
	if err == nil && action == "duplicate" {
		response, err = base.RoundTrip(request)
	}
	if err == nil && action == "fail_after" {
		response, err = failure(request, rule)
	}
	if err != nil {
		faultpoint.Observe(ctx, point, errorOutcome(err), milliseconds(started), rule)
		return nil, err
	}
	faultpoint.Observe(ctx, point, statusOutcome(response.StatusCode), milliseconds(started), rule)
	return response, nil
}
