// Package fphttp places rpc_server and rpc_client points on net/http handlers and clients.
package fphttp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"faultpoint"

	"go.opentelemetry.io/otel/propagation"
)

const defaultFailureStatus = http.StatusServiceUnavailable

var identifierSegment = regexp.MustCompile(`^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$`)

// PathTemplate replaces identifier segments of a path, so that one route is one point.
func PathTemplate(path string) string {
	segments := strings.Split(path, "/")
	for index, segment := range segments {
		if identifierSegment.MatchString(segment) {
			segments[index] = "{}"
		}
	}
	return strings.Join(segments, "/")
}

func statusOutcome(status int) string { return string(rune('0'+status/100)) + "xx" }

func failureStatus(action faultpoint.Action) int {
	if action.Status != 0 {
		return action.Status
	}
	return defaultFailureStatus
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(status int) {
	if s.status == 0 {
		s.status = status
	}
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Write(body []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(body)
}

type discardWriter struct{ header http.Header }

func (d *discardWriter) Header() http.Header            { return d.header }
func (d *discardWriter) Write(body []byte) (int, error) { return len(body), nil }
func (d *discardWriter) WriteHeader(int)                {}

// Middleware is the rpc_server point of every route of a handler, which also restores the
// caller's trace context and baggage.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !faultpoint.Enabled() {
			next.ServeHTTP(writer, request)
			return
		}
		ctx := faultpoint.Propagator.Extract(request.Context(), propagation.HeaderCarrier(request.Header))
		request = request.WithContext(ctx)
		point := faultpoint.PointID(faultpoint.Service(), faultpoint.KindRPCServer,
			request.Method+" "+PathTemplate(request.URL.Path))
		rule := faultpoint.Decide(ctx, point)
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: writer}
		defer func() {
			if recovered := recover(); recovered != nil {
				faultpoint.Record(ctx, point, "error", milliseconds(started), rule)
				panic(recovered)
			}
		}()
		if rule != nil {
			faultpoint.Hold(rule.Action)
		}
		switch {
		case rule != nil && rule.Action.Kind == faultpoint.ActionFail:
			recorder.WriteHeader(failureStatus(rule.Action))
		case rule != nil && rule.Action.Kind == faultpoint.ActionFailAfter:
			next.ServeHTTP(&discardWriter{header: http.Header{}}, request)
			recorder.WriteHeader(failureStatus(rule.Action))
		default:
			next.ServeHTTP(recorder, request)
		}
		if recorder.status == 0 {
			recorder.status = http.StatusOK
		}
		faultpoint.Record(ctx, point, statusOutcome(recorder.status), milliseconds(started), rule)
	})
}

func milliseconds(started time.Time) float64 {
	return float64(time.Since(started).Microseconds()) / 1000
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "faultpoint: read timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func boundaryError(name string) error {
	if name == faultpoint.ErrorRefused {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	return timeoutError{}
}

func errorOutcome(err error) string {
	var netError net.Error
	switch {
	case errors.As(err, &netError) && netError.Timeout():
		return faultpoint.ErrorTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return faultpoint.ErrorRefused
	}
	return "error"
}

func syntheticResponse(request *http.Request, status int) *http.Response {
	return &http.Response{
		Status: http.StatusText(status), StatusCode: status, Proto: "HTTP/1.1", ProtoMajor: 1,
		ProtoMinor: 1, Header: http.Header{}, Body: http.NoBody, Request: request,
	}
}

// Transport is the rpc_client point of every request a client sends, which also forwards the
// current trace context and baggage.
type Transport struct {
	Base http.RoundTripper
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// RoundTrip sends a request under the rule of its point.
func (t *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	ctx := request.Context()
	request = request.Clone(ctx)
	faultpoint.Propagator.Inject(ctx, propagation.HeaderCarrier(request.Header))
	if !faultpoint.Enabled() {
		return t.base().RoundTrip(request)
	}
	point := faultpoint.PointID(faultpoint.Service(), faultpoint.KindRPCClient,
		request.Method+" "+request.URL.Host+PathTemplate(request.URL.Path))
	rule := faultpoint.Decide(ctx, point)
	started := time.Now()
	action := faultpoint.Action{}
	if rule != nil {
		action = rule.Action
		faultpoint.Hold(action)
	}
	if action.Kind == faultpoint.ActionFail {
		if action.Status != 0 {
			faultpoint.Record(ctx, point, statusOutcome(action.Status), 0, rule)
			return syntheticResponse(request, action.Status), nil
		}
		err := boundaryError(action.Error)
		faultpoint.Record(ctx, point, errorOutcome(err), 0, rule)
		return nil, err
	}
	if action.Kind == faultpoint.ActionDuplicate && request.Body != nil && request.GetBody == nil {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	response, err := t.base().RoundTrip(request)
	if err == nil && (action.Kind == faultpoint.ActionDuplicate || action.Kind == faultpoint.ActionFailAfter) {
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if action.Kind == faultpoint.ActionDuplicate {
			if request.GetBody != nil {
				if request.Body, err = request.GetBody(); err != nil {
					return nil, err
				}
			}
			response, err = t.base().RoundTrip(request)
		}
	}
	if err != nil {
		faultpoint.Record(ctx, point, errorOutcome(err), milliseconds(started), rule)
		return nil, err
	}
	if action.Kind == faultpoint.ActionFailAfter {
		if action.Status != 0 {
			faultpoint.Record(ctx, point, statusOutcome(action.Status), milliseconds(started), rule)
			return syntheticResponse(request, action.Status), nil
		}
		err := boundaryError(action.Error)
		faultpoint.Record(ctx, point, errorOutcome(err), milliseconds(started), rule)
		return nil, err
	}
	faultpoint.Record(ctx, point, statusOutcome(response.StatusCode), milliseconds(started), rule)
	return response, nil
}
