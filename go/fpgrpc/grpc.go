// Package fpgrpc places rpc_server points at grpc-go unary calls and streams.
package fpgrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"faultpoint"
	"faultpoint/internal/action"

	"go.opentelemetry.io/otel/propagation"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const locatorPrefix = "gRPC "

var (
	enabled = faultpoint.Register(faultpoint.Plugin{Name: "grpc", Actions: map[string][]string{
		"rpc_server": {"fail", "fail_after", "delay", "crash"},
	}, Serves: func(locator string) bool { return strings.HasPrefix(locator, locatorPrefix) },
		Refuse: func(rule *faultpoint.Rule) error {
			if rule.Action.Kind != "fail" && rule.Action.Kind != "fail_after" {
				return nil
			}
			_, err := failureCode(rule)
			return err
		}})
	propagator = propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
)

// failureCode accepts the native gRPC status code of a failure, never an HTTP status.
func failureCode(rule *faultpoint.Rule) (codes.Code, error) {
	params := struct {
		Code string `json:"code"`
		MS   int    `json:"ms"`
	}{Code: strconv.FormatUint(uint64(codes.Unavailable), 10)}
	decoder := json.NewDecoder(bytes.NewReader(rule.Action.Params))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&params); err != nil {
		return codes.OK, err
	}
	code, err := strconv.ParseUint(params.Code, 10, 32)
	if err != nil {
		return codes.OK, err
	}
	if code == uint64(codes.OK) || code > uint64(codes.Unauthenticated) {
		return codes.OK, fmt.Errorf("a gRPC failure needs a native code from 1 to 16, not %q", params.Code)
	}
	return codes.Code(code), nil
}

// NewServer keeps the application's options and adds one point around each unary call and stream.
func NewServer(options ...grpc.ServerOption) *grpc.Server {
	if enabled {
		options = append(options, grpc.ChainUnaryInterceptor(serveUnary), grpc.ChainStreamInterceptor(serveStream))
	}
	return grpc.NewServer(options...)
}

type metadataCarrier struct{ metadata.MD }

func (m metadataCarrier) Get(key string) string {
	if values := m.MD.Get(key); len(values) > 0 {
		return values[0]
	}
	return ""
}

func (m metadataCarrier) Set(key, value string) { m.MD.Set(key, value) }

func (m metadataCarrier) Keys() []string {
	keys := make([]string, 0, len(m.MD))
	for key := range m.MD {
		keys = append(keys, key)
	}
	return keys
}

type serverCall struct {
	ctx     context.Context
	point   string
	rule    *faultpoint.Rule
	started time.Time
}

// take restores propagation metadata and applies the call's wait or pre-handler failure.
func take(ctx context.Context, method string) *serverCall {
	defer faultpoint.Guard()
	if incoming, found := metadata.FromIncomingContext(ctx); found {
		ctx = propagator.Extract(ctx, metadataCarrier{MD: incoming})
	}
	call := &serverCall{ctx: ctx, point: faultpoint.PointID(faultpoint.Service(), "rpc_server", locatorPrefix+method),
		started: time.Now()}
	call.rule = faultpoint.Decide(ctx, call.point, action.Before...)
	if call.rule != nil {
		action.Hold(call.rule)
	}
	return call
}

func (c *serverCall) failure() error {
	code, err := failureCode(c.rule)
	if err != nil {
		faultpoint.Abort("rule %s: %v", c.rule.ID, err)
	}
	return status.Error(code, action.ErrInjected.Error())
}

// finish replaces a successful completion only for fail_after and observes the native final status.
func (c *serverCall) finish(err error) error {
	defer faultpoint.Guard()
	if err == nil && c.rule == nil {
		c.rule = faultpoint.Decide(c.ctx, c.point, "fail_after")
		if c.rule != nil {
			err = c.failure()
		}
	}
	completion, native := status.FromError(err)
	if !native {
		completion = status.FromContextError(err)
	}
	code := completion.Code()
	outcome := "2xx"
	detail := map[string]string{"code": strconv.FormatUint(uint64(code), 10),
		"abandoned": strconv.FormatBool(c.ctx.Err() != nil)}
	if code != codes.OK {
		outcome = "error"
		detail["error"] = code.String()
	}
	elapsed := faultpoint.Elapsed(c.started)
	faultpoint.Observe(c.ctx, c.point, outcome, elapsed, elapsed, c.rule, detail)
	return err
}

func serveUnary(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	defer faultpoint.Guard()
	call := take(ctx, info.FullMethod)
	var response any
	var err error
	if call.rule != nil && call.rule.Action.Kind == "fail" {
		err = call.failure()
	} else {
		faultpoint.Outside(func() { response, err = handler(call.ctx, request) })
	}
	return response, call.finish(err)
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s serverStream) Context() context.Context { return s.ctx }

func serveStream(service any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	defer faultpoint.Guard()
	call := take(stream.Context(), info.FullMethod)
	var err error
	if call.rule != nil && call.rule.Action.Kind == "fail" {
		err = call.failure()
	} else {
		faultpoint.Outside(func() { err = handler(service, serverStream{ServerStream: stream, ctx: call.ctx}) })
	}
	return call.finish(err)
}
