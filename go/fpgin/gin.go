// Package fpgin is the adapter plugin of gin: a middleware added where an engine is created makes every route an
// rpc_server point, however the engine is served, including by engine.Run, which builds its server inside gin.
package fpgin

import (
	"faultpoint"
	"faultpoint/fphttp"

	"github.com/gin-gonic/gin"
)

var enabled = faultpoint.Register(faultpoint.Plugin{Name: "gin", Actions: map[string][]string{
	"rpc_server": {"fail", "fail_after", "delay", "crash"},
}})

// Instrument adds the rpc_server middleware to an engine where it is created, before any route, and returns the
// engine; the engine of a plugin that is not enabled is returned as it is.
func Instrument(engine *gin.Engine) *gin.Engine {
	defer faultpoint.Guard()
	if enabled {
		engine.Use(serve)
	}
	return engine
}

// answer passes a handler's response through until its status is known, when a fail_after rule may replace a 2xx
// or 3xx status with its own, whose body is empty.
type answer struct {
	gin.ResponseWriter
	call    *fphttp.ServerCall
	settled bool
}

func (a *answer) replaced() bool { return a.call.Action() == "fail_after" }

// settle settles the status the handler set, once, dropping the headers it set when a rule replaces its answer.
func (a *answer) settle() {
	if a.settled {
		return
	}
	a.settled = true
	status := a.call.Answer(a.ResponseWriter.Status())
	if a.replaced() {
		clear(a.ResponseWriter.Header())
		a.ResponseWriter.WriteHeader(status)
	}
}

func (a *answer) WriteHeader(code int) {
	defer faultpoint.Guard()
	if !a.replaced() {
		faultpoint.Outside(func() { a.ResponseWriter.WriteHeader(code) })
	}
}

func (a *answer) WriteHeaderNow() {
	defer faultpoint.Guard()
	a.settle()
	faultpoint.Outside(a.ResponseWriter.WriteHeaderNow)
}

func (a *answer) Write(body []byte) (written int, err error) {
	defer faultpoint.Guard()
	a.WriteHeaderNow()
	if a.replaced() {
		return len(body), nil
	}
	faultpoint.Outside(func() { written, err = a.ResponseWriter.Write(body) })
	return written, err
}

func (a *answer) WriteString(body string) (written int, err error) {
	defer faultpoint.Guard()
	a.WriteHeaderNow()
	if a.replaced() {
		return len(body), nil
	}
	faultpoint.Outside(func() { written, err = a.ResponseWriter.WriteString(body) })
	return written, err
}

func (a *answer) Flush() {
	defer faultpoint.Guard()
	a.WriteHeaderNow()
	faultpoint.Outside(a.ResponseWriter.Flush)
}

func serve(c *gin.Context) {
	defer faultpoint.Guard()
	call := fphttp.Take(c.Request)
	if call == nil {
		faultpoint.Outside(c.Next)
		return
	}
	c.Request = call.Request
	switch {
	case call.Ended != nil:
		c.Abort()
		call.Failed(call.Ended)
	case call.Action() == "fail":
		c.AbortWithStatus(call.FailureStatus())
		call.Finish(c.Writer.Status())
	default:
		writer := c.Writer
		answered := &answer{ResponseWriter: writer, call: call}
		c.Writer = answered
		faultpoint.Outside(func() { handle(call, c) })
		// gin writes the header of a handler that wrote nothing after the middleware returns, so the status is settled
		// here without writing it.
		answered.settle()
		c.Writer = writer
		call.Finish(c.Writer.Status())
	}
}

// handle runs the handlers after the middleware for a request the server point took, observing a panic of them,
// which goes on.
func handle(call *fphttp.ServerCall, c *gin.Context) {
	defer func() {
		if recovered := recover(); recovered != nil {
			call.Failed(recovered)
			panic(recovered)
		}
	}()
	c.Next()
}
