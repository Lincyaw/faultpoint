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
	if enabled {
		engine.Use(serve)
	}
	return engine
}

// discardWriter swallows what a handler writes under fail_after, whose response the rule replaces.
type discardWriter struct{ gin.ResponseWriter }

func (discardWriter) Write(body []byte) (int, error)       { return len(body), nil }
func (discardWriter) WriteString(body string) (int, error) { return len(body), nil }
func (discardWriter) WriteHeader(int)                      {}
func (discardWriter) WriteHeaderNow()                      {}

func serve(c *gin.Context) {
	call := fphttp.Take(c.Request)
	if call == nil {
		c.Next()
		return
	}
	c.Request = call.Request
	defer func() {
		if recovered := recover(); recovered != nil {
			call.Panicked()
			panic(recovered)
		}
	}()
	switch call.Action() {
	case "fail":
		c.AbortWithStatus(call.FailureStatus())
	case "fail_after":
		writer := c.Writer
		c.Writer = discardWriter{ResponseWriter: writer}
		c.Next()
		c.Writer = writer
		c.AbortWithStatus(call.FailureStatus())
	default:
		c.Next()
	}
	call.Finish(c.Writer.Status())
}
