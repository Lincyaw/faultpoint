// Package action holds what every plugin does the same way: delay and crash, and the error of a peer that timed out
// or refused the connection.
package action

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"faultpoint"
)

// The peer errors a boundary rule names.
const (
	Timeout = "timeout"
	Refused = "refused"
)

// Hold performs delay and crash: a delay blocks the calling goroutine, a crash ends the process with its code.
func Hold(rule *faultpoint.Rule) {
	switch rule.Action.Kind {
	case "delay":
		var params struct {
			MS int `json:"ms"`
		}
		rule.DecodeParams(&params)
		time.Sleep(time.Duration(params.MS) * time.Millisecond)
	case "crash":
		params := struct {
			Code int `json:"code"`
		}{Code: 1}
		rule.DecodeParams(&params)
		faultpoint.Crash(params.Code)
	}
}

// ErrInjected is the error of a store or broker whose fail rule names no peer error.
var ErrInjected = errors.New("faultpoint: injected failure")

// The injected error is registered, so that an observation names it as it names the sentinels of the service.
func init() { faultpoint.RegisterError("faultpoint/internal/action.ErrInjected", ErrInjected) }

// Failure is the error a fail or fail_after rule of a store or broker gives the caller: the peer error the rule
// names, or ErrInjected.
func Failure(rule *faultpoint.Rule) error {
	var params struct {
		Error string `json:"error"`
	}
	rule.DecodeParams(&params)
	if params.Error == "" {
		return ErrInjected
	}
	return PeerError(rule, params.Error)
}

// PeerError is the error a caller sees when its peer timed out or refused the connection; any other name ends the
// process, since the rule cannot be obeyed.
func PeerError(rule *faultpoint.Rule, name string) error {
	switch name {
	case Timeout:
		return context.DeadlineExceeded
	case Refused:
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	faultpoint.Abort("rule %s: a peer fails with %s or %s, not %q", rule.ID, Timeout, Refused, name)
	return nil
}
