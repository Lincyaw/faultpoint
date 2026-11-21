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

// Before are the actions a point decides before its operation runs. It decides fail_after only once the operation
// completed normally, so that an operation failing by itself keeps its failure, is observed as natural and does not
// count towards a fail_after rule.
var Before = []string{"fail", "drop", "duplicate", "empty", "delay", "crash"}

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

// ErrInjected is the error of a store or broker whose fail rule names no peer error and no code.
var ErrInjected = errors.New("faultpoint: injected failure")

// The injected error is registered, so that an observation names it as it names the sentinels of the service.
func init() { faultpoint.RegisterError("faultpoint/internal/action.ErrInjected", ErrInjected) }

// Failure is the error a fail or fail_after rule of a store or broker gives the caller: the client library's own
// error with the code the rule names, which coded builds, the peer error it names, or ErrInjected.
func Failure(rule *faultpoint.Rule, coded func(code string) error) error {
	var params struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	rule.DecodeParams(&params)
	switch {
	case params.Code != "" && params.Error != "":
		faultpoint.Abort("rule %s: a failure names a peer error or a code, not both", rule.ID)
	case params.Code != "":
		return coded(params.Code)
	case params.Error != "":
		return PeerError(rule, params.Error)
	}
	return ErrInjected
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
