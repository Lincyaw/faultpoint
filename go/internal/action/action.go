// Package action holds what every plugin does the same way: delay, the wait of a fail and crash, inside the process
// or at a boundary, and the error of a peer that timed out or refused the connection.
package action

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
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

// Hold holds an execution as its rule says where the wait outlasts any caller, as the contention inside the process
// or a server slow before it handles a request does: a delay, and the ms of a fail, block the calling goroutine, a
// crash ends the process with its code.
func Hold(rule *faultpoint.Rule) {
	defer faultpoint.Guard()
	time.Sleep(Pause(rule))
}

// Wait holds an execution of a client of a peer as its rule says, where a delay, and the ms of a fail, model a slow
// peer: a caller that gives up ends the wait as it ends a wait for a peer, and Wait returns the context's error
// then, nil once the wait is over. A crash rule ends the process with its code.
func Wait(ctx context.Context, rule *faultpoint.Rule) error {
	defer faultpoint.Guard()
	return Sleep(ctx, Pause(rule))
}

// SendLate sends an operation whose delay its caller cut short, as a slow peer still serves what its client gave up
// on: in the background, under a context that the caller's end does not cancel, the sender discarding the reply.
func SendLate(ctx context.Context, send func(late context.Context)) {
	late := context.WithoutCancel(ctx)
	go func() {
		defer faultpoint.Guard()
		faultpoint.Outside(func() { send(late) })
	}()
}

// Sent records in a failure's detail whether the operation reached its peer, and returns the detail. A rule's own
// failure says it: a fail kept the operation back, a fail_after replaced the reply of one that went, and a delay
// that its caller cut short models a slow peer that has it. Any other failure is the client library's, about which
// reached tells, known false leaving sent out of the detail.
func Sent(detail map[string]string, rule *faultpoint.Rule, cut bool, err error,
	reached func(err error) (sent, known bool)) map[string]string {
	var sent, known bool
	switch {
	case rule != nil && rule.Action.Kind == "fail":
		known = true
	case rule != nil && (rule.Action.Kind == "fail_after" || (cut && rule.Action.Kind == "delay")):
		sent, known = true, true
	default:
		sent, known = reached(err)
	}
	if known {
		detail["sent"] = strconv.FormatBool(sent)
	}
	return detail
}

// Sleep waits for a duration unless the caller gives up first, and returns the context's error then, nil once the
// duration is over or when it is zero.
func Sleep(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Pause is how long a rule holds an execution before it acts, the ms of a delay or of a fail; a crash rule ends the
// process instead.
func Pause(rule *faultpoint.Rule) time.Duration {
	var wait struct {
		MS int `json:"ms"`
	}
	switch rule.Action.Kind {
	case "delay":
		rule.DecodeParams(&wait)
	case "fail":
		// The plugin that builds the failure checks the other parameters of a fail.
		if err := json.Unmarshal(rule.Action.Params, &wait); err != nil {
			faultpoint.Abort("rule %s: parameters of fail: %v", rule.ID, err)
		}
	case "crash":
		crash := struct {
			Code int `json:"code"`
		}{Code: 1}
		rule.DecodeParams(&crash)
		faultpoint.Crash(crash.Code)
	}
	return time.Duration(wait.MS) * time.Millisecond
}

// ErrInjected is the error of a store or broker whose fail rule names no peer error and no code.
var ErrInjected = errors.New("faultpoint: injected failure")

// The injected error is registered, so that an observation names it as it names the sentinels of the service.
func init() { faultpoint.RegisterError("faultpoint/internal/action.ErrInjected", ErrInjected) }

// Failure is the error a fail or fail_after rule of a store or broker gives the caller: the client library's own
// error with the code the rule names, which coded builds, the peer error it names, or ErrInjected.
func Failure(rule *faultpoint.Rule, coded func(code string) error) error {
	defer faultpoint.Guard()
	var params struct {
		Error string `json:"error"`
		Code  string `json:"code"`
		// MS is the wait before a fail, which Wait has already waited.
		MS int `json:"ms"`
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
