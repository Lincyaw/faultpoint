// Package fppoints is the plugin of the in-process points the rewriter places: branch, call, check, loop, value,
// clock and acquire.
package fppoints

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"faultpoint"
	"faultpoint/internal/action"
)

var enabled = faultpoint.Register(faultpoint.Plugin{Name: "points", Actions: map[string][]string{
	"branch":  {"fail", "delay", "crash"},
	"call":    {"fail", "fail_after", "delay", "crash"},
	"check":   {"negate", "delay", "crash"},
	"loop":    {"delay", "crash"},
	"value":   {"set", "shift", "delay", "crash"},
	"clock":   {"shift", "delay", "crash"},
	"acquire": {"fail", "delay", "crash"},
}})

type injectedError struct{ point string }

func (e *injectedError) Error() string { return "faultpoint: injected error at " + e.point }

// Branch is whether a guarded error path runs: its natural condition, or forced by a fail rule.
func Branch(ctx context.Context, point string, taken bool) bool {
	if !enabled {
		return taken
	}
	rule := faultpoint.Decide(ctx, point)
	if rule != nil {
		action.Hold(rule)
		taken = taken || rule.Action.Kind == "fail"
	}
	outcome := "not_taken"
	if taken {
		outcome = "taken"
	}
	faultpoint.Observe(ctx, point, outcome, 0, rule, nil)
	return taken
}

// injected is the error a fail or fail_after rule of a call point returns: the registered error it names, or an
// injected one.
func injected(rule *faultpoint.Rule, point string) error {
	var params struct {
		Error string `json:"error"`
	}
	rule.DecodeParams(&params)
	if params.Error == "" {
		return &injectedError{point: point}
	}
	registered, found := faultpoint.RegisteredError(params.Error)
	if !found {
		faultpoint.Abort("rule %s names unregistered error %q", rule.ID, params.Error)
	}
	return registered
}

// observeCall records the error a call point's caller gets, with its name as the detail.
func observeCall(ctx context.Context, point string, rule *faultpoint.Rule, err error) {
	if err == nil {
		faultpoint.Observe(ctx, point, "ok", 0, rule, nil)
		return
	}
	faultpoint.Observe(ctx, point, "error", 0, rule, map[string]string{"error": faultpoint.ErrorName(err)})
}

// Call is the call point of a call site whose error the caller checks: the rewriter calls Call(ctx, id, f)(args)
// where the source calls f(args), so that the arguments are evaluated as before. Under a fail rule f is not called:
// the results are zero values and the error the rule names. Under fail_after f is called and, when it returned no
// error, the caller gets the rule's error instead. f is returned as it is when the plugin is not enabled.
func Call[F any](ctx context.Context, point string, fn F) F {
	if !enabled {
		return fn
	}
	callee := reflect.ValueOf(fn)
	called := reflect.MakeFunc(callee.Type(), func(arguments []reflect.Value) []reflect.Value {
		rule := faultpoint.Decide(ctx, point, action.Before...)
		if rule != nil {
			action.Hold(rule)
		}
		var results []reflect.Value
		switch {
		case rule != nil && rule.Action.Kind == "fail":
			for index := range callee.Type().NumOut() {
				results = append(results, reflect.Zero(callee.Type().Out(index)))
			}
		case callee.Type().IsVariadic():
			results = callee.CallSlice(arguments)
		default:
			results = callee.Call(arguments)
		}
		last := len(results) - 1
		if rule == nil && results[last].IsNil() {
			rule = faultpoint.Decide(ctx, point, "fail_after")
		}
		if rule != nil && (rule.Action.Kind == "fail" || rule.Action.Kind == "fail_after") {
			replaced := reflect.New(callee.Type().Out(last)).Elem()
			replaced.Set(reflect.ValueOf(injected(rule, point)))
			results[last] = replaced
		}
		err, _ := results[last].Interface().(error)
		observeCall(ctx, point, rule, err)
		return results
	})
	return called.Interface().(F)
}

// Failed is the call point of an error check whose call the rewriter cannot hand to Call: it observes the error the
// call returned and, under a fail_after rule when the call returned no error, replaces it, which is all it can do
// once the call has run; a fail rule, which skips the call, cannot be obeyed there. It reports whether the error is
// not nil.
func Failed(ctx context.Context, point string, err *error) bool {
	if !enabled {
		return *err != nil
	}
	var rule *faultpoint.Rule
	if *err == nil {
		rule = faultpoint.Decide(ctx, point)
	} else {
		rule = faultpoint.Decide(ctx, point, action.Before...)
	}
	if rule != nil {
		action.Hold(rule)
	}
	if rule != nil && rule.Action.Kind == "fail" {
		faultpoint.Abort("rule %s: the call of %s has run before its error is checked, so it fails only with fail_after", rule.ID, point)
	}
	if rule != nil && rule.Action.Kind == "fail_after" {
		*err = injected(rule, point)
	}
	observeCall(ctx, point, rule, *err)
	return *err != nil
}

// Check is the result of a detector, negated by a negate rule.
func Check(ctx context.Context, point string, result bool) bool {
	if !enabled {
		return result
	}
	rule := faultpoint.Decide(ctx, point)
	if rule != nil {
		action.Hold(rule)
		result = result != (rule.Action.Kind == "negate")
	}
	outcome := "false"
	if result {
		outcome = "true"
	}
	faultpoint.Observe(ctx, point, outcome, 0, rule, nil)
	return result
}

// Loop marks one iteration of a loop, delayed by a delay rule to model contention.
func Loop(ctx context.Context, point string) {
	if !enabled {
		return
	}
	rule := faultpoint.Decide(ctx, point)
	if rule != nil {
		action.Hold(rule)
	}
	faultpoint.Observe(ctx, point, "iteration", 0, rule, nil)
}

// Value is a business value, replaced by a set rule or offset by a shift rule.
func Value[T any](ctx context.Context, point string, observed T) T {
	if !enabled {
		return observed
	}
	rule := faultpoint.Decide(ctx, point)
	result := observed
	if rule != nil {
		action.Hold(rule)
	}
	if rule != nil && rule.Action.Kind == "set" {
		var params struct {
			Value json.RawMessage `json:"value"`
		}
		rule.DecodeParams(&params)
		if err := json.Unmarshal(params.Value, &result); err != nil {
			faultpoint.Abort("rule %s sets a value that does not fit %T: %v", rule.ID, observed, err)
		}
	}
	if rule != nil && rule.Action.Kind == "shift" {
		result = shifted(rule, result)
	}
	faultpoint.Observe(ctx, point, "observed", numeric(result), rule, nil)
	return result
}

// shifted offsets a numeric value by a shift rule's amount.
func shifted[T any](rule *faultpoint.Rule, observed T) T {
	var params struct {
		Amount float64 `json:"amount"`
	}
	rule.DecodeParams(&params)
	value := reflect.ValueOf(&observed).Elem()
	switch {
	case value.CanInt():
		value.SetInt(value.Int() + int64(params.Amount))
	case value.CanUint():
		value.SetUint(uint64(int64(value.Uint()) + int64(params.Amount)))
	case value.CanFloat():
		value.SetFloat(value.Float() + params.Amount)
	default:
		faultpoint.Abort("rule %s shifts a value of non-numeric type %T", rule.ID, observed)
	}
	return observed
}

func numeric(value any) float64 {
	reflected := reflect.ValueOf(value)
	switch {
	case reflected.CanInt():
		return float64(reflected.Int())
	case reflected.CanUint():
		return float64(reflected.Uint())
	case reflected.CanFloat():
		return reflected.Float()
	}
	return 0
}

// Clock is a clock reading, moved by a shift rule's seconds.
func Clock(ctx context.Context, point string, reading time.Time) time.Time {
	if !enabled {
		return reading
	}
	rule := faultpoint.Decide(ctx, point)
	if rule != nil {
		action.Hold(rule)
	}
	if rule != nil && rule.Action.Kind == "shift" {
		var params struct {
			Amount float64 `json:"amount"`
		}
		rule.DecodeParams(&params)
		reading = reading.Add(time.Duration(params.Amount * float64(time.Second)))
	}
	faultpoint.Observe(ctx, point, "read", 0, rule, nil)
	return reading
}

// Acquire is whether a resource was acquired: its natural outcome, or rejected by a fail rule.
func Acquire(ctx context.Context, point string, acquired bool) bool {
	if !enabled {
		return acquired
	}
	rule := faultpoint.Decide(ctx, point)
	if rule != nil {
		action.Hold(rule)
		acquired = acquired && rule.Action.Kind != "fail"
	}
	outcome := "rejected"
	if acquired {
		outcome = "acquired"
	}
	faultpoint.Observe(ctx, point, outcome, 0, rule, nil)
	return acquired
}
