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
	"call":    {"fail", "delay", "crash"},
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

// Failed observes the error a call returned, with its name as the detail, and, under a fail rule, replaces it with
// the registered error the rule names or an injected one; it reports whether the error is not nil.
func Failed(ctx context.Context, point string, err *error) bool {
	if !enabled {
		return *err != nil
	}
	rule := faultpoint.Decide(ctx, point)
	if rule != nil {
		action.Hold(rule)
	}
	if rule != nil && rule.Action.Kind == "fail" {
		var params struct {
			Error string `json:"error"`
		}
		rule.DecodeParams(&params)
		*err = &injectedError{point: point}
		if params.Error != "" {
			registered, found := faultpoint.RegisteredError(params.Error)
			if !found {
				faultpoint.Abort("rule %s names unregistered error %q", rule.ID, params.Error)
			}
			*err = registered
		}
	}
	if *err == nil {
		faultpoint.Observe(ctx, point, "ok", 0, rule, nil)
		return false
	}
	faultpoint.Observe(ctx, point, "error", 0, rule, map[string]string{"error": faultpoint.ErrorName(*err)})
	return true
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
