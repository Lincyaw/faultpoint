package faultpoint

import (
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"time"
)

var registry sync.Map

// RegisterError names an error a call point can return when a fail rule names it, so that an
// injection returns a sentinel the code really returns.
func RegisterError(name string, err error) { registry.Store(name, err) }

// InjectedError is returned by a call point whose fail rule names no registered error.
type InjectedError struct{ Point string }

func (e *InjectedError) Error() string { return "faultpoint: injected error at " + e.Point }

// Branch is whether a guarded error path runs: its natural condition, or forced by a fail rule.
func Branch(ctx context.Context, point string, taken bool) bool {
	if !current.enabled {
		return taken
	}
	rule := current.decide(ctx, point)
	if rule != nil {
		Hold(rule.Action)
		taken = taken || rule.Action.Kind == ActionFail
	}
	outcome := "not_taken"
	if taken {
		outcome = "taken"
	}
	current.record(ctx, point, outcome, 0, rule)
	return taken
}

// Failed observes the error a call returned and, under a fail rule, replaces it; it reports
// whether the error is not nil.
func Failed(ctx context.Context, point string, err *error) bool {
	if !current.enabled {
		return *err != nil
	}
	rule := current.decide(ctx, point)
	if rule != nil {
		Hold(rule.Action)
		if rule.Action.Kind == ActionFail {
			*err = &InjectedError{Point: point}
			if rule.Action.Error != "" {
				registered, found := registry.Load(rule.Action.Error)
				if !found {
					Abort("rule %s names unregistered error %q", rule.ID, rule.Action.Error)
				}
				*err = registered.(error)
			}
		}
	}
	outcome := "ok"
	if *err != nil {
		outcome = "error"
	}
	current.record(ctx, point, outcome, 0, rule)
	return *err != nil
}

// Check is the result of a detector, negated by a negate rule.
func Check(ctx context.Context, point string, result bool) bool {
	if !current.enabled {
		return result
	}
	rule := current.decide(ctx, point)
	if rule != nil {
		Hold(rule.Action)
		result = result != (rule.Action.Kind == ActionNegate)
	}
	outcome := "false"
	if result {
		outcome = "true"
	}
	current.record(ctx, point, outcome, 0, rule)
	return result
}

// Loop marks one iteration of a loop, delayed by a delay rule to model contention.
func Loop(ctx context.Context, point string) {
	if !current.enabled {
		return
	}
	rule := current.decide(ctx, point)
	if rule != nil {
		Hold(rule.Action)
	}
	current.record(ctx, point, "iteration", 0, rule)
}

// Value is a business value, replaced by a set rule or offset by a shift rule.
func Value[T any](ctx context.Context, point string, observed T) T {
	if !current.enabled {
		return observed
	}
	rule := current.decide(ctx, point)
	result := observed
	if rule != nil {
		Hold(rule.Action)
		switch rule.Action.Kind {
		case ActionSet:
			if err := json.Unmarshal(rule.Action.Value, &result); err != nil {
				Abort("rule %s sets a value that does not fit %T: %v", rule.ID, observed, err)
			}
		case ActionShift:
			value := reflect.ValueOf(&result).Elem()
			switch {
			case value.CanInt():
				value.SetInt(value.Int() + int64(rule.Action.Amount))
			case value.CanUint():
				value.SetUint(uint64(int64(value.Uint()) + int64(rule.Action.Amount)))
			case value.CanFloat():
				value.SetFloat(value.Float() + rule.Action.Amount)
			default:
				Abort("rule %s shifts a value of non-numeric type %T", rule.ID, observed)
			}
		}
	}
	current.record(ctx, point, "observed", numeric(result), rule)
	return result
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
	if !current.enabled {
		return reading
	}
	rule := current.decide(ctx, point)
	if rule != nil {
		Hold(rule.Action)
		if rule.Action.Kind == ActionShift {
			reading = reading.Add(time.Duration(rule.Action.Amount * float64(time.Second)))
		}
	}
	current.record(ctx, point, "read", 0, rule)
	return reading
}

// Acquire is whether a resource was acquired: its natural outcome, or rejected by a fail rule.
func Acquire(ctx context.Context, point string, acquired bool) bool {
	if !current.enabled {
		return acquired
	}
	rule := current.decide(ctx, point)
	if rule != nil {
		Hold(rule.Action)
		acquired = acquired && rule.Action.Kind != ActionFail
	}
	outcome := "rejected"
	if acquired {
		outcome = "acquired"
	}
	current.record(ctx, point, outcome, 0, rule)
	return acquired
}
