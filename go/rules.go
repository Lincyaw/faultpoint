package faultpoint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Kind is where a fault point sits.
type Kind string

const (
	KindBranch     Kind = "branch"
	KindCall       Kind = "call"
	KindCheck      Kind = "check"
	KindLoop       Kind = "loop"
	KindValue      Kind = "value"
	KindClock      Kind = "clock"
	KindAcquire    Kind = "acquire"
	KindRPCClient  Kind = "rpc_client"
	KindRPCServer  Kind = "rpc_server"
	KindStoreRead  Kind = "store_read"
	KindStoreWrite Kind = "store_write"
	KindPublish    Kind = "publish"
	KindConsume    Kind = "consume"
	KindSyscall    Kind = "syscall"
	KindPacket     Kind = "packet"
)

// ActionKind is the deviation a rule injects.
type ActionKind string

const (
	ActionFail      ActionKind = "fail"
	ActionDelay     ActionKind = "delay"
	ActionFailAfter ActionKind = "fail_after"
	ActionDrop      ActionKind = "drop"
	ActionDuplicate ActionKind = "duplicate"
	ActionNegate    ActionKind = "negate"
	ActionEmpty     ActionKind = "empty"
	ActionSet       ActionKind = "set"
	ActionShift     ActionKind = "shift"
	ActionCrash     ActionKind = "crash"
)

// Boundary errors a failing boundary point raises instead of a response.
const (
	ErrorTimeout = "timeout"
	ErrorRefused = "refused"
)

var allowedActions = map[Kind][]ActionKind{
	KindBranch:     {ActionDelay, ActionCrash, ActionFail},
	KindCall:       {ActionDelay, ActionCrash, ActionFail},
	KindCheck:      {ActionDelay, ActionCrash, ActionNegate},
	KindLoop:       {ActionDelay, ActionCrash},
	KindValue:      {ActionDelay, ActionCrash, ActionSet, ActionShift},
	KindClock:      {ActionDelay, ActionCrash, ActionShift},
	KindAcquire:    {ActionDelay, ActionCrash, ActionFail},
	KindRPCClient:  {ActionDelay, ActionCrash, ActionFail, ActionFailAfter, ActionDuplicate},
	KindRPCServer:  {ActionDelay, ActionCrash, ActionFail, ActionFailAfter},
	KindStoreRead:  {ActionDelay, ActionCrash, ActionFail, ActionEmpty},
	KindStoreWrite: {ActionDelay, ActionCrash, ActionFail, ActionFailAfter, ActionDrop, ActionDuplicate},
	KindPublish:    {ActionDelay, ActionCrash, ActionFail, ActionFailAfter, ActionDrop, ActionDuplicate},
	KindConsume:    {ActionDelay, ActionCrash, ActionFail, ActionFailAfter, ActionDuplicate},
	KindSyscall:    {ActionFail, ActionCrash},
	KindPacket:     {ActionDelay, ActionDrop},
}

var errnoName = regexp.MustCompile(`^E[A-Z0-9]+$`)

// kernel is whether the eBPF agent places points of a kind, which see no request baggage.
func kernel(kind Kind) bool { return kind == KindSyscall || kind == KindPacket }

var actionFields = map[ActionKind][]string{
	ActionFail:      {"error", "status"},
	ActionFailAfter: {"error", "status"},
	ActionDelay:     {"ms"},
	ActionSet:       {"value"},
	ActionShift:     {"amount"},
	ActionCrash:     {"code"},
}

func boundary(kind Kind) bool {
	switch kind {
	case KindRPCClient, KindRPCServer, KindStoreRead, KindStoreWrite, KindPublish, KindConsume:
		return true
	}
	return false
}

// PointID builds the identity of a point from its service, kind and locator.
func PointID(service string, kind Kind, locator string) string {
	if strings.Contains(service, ":") {
		panic(fmt.Sprintf("faultpoint: a service name cannot contain ':': %s", service))
	}
	return service + ":" + string(kind) + ":" + locator
}

// PointKind reads the kind of a point from its identity.
func PointKind(point string) (Kind, error) {
	parts := strings.SplitN(point, ":", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("a point id is <service>:<kind>:<locator>: %s", point)
	}
	kind := Kind(parts[1])
	if _, known := allowedActions[kind]; !known {
		return "", fmt.Errorf("unknown point kind %q in %s", parts[1], point)
	}
	return kind, nil
}

// Action is the deviation of a rule; only the fields of its kind are set.
type Action struct {
	Kind   ActionKind      `json:"kind"`
	MS     int             `json:"ms,omitempty"`
	Error  string          `json:"error,omitempty"`
	Status int             `json:"status,omitempty"`
	Value  json.RawMessage `json:"value,omitempty"`
	Amount float64         `json:"amount,omitempty"`
	Code   int             `json:"code,omitempty"`
}

// UnmarshalJSON accepts only the fields of the action's kind, as the shared schema does.
func (a *Action) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	var kind ActionKind
	if err := json.Unmarshal(fields["kind"], &kind); err != nil {
		return fmt.Errorf("an action needs a kind: %w", err)
	}
	for name := range fields {
		if name != "kind" && !slices.Contains(actionFields[kind], name) {
			return fmt.Errorf("a %s action has no field %q", kind, name)
		}
	}
	type plain Action
	decoded := plain{Code: 1}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if kind == ActionShift {
		if _, present := fields["amount"]; !present {
			return fmt.Errorf("a shift action needs an amount")
		}
	}
	if kind == ActionSet {
		if _, present := fields["value"]; !present {
			return fmt.Errorf("a set action needs a value")
		}
	}
	*a = Action(decoded)
	return nil
}

// Trigger chooses which matching executions a rule injects at.
type Trigger struct {
	Skip        int      `json:"skip"`
	Limit       *int     `json:"limit"`
	Probability *float64 `json:"probability"`
}

// Rule injects an action at a point for requests whose baggage carries its scope.
type Rule struct {
	ID      string            `json:"id"`
	Point   string            `json:"point"`
	Action  Action            `json:"action"`
	Scope   map[string]string `json:"scope"`
	Trigger Trigger           `json:"trigger"`
}

// RuleSet is one experiment.
type RuleSet struct {
	Experiment string `json:"experiment"`
	Rules      []Rule `json:"rules"`
}

// ParseRuleSet reads and validates a rule set.
func ParseRuleSet(data []byte) (RuleSet, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var ruleset RuleSet
	if err := decoder.Decode(&ruleset); err != nil {
		return RuleSet{}, err
	}
	if ruleset.Experiment == "" {
		return RuleSet{}, fmt.Errorf("a rule set needs an experiment")
	}
	seen := map[string]bool{}
	for _, rule := range ruleset.Rules {
		if seen[rule.ID] {
			return RuleSet{}, fmt.Errorf("rule id %q repeats", rule.ID)
		}
		seen[rule.ID] = true
		if err := validateRule(rule); err != nil {
			return RuleSet{}, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
	}
	return ruleset, nil
}

func validateRule(rule Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("a rule needs an id")
	}
	kind, err := PointKind(rule.Point)
	if err != nil {
		return err
	}
	action := rule.Action
	if !slices.Contains(allowedActions[kind], action.Kind) {
		return fmt.Errorf("action %s does not apply to a %s point", action.Kind, kind)
	}
	if kernel(kind) && len(rule.Scope) > 0 {
		return fmt.Errorf("a %s point sees no baggage, so its rule has no scope", kind)
	}
	if kind == KindSyscall && action.Kind == ActionFail && !errnoName.MatchString(action.Error) {
		return fmt.Errorf("a syscall fails with an errno name such as ECONNREFUSED")
	}
	switch action.Kind {
	case ActionDelay:
		if action.MS <= 0 {
			return fmt.Errorf("a delay needs a positive ms")
		}
	case ActionCrash:
		if action.Code < 0 || action.Code > 255 {
			return fmt.Errorf("an exit code is between 0 and 255")
		}
	case ActionFail, ActionFailAfter:
		if action.Status != 0 && (action.Status < 100 || action.Status > 599) {
			return fmt.Errorf("a status is between 100 and 599")
		}
		if action.Status != 0 && kind != KindRPCClient && kind != KindRPCServer {
			return fmt.Errorf("only an RPC point responds with a status")
		}
		if action.Status != 0 && action.Error != "" {
			return fmt.Errorf("a failure has either a status or an error")
		}
		if kind == KindRPCServer && action.Error != "" {
			return fmt.Errorf("an RPC server fails with a status")
		}
		if (boundary(kind) || action.Kind == ActionFailAfter) && action.Error != "" && action.Error != ErrorTimeout && action.Error != ErrorRefused {
			return fmt.Errorf("a boundary error is %s or %s", ErrorTimeout, ErrorRefused)
		}
	}
	trigger := rule.Trigger
	if trigger.Skip < 0 || (trigger.Limit != nil && *trigger.Limit < 1) {
		return fmt.Errorf("a trigger skips at least 0 and is limited to at least 1")
	}
	if trigger.Probability != nil && (*trigger.Probability <= 0 || *trigger.Probability > 1) {
		return fmt.Errorf("a probability is in (0, 1]")
	}
	return nil
}
