package faultpoint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const ruleFilePollInterval = 500 * time.Millisecond

// GRPCLocatorPrefix distinguishes native gRPC points from HTTP points sharing the RPC kinds.
const GRPCLocatorPrefix = "gRPC "

// RuleSet is one experiment, as spec/rules.schema.json defines it.
type RuleSet struct {
	Experiment string `json:"experiment"`
	Rules      []Rule `json:"rules"`
}

// Rule injects an action at a point for executions whose baggage carries its scope.
type Rule struct {
	ID      string            `json:"id"`
	Point   string            `json:"point"`
	Action  Action            `json:"action"`
	Scope   map[string]string `json:"scope"`
	Trigger Trigger           `json:"trigger"`
}

// Action is a deviation: its kind and its parameters, which only the plugin executing it interprets.
type Action struct {
	Kind   string
	Params json.RawMessage
}

// UnmarshalJSON separates the kind of an action from its free parameters.
func (a *Action) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if err := json.Unmarshal(fields["kind"], &a.Kind); err != nil || a.Kind == "" {
		return errors.New("an action needs a kind")
	}
	delete(fields, "kind")
	params, err := json.Marshal(fields)
	a.Params = params
	return err
}

// Trigger chooses which matching executions of a rule inject; a nil limit is unlimited and a nil probability is 1.
type Trigger struct {
	Skip        int      `json:"skip"`
	Limit       *int     `json:"limit"`
	Probability *float64 `json:"probability"`
}

// DecodeParams decodes the parameters of a rule's action into the fields a plugin reads, and ends the process
// when they do not fit, since an experiment must not run under rules it did not ask for.
func (r *Rule) DecodeParams(target any) {
	if err := decodeStrict(r.Action.Params, target); err != nil {
		Abort("rule %s: parameters of %s: %v", r.ID, r.Action.Kind, err)
	}
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// PointID builds the identity of a point from its service, kind and locator.
func PointID(service, kind, locator string) string {
	return service + ":" + kind + ":" + locator
}

// SplitPoint reads the service, kind and locator of a point identity.
func SplitPoint(point string) (service, kind, locator string, err error) {
	parts := strings.SplitN(point, ":", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("a point id is <service>:<kind>:<locator>: %q", point)
	}
	return parts[0], parts[1], parts[2], nil
}

// ParseRuleSet reads a rule set and checks the structure every kind shares; action parameters are left to plugins.
func ParseRuleSet(data []byte) (RuleSet, error) {
	var ruleset RuleSet
	if err := decodeStrict(data, &ruleset); err != nil {
		return RuleSet{}, err
	}
	if ruleset.Experiment == "" {
		return RuleSet{}, errors.New("a rule set needs an experiment")
	}
	seen := map[string]bool{}
	for _, rule := range ruleset.Rules {
		if rule.ID == "" || seen[rule.ID] {
			return RuleSet{}, fmt.Errorf("rule ids are present and unique: %q", rule.ID)
		}
		seen[rule.ID] = true
		if _, _, _, err := SplitPoint(rule.Point); err != nil {
			return RuleSet{}, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		trigger := rule.Trigger
		if trigger.Skip < 0 || (trigger.Limit != nil && *trigger.Limit < 1) {
			return RuleSet{}, fmt.Errorf("rule %s: a trigger skips at least 0 and is limited to at least 1", rule.ID)
		}
		if trigger.Probability != nil && (*trigger.Probability <= 0 || *trigger.Probability > 1) {
			return RuleSet{}, fmt.Errorf("rule %s: a probability is in (0, 1]", rule.ID)
		}
	}
	return ruleset, nil
}

// RuleSource delivers rule sets: it hands the first to install before Start returns, and every replacement after.
type RuleSource interface {
	Start(install func(data []byte))
}

// FileRuleSource reads a rule set from a file and reads it again whenever the file's modification time changes,
// so that a controller replaces rules by writing a temporary file and renaming it.
type FileRuleSource struct {
	Path string
}

// Start installs the rules of the file and starts polling it.
func (source FileRuleSource) Start(install func(data []byte)) {
	modified := source.read(install)
	go func() {
		defer Guard()
		for range time.Tick(ruleFilePollInterval) {
			info, err := os.Stat(source.Path)
			if err != nil {
				Abort("cannot read rules: %v", err)
			}
			if !info.ModTime().Equal(modified) {
				modified = source.read(install)
			}
		}
	}()
}

// read hands the file to install and returns the modification time of what it read.
func (source FileRuleSource) read(install func(data []byte)) time.Time {
	file, err := os.Open(source.Path)
	if err != nil {
		Abort("cannot read rules: %v", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		Abort("cannot read rules: %v", err)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		Abort("cannot read rules: %v", err)
	}
	install(data)
	return info.ModTime()
}
