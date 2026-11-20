// Package faultpoint is the core of the Go SDK: it obtains rule sets, selects the rule of each execution of a
// point and hands observations to a sink, while every kind's semantics lives in plugins that register at init.
package faultpoint

import (
	"context"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

const invalidRulesExit = 70

// ContextProvider reads the baggage and the trace of an execution's context.
type ContextProvider interface {
	Baggage(ctx context.Context, key string) string
	TraceID(ctx context.Context) string
}

// Plugin is a point or adapter plugin as it registers from its package's init: the actions it implements at each
// kind it serves, and a pointer to its options holding their defaults, nil when it has none.
type Plugin struct {
	Name    string
	Actions map[string][]string
	Options any
}

// ruleState is an installed rule set with the per-process counts of its triggers.
type ruleState struct {
	experiment string
	byPoint    map[string][]*Rule
	matches    map[string]int
	injections map[string]int
	randoms    map[string]*rand.Rand
}

type core struct {
	settings   settings
	enabled    bool
	registered []string
	actions    map[string][]string
	source     RuleSource
	sink       ObservationSink
	context    ContextProvider
	start      sync.Once
	started    atomic.Bool
	state      atomic.Pointer[ruleState]
	mu         sync.Mutex
	exit       sync.Mutex
	cleanups   []func()
}

var current core

func init() {
	current.settings = readSettings()
	current.enabled = current.settings.rules != "" || current.settings.report != ""
	current.actions = map[string][]string{}
	current.state.Store(&ruleState{})
}

// Register enrolls a plugin and reports whether it is enabled; its options are decoded only then. A kind several
// plugins serve accepts only the actions all of them implement, so that a rule one of them cannot obey is refused
// when it is installed.
func Register(plugin Plugin) bool {
	current.registered = append(current.registered, plugin.Name)
	if !current.enabled || !current.settings.config.enables(plugin.Name) {
		return false
	}
	Options(plugin.Name, plugin.Options)
	for kind, actions := range plugin.Actions {
		served, found := current.actions[kind]
		if found {
			actions = slices.DeleteFunc(slices.Clone(served), func(action string) bool { return !slices.Contains(actions, action) })
		}
		current.actions[kind] = actions
	}
	return true
}

// UseRuleSource replaces the file rule source; a plugin calls it from its init.
func UseRuleSource(source RuleSource) { current.source = source }

// UseSink replaces the JSON Lines sink; a plugin calls it from its init.
func UseSink(sink ObservationSink) { current.sink = sink }

// UseContext installs the context provider; a plugin calls it from its init.
func UseContext(provider ContextProvider) { current.context = provider }

// Start brings the observation sink and the rules into force once every plugin of the build has registered; the
// rewriter calls it from an init of every rewritten package, and only the first call starts.
func Start() { current.start.Do(start) }

func start() {
	if !current.enabled {
		return
	}
	if service := current.settings.service; service == "" || strings.Contains(service, ":") {
		Abort("FAULTPOINT_SERVICE names the service, without ':', when faultpoint is enabled: %q", service)
	}
	current.settings.config.checkNames(current.registered)
	if current.sink == nil && current.settings.report != "" {
		options := DefaultJSONLOptions
		Options(jsonlOptionsName, &options)
		sink, err := NewJSONLSink(current.settings.report, current.settings.service, options)
		if err != nil {
			Abort("%v", err)
		}
		current.sink = sink
	}
	if current.source == nil && current.settings.rules != "" {
		current.source = FileRuleSource{Path: current.settings.rules}
	}
	current.started.Store(true)
	if current.source != nil {
		current.source.Start(current.install)
	}
}

// install replaces the rule set; a rule of this service at a kind a plugin serves must use an action that plugin
// implements, and rules of other services or kinds are left to the processes that serve them.
func (c *core) install(data []byte) {
	ruleset, err := ParseRuleSet(data)
	if err != nil {
		Abort("invalid rules: %v", err)
	}
	next := &ruleState{experiment: ruleset.Experiment, byPoint: map[string][]*Rule{}, matches: map[string]int{},
		injections: map[string]int{}, randoms: map[string]*rand.Rand{}}
	for index := range ruleset.Rules {
		rule := &ruleset.Rules[index]
		service, kind, _, _ := SplitPoint(rule.Point)
		actions, served := c.actions[kind]
		if service != c.settings.service || !served {
			continue
		}
		if !slices.Contains(actions, rule.Action.Kind) {
			Abort("rule %s: no plugin of this process implements %s at a %s point", rule.ID, rule.Action.Kind, kind)
		}
		next.byPoint[rule.Point] = append(next.byPoint[rule.Point], rule)
		seed := fnv.New64a()
		seed.Write([]byte(rule.ID))
		next.randoms[rule.ID] = rand.New(rand.NewPCG(uint64(c.settings.seed), seed.Sum64()))
	}
	if c.sink != nil {
		c.sink.Flush()
	}
	c.state.Store(next)
}

// Decide returns the rule that injects at this execution of a point: the first whose scope matches the
// execution's baggage and whose trigger fires, or nil.
func Decide(ctx context.Context, point string) *Rule {
	state := current.state.Load()
	for _, rule := range state.byPoint[point] {
		if current.inScope(ctx, rule.Scope) && current.fires(state, rule) {
			return rule
		}
	}
	return nil
}

// inScope is whether every scope entry equals the baggage member of the same key; without a context only an
// empty scope matches.
func (c *core) inScope(ctx context.Context, scope map[string]string) bool {
	for key, value := range scope {
		if ctx == nil || c.context == nil || c.context.Baggage(ctx, key) != value {
			return false
		}
	}
	return true
}

// fires counts a match of a rule and reports whether its trigger injects at it.
func (c *core) fires(state *ruleState, rule *Rule) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := state.matches[rule.ID]
	state.matches[rule.ID] = seen + 1
	trigger := rule.Trigger
	fires := seen >= trigger.Skip &&
		(trigger.Limit == nil || state.injections[rule.ID] < *trigger.Limit) &&
		(trigger.Probability == nil || state.randoms[rule.ID].Float64() < *trigger.Probability)
	if fires {
		state.injections[rule.ID]++
	}
	return fires
}

// Observe hands one outcome of a point to the sink; rule is the rule that injected at this execution, or nil.
func Observe(ctx context.Context, point, outcome string, total float64, rule *Rule) {
	if !current.started.Load() || current.sink == nil {
		return
	}
	observation := Observation{Experiment: current.state.Load().experiment, Point: point, Outcome: outcome,
		Count: 1, Total: total}
	if rule != nil {
		observation.Rule = rule.ID
	}
	if ctx != nil && current.context != nil {
		observation.Scope = current.context.Baggage(ctx, current.settings.scopeKey)
		observation.TraceID = current.context.TraceID(ctx)
	}
	current.sink.Add(observation)
}

// Service is the name the points of boundaries are identified by.
func Service() string { return current.settings.service }

// AtExit registers a cleanup that Crash and Abort run, in registration order, before the process ends, so that a
// process owner such as the eBPF agent can undo what it changed on the host.
func AtExit(cleanup func()) {
	current.exit.Lock()
	defer current.exit.Unlock()
	current.cleanups = append(current.cleanups, cleanup)
}

// Crash writes the pending observations, runs the registered cleanups and ends the process with code.
func Crash(code int) {
	// The lock is held until the process ends, so that a concurrent Crash waits for the cleanups instead of exiting first.
	current.exit.Lock()
	if current.started.Load() && current.sink != nil {
		current.sink.Flush()
	}
	for _, cleanup := range current.cleanups {
		cleanup()
	}
	os.Exit(code)
}

// Abort ends the process when rules or configuration cannot be obeyed, so that no experiment runs under rules
// it did not ask for.
func Abort(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "faultpoint: "+format+"; stopping the process\n", arguments...)
	Crash(invalidRulesExit)
}
