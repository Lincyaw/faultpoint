package faultpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const (
	watchInterval     = 500 * time.Millisecond
	invalidRulesExit  = 70
	exemplarLimit     = 5
	defaultScopeKey   = "fp.scope"
	defaultFlushSecs  = 2.0
	environmentPrefix = "FAULTPOINT_"
)

// Propagator carries trace context and baggage across the boundaries this SDK instruments,
// whatever propagator the process configured.
var Propagator = propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})

// Settings are read from the FAULTPOINT_ environment variables.
type Settings struct {
	Service  string
	Rules    string
	Report   string
	ScopeKey string
	Flush    time.Duration
	Seed     int64
}

func settingsFromEnvironment() Settings {
	settings := Settings{
		Service:  os.Getenv(environmentPrefix + "SERVICE"),
		Rules:    os.Getenv(environmentPrefix + "RULES"),
		Report:   os.Getenv(environmentPrefix + "REPORT"),
		ScopeKey: defaultScopeKey,
		Flush:    time.Duration(defaultFlushSecs * float64(time.Second)),
	}
	if key := os.Getenv(environmentPrefix + "SCOPE_KEY"); key != "" {
		settings.ScopeKey = key
	}
	if text := os.Getenv(environmentPrefix + "FLUSH_SECONDS"); text != "" {
		seconds, err := strconv.ParseFloat(text, 64)
		if err != nil || seconds <= 0 {
			panic(fmt.Sprintf("faultpoint: FAULTPOINT_FLUSH_SECONDS is a positive number: %q", text))
		}
		settings.Flush = time.Duration(seconds * float64(time.Second))
	}
	if text := os.Getenv(environmentPrefix + "SEED"); text != "" {
		seed, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			panic(fmt.Sprintf("faultpoint: FAULTPOINT_SEED is an integer: %q", text))
		}
		settings.Seed = seed
	}
	return settings
}

type ruleState struct {
	experiment string
	byPoint    map[string][]*Rule
}

type tallyKey struct {
	point, outcome, scope, rule string
	injected                    bool
}

type tallyEntry struct {
	count     int
	total     float64
	exemplars []string
}

// ObservationRecord is one line of an observation file, as spec/observation.schema.json defines.
type ObservationRecord struct {
	Experiment string   `json:"experiment"`
	Service    string   `json:"service"`
	Process    string   `json:"process"`
	Start      float64  `json:"start"`
	End        float64  `json:"end"`
	Point      string   `json:"point"`
	Outcome    string   `json:"outcome"`
	Scope      string   `json:"scope"`
	Rule       *string  `json:"rule"`
	Count      int      `json:"count"`
	Total      float64  `json:"total"`
	Exemplars  []string `json:"exemplars"`
}

type runtime struct {
	settings    Settings
	enabled     bool
	process     string
	state       atomic.Pointer[ruleState]
	mu          sync.Mutex
	matches     map[string]int
	injections  map[string]int
	randoms     map[string]*rand.Rand
	tally       map[tallyKey]*tallyEntry
	windowStart time.Time
	modified    time.Time
}

var current = newRuntime(settingsFromEnvironment())

func newRuntime(settings Settings) *runtime {
	host, _ := os.Hostname()
	r := &runtime{
		settings:    settings,
		enabled:     settings.Rules != "" || settings.Report != "",
		process:     fmt.Sprintf("%s:%d", host, os.Getpid()),
		tally:       map[tallyKey]*tallyEntry{},
		windowStart: time.Now(),
	}
	r.state.Store(&ruleState{byPoint: map[string][]*Rule{}})
	if r.enabled && settings.Service == "" {
		panic("faultpoint: FAULTPOINT_SERVICE is required when faultpoint is enabled")
	}
	if settings.Rules != "" {
		if err := r.loadRules(); err != nil {
			panic(fmt.Sprintf("faultpoint: %v", err))
		}
	}
	if r.enabled {
		go r.watch()
	}
	return r
}

func (r *runtime) loadRules() error {
	info, err := os.Stat(r.settings.Rules)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(r.settings.Rules)
	if err != nil {
		return err
	}
	ruleset, err := ParseRuleSet(data)
	if err != nil {
		return fmt.Errorf("invalid rules in %s: %w", r.settings.Rules, err)
	}
	r.flush()
	byPoint := map[string][]*Rule{}
	randoms := map[string]*rand.Rand{}
	for index := range ruleset.Rules {
		rule := &ruleset.Rules[index]
		byPoint[rule.Point] = append(byPoint[rule.Point], rule)
		seed := fnv.New64a()
		fmt.Fprintf(seed, "%d:%s", r.settings.Seed, rule.ID)
		randoms[rule.ID] = rand.New(rand.NewSource(int64(seed.Sum64())))
	}
	r.mu.Lock()
	r.matches, r.injections, r.randoms = map[string]int{}, map[string]int{}, randoms
	r.state.Store(&ruleState{experiment: ruleset.Experiment, byPoint: byPoint})
	r.modified = info.ModTime()
	r.mu.Unlock()
	return nil
}

// An unusable rule file ends the process so that no experiment runs under rules it did not ask for.
func (r *runtime) watch() {
	lastFlush := time.Now()
	for range time.Tick(watchInterval) {
		if r.settings.Rules != "" {
			info, err := os.Stat(r.settings.Rules)
			if err == nil && !info.ModTime().Equal(r.modified) {
				err = r.loadRules()
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "faultpoint: %v; stopping the process\n", err)
				os.Exit(invalidRulesExit)
			}
		}
		if time.Since(lastFlush) >= r.settings.Flush {
			r.flush()
			lastFlush = time.Now()
		}
	}
}

func scopeMatches(ctx context.Context, scope map[string]string) bool {
	if len(scope) == 0 {
		return true
	}
	if ctx == nil {
		return false
	}
	bag := baggage.FromContext(ctx)
	for key, value := range scope {
		if bag.Member(key).Value() != value {
			return false
		}
	}
	return true
}

func (r *runtime) decide(ctx context.Context, point string) *Rule {
	for _, rule := range r.state.Load().byPoint[point] {
		if !scopeMatches(ctx, rule.Scope) {
			continue
		}
		r.mu.Lock()
		seen := r.matches[rule.ID]
		r.matches[rule.ID] = seen + 1
		fires := seen >= rule.Trigger.Skip &&
			(rule.Trigger.Limit == nil || r.injections[rule.ID] < *rule.Trigger.Limit) &&
			(rule.Trigger.Probability == nil || r.randoms[rule.ID].Float64() < *rule.Trigger.Probability)
		if fires {
			r.injections[rule.ID]++
		}
		r.mu.Unlock()
		if fires {
			return rule
		}
	}
	return nil
}

func (r *runtime) record(ctx context.Context, point, outcome string, total float64, rule *Rule) {
	if r.settings.Report == "" {
		return
	}
	key := tallyKey{point: point, outcome: outcome}
	traceID := ""
	if ctx != nil {
		key.scope = baggage.FromContext(ctx).Member(r.settings.ScopeKey).Value()
		if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
			traceID = spanContext.TraceID().String()
		}
	}
	if rule != nil {
		key.rule, key.injected = rule.ID, true
	}
	r.mu.Lock()
	entry := r.tally[key]
	if entry == nil {
		entry = &tallyEntry{}
		r.tally[key] = entry
	}
	entry.count++
	entry.total += total
	if traceID != "" && len(entry.exemplars) < exemplarLimit {
		entry.exemplars = append(entry.exemplars, traceID)
	}
	r.mu.Unlock()
}

func (r *runtime) flush() {
	if r.settings.Report == "" {
		return
	}
	end := time.Now()
	r.mu.Lock()
	entries, start := r.tally, r.windowStart
	r.tally, r.windowStart = map[tallyKey]*tallyEntry{}, end
	experiment := r.state.Load().experiment
	r.mu.Unlock()
	if len(entries) == 0 {
		return
	}
	var lines []byte
	for key, entry := range entries {
		record := ObservationRecord{
			Experiment: experiment, Service: r.settings.Service, Process: r.process,
			Start: float64(start.UnixNano()) / 1e9, End: float64(end.UnixNano()) / 1e9,
			Point: key.point, Outcome: key.outcome, Scope: key.scope, Count: entry.count,
			Total: entry.total, Exemplars: append([]string{}, entry.exemplars...),
		}
		if key.injected {
			record.Rule = &key.rule
		}
		line, err := json.Marshal(record)
		if err != nil {
			panic(err)
		}
		lines = append(append(lines, line...), '\n')
	}
	file, err := os.OpenFile(r.settings.Report, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		panic(fmt.Sprintf("faultpoint: cannot write observations: %v", err))
	}
	defer file.Close()
	if _, err := file.Write(lines); err != nil {
		panic(fmt.Sprintf("faultpoint: cannot write observations: %v", err))
	}
}

// Enabled reports whether the process injects or observes at all.
func Enabled() bool { return current.enabled }

// Service is the service name points of boundaries are identified by.
func Service() string { return current.settings.Service }

// Decide returns the rule to inject at this execution of a point, or nil.
func Decide(ctx context.Context, point string) *Rule { return current.decide(ctx, point) }

// Record counts one outcome of a point; rule is the rule that injected at this execution.
func Record(ctx context.Context, point, outcome string, total float64, rule *Rule) {
	current.record(ctx, point, outcome, total, rule)
}

// Hold performs the actions every point shares: it sleeps for a delay and ends the process for a crash.
func Hold(action Action) {
	switch action.Kind {
	case ActionDelay:
		time.Sleep(time.Duration(action.MS) * time.Millisecond)
	case ActionCrash:
		Crash(action.Code)
	}
}

// Crash writes the pending observations and ends the process.
func Crash(code int) {
	current.flush()
	os.Exit(code)
}

// Flush writes the pending observations; a process calls it before a graceful exit.
func Flush() { current.flush() }

// Abort ends the process when a rule cannot be applied where it was installed.
func Abort(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "faultpoint: "+format+"; stopping the process\n", arguments...)
	current.flush()
	os.Exit(invalidRulesExit)
}
