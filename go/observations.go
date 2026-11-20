package faultpoint

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Observation is Count executions of a point with one outcome and Total their summed quantity: one execution
// from the core, or the counts a kernel program already aggregated.
type Observation struct {
	Experiment string
	Point      string
	Outcome    string
	Scope      string
	Rule       string
	Count      int
	Total      float64
	TraceID    string
}

// ObservationSink receives every observation; Flush writes what it holds, and the core calls it before
// a rule set is replaced and before the process ends.
type ObservationSink interface {
	Add(observation Observation)
	Flush()
}

// ObservationRecord is one line of an observation file, as spec/observation.schema.json defines it.
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

// JSONLOptions are the options of the JSON Lines sink, given under "jsonl" in the configuration.
type JSONLOptions struct {
	FlushSeconds float64 `json:"flush_seconds"`
	Exemplars    int     `json:"exemplars"`
}

// DefaultJSONLOptions write every two seconds and keep five trace ids per record.
var DefaultJSONLOptions = JSONLOptions{FlushSeconds: 2, Exemplars: 5}

type tallyKey struct {
	experiment, point, outcome, scope, rule string
}

type tally struct {
	count     int
	total     float64
	exemplars []string
}

// JSONLSink counts observations per experiment, point, outcome, scope and rule, and appends the counts of each
// window to a JSON Lines file.
type JSONLSink struct {
	path      string
	service   string
	process   string
	exemplars int
	mu        sync.Mutex
	start     time.Time
	tallies   map[tallyKey]*tally
}

// NewJSONLSink starts a sink that writes to path at the interval its options give.
func NewJSONLSink(path, service string, options JSONLOptions) (*JSONLSink, error) {
	if options.FlushSeconds <= 0 || options.Exemplars < 0 {
		return nil, fmt.Errorf("jsonl flushes after a positive number of seconds and keeps at least 0 exemplars: %+v", options)
	}
	host, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	sink := &JSONLSink{
		path: path, service: service, process: fmt.Sprintf("%s:%d", host, os.Getpid()),
		exemplars: options.Exemplars, start: time.Now(), tallies: map[tallyKey]*tally{},
	}
	go func() {
		for range time.Tick(time.Duration(options.FlushSeconds * float64(time.Second))) {
			sink.Flush()
		}
	}()
	return sink, nil
}

// Add counts an observation.
func (s *JSONLSink) Add(observation Observation) {
	key := tallyKey{experiment: observation.Experiment, point: observation.Point, outcome: observation.Outcome,
		scope: observation.Scope, rule: observation.Rule}
	s.mu.Lock()
	defer s.mu.Unlock()
	counted := s.tallies[key]
	if counted == nil {
		counted = &tally{}
		s.tallies[key] = counted
	}
	counted.count += observation.Count
	counted.total += observation.Total
	if observation.TraceID != "" && len(counted.exemplars) < s.exemplars {
		counted.exemplars = append(counted.exemplars, observation.TraceID)
	}
}

// Flush appends the counts of the window that ends now.
func (s *JSONLSink) Flush() {
	end := time.Now()
	s.mu.Lock()
	tallies, start := s.tallies, s.start
	s.tallies, s.start = map[tallyKey]*tally{}, end
	s.mu.Unlock()
	if len(tallies) == 0 {
		return
	}
	var lines []byte
	for key, counted := range tallies {
		record := ObservationRecord{
			Experiment: key.experiment, Service: s.service, Process: s.process,
			Start: float64(start.UnixNano()) / 1e9, End: float64(end.UnixNano()) / 1e9,
			Point: key.point, Outcome: key.outcome, Scope: key.scope, Count: counted.count,
			Total: counted.total, Exemplars: append([]string{}, counted.exemplars...),
		}
		if key.rule != "" {
			record.Rule = &key.rule
		}
		line, err := json.Marshal(record)
		if err != nil {
			panic(err)
		}
		lines = append(append(lines, line...), '\n')
	}
	file, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		panic(fmt.Sprintf("faultpoint: cannot write observations: %v", err))
	}
	defer file.Close()
	if _, err := file.Write(lines); err != nil {
		panic(fmt.Sprintf("faultpoint: cannot write observations: %v", err))
	}
}
