package faultpoint

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"strconv"
	"sync"
	"time"
)

// Observation is Count executions of a point with one outcome, Total their summed quantity and Elapsed their summed
// milliseconds from entering the point to the outcome: one execution from the core, or the counts a kernel program
// already aggregated. Detail tells apart executions of one outcome by bounded values, such as an exact status or an
// error type, with the keys spec/kinds.json gives the kind.
type Observation struct {
	Experiment string
	Point      string
	Outcome    string
	Scope      string
	Rule       string
	Count      int
	Total      float64
	Elapsed    float64
	TraceID    string
	Detail     map[string]string
}

// ObservationSink receives every observation; Flush writes what it holds, and the core calls it before
// a rule set is replaced and before the process ends.
type ObservationSink interface {
	Add(observation Observation)
	Flush()
}

// ObservationRecord is one line of an observation file, as spec/observation.schema.json defines it.
type ObservationRecord struct {
	Experiment string            `json:"experiment"`
	Service    string            `json:"service"`
	Process    string            `json:"process"`
	Start      float64           `json:"start"`
	End        float64           `json:"end"`
	Point      string            `json:"point"`
	Outcome    string            `json:"outcome"`
	Scope      string            `json:"scope"`
	Rule       *string           `json:"rule"`
	Count      int               `json:"count"`
	Total      float64           `json:"total"`
	Elapsed    float64           `json:"elapsed"`
	Exemplars  []string          `json:"exemplars"`
	Detail     map[string]string `json:"detail"`
}

// JSONLOptions are the options of the JSON Lines sink, given under "jsonl" in the configuration; a flush interval of
// 0 writes every observation as it comes, for processes such as test binaries that end without a last flush, and the
// exemplar rate is the share of traces whose ids are kept, for hot library paths, while counts stay exact.
type JSONLOptions struct {
	FlushSeconds float64 `json:"flush_seconds"`
	Exemplars    int     `json:"exemplars"`
	ExemplarRate float64 `json:"exemplar_rate"`
}

// DefaultJSONLOptions write every two seconds and keep five trace ids per record, of every trace.
var DefaultJSONLOptions = JSONLOptions{FlushSeconds: 2, Exemplars: 5, ExemplarRate: 1}

const exemplarBuckets = 10_000

// tallyKey is what one record counts; detail is the detail in its canonical form, JSON with sorted keys.
type tallyKey struct {
	experiment, point, outcome, scope, rule, detail string
}

type tally struct {
	count     int
	total     float64
	elapsed   float64
	exemplars []string
	detail    map[string]string
}

// JSONLSink counts observations per experiment, point, outcome, scope, rule and detail, and appends the counts of
// each window to a JSON Lines file.
type JSONLSink struct {
	path         string
	service      string
	process      string
	exemplars    int
	sampled      uint64
	writeThrough bool
	mu           sync.Mutex
	start        time.Time
	tallies      map[tallyKey]*tally
}

// NewJSONLSink starts a sink that writes to path at the interval its options give.
func NewJSONLSink(path, service string, options JSONLOptions) (*JSONLSink, error) {
	if options.FlushSeconds < 0 || options.Exemplars < 0 || options.ExemplarRate < 0 || options.ExemplarRate > 1 {
		return nil, fmt.Errorf("jsonl flushes after at least 0 seconds, keeps at least 0 exemplars and samples a share of traces: %+v", options)
	}
	host, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	sink := &JSONLSink{
		path: path, service: service, process: fmt.Sprintf("%s:%d", host, os.Getpid()), exemplars: options.Exemplars,
		sampled: uint64(options.ExemplarRate * exemplarBuckets), writeThrough: options.FlushSeconds == 0,
		start: time.Now(), tallies: map[tallyKey]*tally{},
	}
	if !sink.writeThrough {
		go func() {
			defer Guard()
			for range time.Tick(time.Duration(options.FlushSeconds * float64(time.Second))) {
				sink.Flush()
			}
		}()
	}
	return sink, nil
}

// Add counts an observation.
func (s *JSONLSink) Add(observation Observation) {
	detail := map[string]string{}
	maps.Copy(detail, observation.Detail)
	canonical, err := json.Marshal(detail)
	if err != nil {
		panic(err)
	}
	key := tallyKey{experiment: observation.Experiment, point: observation.Point, outcome: observation.Outcome,
		scope: observation.Scope, rule: observation.Rule, detail: string(canonical)}
	s.mu.Lock()
	counted := s.tallies[key]
	if counted == nil {
		counted = &tally{detail: detail}
		s.tallies[key] = counted
	}
	counted.count += observation.Count
	counted.total += observation.Total
	counted.elapsed += observation.Elapsed
	if len(counted.exemplars) < s.exemplars && s.keeps(observation.TraceID) {
		counted.exemplars = append(counted.exemplars, observation.TraceID)
	}
	s.mu.Unlock()
	if s.writeThrough {
		s.Flush()
	}
}

// keeps is whether a trace's id is sampled as an exemplar, by the low bits of the id, so that every process keeps the
// same traces.
func (s *JSONLSink) keeps(traceID string) bool {
	low, err := strconv.ParseUint(traceID[max(len(traceID)-8, 0):], 16, 64)
	return traceID != "" && err == nil && low%exemplarBuckets < s.sampled
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
			Total: counted.total, Elapsed: counted.elapsed, Exemplars: append([]string{}, counted.exemplars...),
			Detail: counted.detail,
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
