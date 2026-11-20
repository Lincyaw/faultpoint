// Command fpebpf is the faultpoint eBPF agent: it applies the syscall and packet rules of the services its
// configuration names to their cgroups and network devices, and reports what the kernel observed at those points.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"faultpoint"
)

const (
	environmentPrefix = "FAULTPOINT_"
	invalidRulesExit  = 70
)

// agent applies one rule set at a time; the mutex orders installs, collections and the final detach.
type agent struct {
	mu         sync.Mutex
	services   []service
	syscalls   syscallTable
	seed       int64
	kernel     *kernel
	injector   *injector
	rules      *kernelRules
	experiment string
	sinks      map[string]*faultpoint.JSONLSink
	natural    map[pointsNaturalKey]uint64
	injected   []uint64
}

func main() {
	rules, report := os.Getenv(environmentPrefix+"RULES"), os.Getenv(environmentPrefix+"REPORT")
	if rules == "" && report == "" {
		exit(errors.New("neither FAULTPOINT_RULES nor FAULTPOINT_REPORT is set, so the agent has nothing to do"))
	}
	var options agentOptions
	faultpoint.Options(optionsName, &options)
	jsonl := faultpoint.DefaultJSONLOptions
	faultpoint.Options(jsonlOptionsName, &jsonl)
	services, err := options.services()
	if err != nil {
		exit(err)
	}
	var seed int64
	if text := os.Getenv(environmentPrefix + "SEED"); text != "" {
		if seed, err = strconv.ParseInt(text, 10, 64); err != nil {
			exit(fmt.Errorf("FAULTPOINT_SEED is an integer: %w", err))
		}
	}
	loaded, err := loadKernel(services)
	if err != nil {
		exit(err)
	}
	a := &agent{services: services, seed: seed, kernel: loaded, sinks: map[string]*faultpoint.JSONLSink{},
		natural: map[pointsNaturalKey]uint64{}}
	for _, name := range options.Syscalls {
		a.syscalls.number(name)
	}
	if report != "" {
		a.mu.Lock()
		for _, configured := range services {
			if a.sinks[configured.name], err = faultpoint.NewJSONLSink(report, configured.name, jsonl); err != nil {
				a.abort("%v", err)
			}
		}
		if err := loaded.observe(a.syscalls); err != nil {
			a.abort("%v", err)
		}
		a.mu.Unlock()
		go func() {
			for range time.Tick(time.Duration(jsonl.FlushSeconds * float64(time.Second))) {
				a.mu.Lock()
				if err := a.collect(); err != nil {
					a.abort("%v", err)
				}
				a.mu.Unlock()
			}
		}()
	}
	if rules != "" {
		faultpoint.FileRuleSource{Path: rules}.Start(a.install)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	a.mu.Lock()
	if err := a.close(); err != nil {
		exit(err)
	}
}

// install replaces the rule set: the old one is detached and its counts written before the new one is attached,
// so that every record belongs to one experiment.
func (a *agent) install(data []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ruleset, err := faultpoint.ParseRuleSet(data)
	if err != nil {
		a.abort("invalid rules: %v", err)
	}
	rules, err := translate(ruleset, a.services, &a.syscalls, a.seed)
	if err != nil {
		a.abort("rules the agent cannot apply: %v", err)
	}
	if err := a.detach(); err != nil {
		a.abort("%v", err)
	}
	if a.injector, err = a.kernel.inject(rules, a.services, a.syscalls); err != nil {
		a.abort("%v", err)
	}
	a.rules, a.experiment, a.injected = rules, rules.experiment, make([]uint64, len(rules.triggers))
}

// detach removes the rule set from the kernel and writes what was counted under it.
func (a *agent) detach() error {
	var errs []error
	if a.injector != nil {
		errs = append(errs, a.injector.Close())
		a.injector = nil
	}
	if len(a.sinks) > 0 {
		errs = append(errs, a.collect())
	}
	for _, sink := range a.sinks {
		sink.Flush()
	}
	return errors.Join(errs...)
}

func (a *agent) close() error {
	return errors.Join(a.detach(), a.kernel.Close())
}

// abort detaches everything and ends the agent, so that no experiment runs under rules it did not ask for.
func (a *agent) abort(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "fpebpf: "+format+"; stopping\n", arguments...)
	if err := a.close(); err != nil {
		fmt.Fprintf(os.Stderr, "fpebpf: %v\n", err)
	}
	os.Exit(invalidRulesExit)
}

func exit(err error) {
	fmt.Fprintf(os.Stderr, "fpebpf: %v\n", err)
	os.Exit(1)
}
