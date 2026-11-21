// Command fpebpf is the faultpoint eBPF agent: it applies the syscall, packet and native function rules of the services
// its configuration names to their cgroups, network devices and the files of their containers, and reports what the
// kernel observed at those points.
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

const environmentPrefix = "FAULTPOINT_"

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
	outcomes   map[pointsNativeKey]uint64
	fired      map[uint32]uint64
	injected   []uint64
}

// main ends through the core's Abort or Crash, whose registered cleanup detaches what the agent attached; with scan, it
// only writes the hook catalog of the configured services.
func main() {
	if len(os.Args) > 1 {
		if len(os.Args) != 3 || os.Args[1] != scanCommand {
			faultpoint.Abort("the agent takes no arguments, or %s and the directory to write the catalog to", scanCommand)
		}
		if err := scan(os.Args[2]); err != nil {
			faultpoint.Abort("%v", err)
		}
		return
	}
	rules, report := os.Getenv(environmentPrefix+"RULES"), os.Getenv(environmentPrefix+"REPORT")
	if rules == "" && report == "" {
		faultpoint.Abort("neither FAULTPOINT_RULES nor FAULTPOINT_REPORT is set, so the agent has nothing to do")
	}
	var options agentOptions
	faultpoint.Options(optionsName, &options)
	jsonl := faultpoint.DefaultJSONLOptions
	faultpoint.Options(jsonlOptionsName, &jsonl)
	if report != "" && jsonl.FlushSeconds == 0 {
		faultpoint.Abort("the agent reads kernel counts every flush_seconds, so it needs a positive interval")
	}
	services, err := options.services()
	if err != nil {
		faultpoint.Abort("%v", err)
	}
	var seed int64
	if text := os.Getenv(environmentPrefix + "SEED"); text != "" {
		if seed, err = strconv.ParseInt(text, 10, 64); err != nil {
			faultpoint.Abort("FAULTPOINT_SEED is an integer: %v", err)
		}
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	points, sites, err := locateFunctions(options.Functions, services)
	if err != nil {
		faultpoint.Abort("%v", err)
	}
	selected, err := selectedRecords(options, services)
	if err != nil {
		faultpoint.Abort("%v", err)
	}
	loaded, err := loadKernel(services)
	if err != nil {
		faultpoint.Abort("%v", err)
	}
	a := &agent{services: services, seed: seed, kernel: loaded, sinks: map[string]*faultpoint.JSONLSink{},
		natural: map[pointsNaturalKey]uint64{}, outcomes: map[pointsNativeKey]uint64{}, fired: map[uint32]uint64{}}
	faultpoint.AtExit(a.shutdown)
	if err := loaded.observeFunctions(points, sites); err != nil {
		faultpoint.Abort("%v", err)
	}
	if err := loaded.observeEvents(selected); err != nil {
		faultpoint.Abort("%v", err)
	}
	for _, name := range options.Syscalls {
		a.syscalls.number(name)
	}
	if report != "" {
		for _, configured := range services {
			if a.sinks[configured.name], err = faultpoint.NewJSONLSink(report, configured.name, jsonl); err != nil {
				faultpoint.Abort("%v", err)
			}
		}
		if err := loaded.observe(a.syscalls); err != nil {
			faultpoint.Abort("%v", err)
		}
		go func() {
			for range time.Tick(time.Duration(jsonl.FlushSeconds * float64(time.Second))) {
				a.mu.Lock()
				err := a.collect()
				a.mu.Unlock()
				if err != nil {
					faultpoint.Abort("%v", err)
				}
			}
		}()
	}
	if rules != "" {
		faultpoint.FileRuleSource{Path: rules}.Start(a.install)
	}
	<-stop
	faultpoint.Crash(0)
}

// install is the rule source's callback; a rule set the agent cannot apply ends it.
func (a *agent) install(data []byte) {
	if err := a.replace(data); err != nil {
		faultpoint.Abort("%v", err)
	}
}

// replace detaches the old rule set and writes its counts before it attaches the new one, so that every record
// belongs to one experiment.
func (a *agent) replace(data []byte) error {
	ruleset, err := faultpoint.ParseRuleSet(data)
	if err != nil {
		return fmt.Errorf("invalid rules: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rules, err := translate(ruleset, a.services, &a.syscalls, a.kernel.points, a.seed)
	if err != nil {
		return fmt.Errorf("rules the agent cannot apply: %w", err)
	}
	if err := a.detach(); err != nil {
		return err
	}
	if a.injector, err = a.kernel.inject(rules, a.services, a.syscalls); err != nil {
		return err
	}
	a.rules, a.experiment, a.injected = rules, rules.experiment, make([]uint64, len(rules.triggers))
	return nil
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

// shutdown detaches everything as the process ends; it keeps the lock, so that nothing touches what it closed.
func (a *agent) shutdown() {
	a.mu.Lock()
	if err := errors.Join(a.detach(), a.kernel.Close()); err != nil {
		fmt.Fprintf(os.Stderr, "fpebpf: %v\n", err)
		os.Exit(1)
	}
}
