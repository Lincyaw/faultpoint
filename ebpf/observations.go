package main

import (
	"fmt"
	"strconv"
	"syscall"

	"faultpoint"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// collect hands the sinks what the kernel counted since the last collection: the natural outcomes of the observed
// syscalls, the natural and injected outcomes of the native points, and the executions each syscall or packet rule
// injected, which are as many as its trigger fired up to its limit.
func (a *agent) collect() error {
	err := countSince(a.kernel.objects.Natural, a.natural, func(key pointsNaturalKey, delta uint64) {
		name := a.services[key.Service].name
		a.sinks[name].Add(faultpoint.Observation{Experiment: a.experiment, Outcome: syscallOutcome(key.Error),
			Point: faultpoint.PointID(name, kindSyscall, a.syscalls[key.Syscall]), Count: int(delta)})
	})
	if err != nil {
		return fmt.Errorf("cannot read the natural counts: %w", err)
	}
	err = countSince(a.kernel.objects.NativeOutcomes, a.outcomes, func(key pointsNativeKey, delta uint64) {
		point := a.kernel.points[key.Point]
		observation := faultpoint.Observation{Experiment: a.experiment, Point: point.id,
			Outcome: point.outcome(key.Flagged), Count: int(delta)}
		if key.Rule > 0 {
			observation.Rule = a.rules.injections[key.Rule-1].rule
		}
		if point.valued && key.Flagged != 0 {
			observation.Detail = map[string]string{detailValue: strconv.FormatInt(key.Value, 10)}
		}
		a.sinks[a.services[point.service].name].Add(observation)
	})
	if err != nil {
		return fmt.Errorf("cannot read the native counts: %w", err)
	}
	if a.rules == nil {
		return nil
	}
	for index, injected := range a.rules.injections {
		var trigger pointsTrigger
		if err := a.kernel.objects.Triggers.Lookup(uint32(index), &trigger); err != nil {
			return fmt.Errorf("cannot read the trigger of rule %s: %w", injected.rule, err)
		}
		count := min(trigger.Injections, trigger.Limit)
		delta := count - a.injected[index]
		a.injected[index] = count
		if delta == 0 || injected.outcome == "" {
			continue
		}
		name, _, _, _ := faultpoint.SplitPoint(injected.point)
		a.sinks[name].Add(faultpoint.Observation{Experiment: a.experiment, Point: injected.point,
			Outcome: injected.outcome, Rule: injected.rule, Count: int(delta)})
	}
	return nil
}

// countSince sums each key of a per-CPU count map and hands add the increase since the totals seen before.
func countSince[K comparable](counts *ebpf.Map, seen map[K]uint64, add func(key K, delta uint64)) error {
	var key K
	var perCPU []uint64
	entries := counts.Iterate()
	for entries.Next(&key, &perCPU) {
		var total uint64
		for _, count := range perCPU {
			total += count
		}
		if delta := total - seen[key]; delta > 0 {
			add(key, delta)
		}
		seen[key] = total
	}
	return entries.Err()
}

// syscallOutcome names a syscall's errno; a kernel-internal errno such as ERESTARTSYS has no name in user space.
func syscallOutcome(errno int32) string {
	if errno == 0 {
		return outcomeOK
	}
	if name := unix.ErrnoName(syscall.Errno(errno)); name != "" {
		return name
	}
	return syscall.Errno(errno).Error()
}
