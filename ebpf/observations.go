package main

import (
	"fmt"
	"syscall"

	"faultpoint"

	"golang.org/x/sys/unix"
)

// collect hands the sinks what the kernel counted since the last collection: the natural outcomes of the observed
// syscalls, and the executions each rule injected, which are as many as its trigger fired up to its limit.
func (a *agent) collect() error {
	var key pointsNaturalKey
	var perCPU []uint64
	entries := a.kernel.objects.Natural.Iterate()
	for entries.Next(&key, &perCPU) {
		var total uint64
		for _, count := range perCPU {
			total += count
		}
		delta := total - a.natural[key]
		a.natural[key] = total
		if delta == 0 {
			continue
		}
		name := a.services[key.Service].name
		a.sinks[name].Add(faultpoint.Observation{Experiment: a.experiment, Outcome: syscallOutcome(key.Error),
			Point: faultpoint.PointID(name, kindSyscall, a.syscalls[key.Syscall]), Count: int(delta)})
	}
	if err := entries.Err(); err != nil {
		return fmt.Errorf("cannot read the natural counts: %w", err)
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
