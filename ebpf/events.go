package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const outcomeFired = "fired"

// eventPoint is an event the agent counts: its point and the service it belongs to; its index is the cookie of the
// probes that fire it.
type eventPoint struct {
	id      string
	service string
}

// observeEvents attaches the selected event records for as long as the agent runs: a uprobe at every site of a USDT
// probe, with its semaphore, in every file of the service's containers that holds it, and a program on a tracepoint.
func (k *kernel) observeEvents(selected []selectedRecord) error {
	if len(selected) == 0 {
		return nil
	}
	build, err := kernelBuild()
	if err != nil {
		return err
	}
	hostRoot, err := hostRootMount()
	if err != nil {
		return err
	}
	for _, event := range selected {
		record := event.record
		if record.Kind != kindEvent {
			continue
		}
		if record.Observe == mechanismTracepoint && record.Target.BuildID != build {
			return fmt.Errorf("%s is a point of another kernel build than the running %s", record.ID, build)
		}
		index := uint32(len(k.events))
		if err := k.objects.EventServices.Put(index, event.owner.index); err != nil {
			return fmt.Errorf("the agent counts at most %d events: %w", k.objects.EventServices.MaxEntries(), err)
		}
		k.events = append(k.events, eventPoint{id: record.ID, service: event.owner.name})
		if record.Observe == mechanismTracepoint {
			// A tracepoint holds a program once however many links attach it, so each event has its own program.
			var observing struct {
				Program *ebpf.Program `ebpf:"observe_tracepoint"`
			}
			err := k.spec.LoadAndAssign(&observing, &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{
				pointsMapCgroupServices: k.objects.CgroupServices, pointsMapEventServices: k.objects.EventServices,
				pointsMapEventCounts: k.objects.EventCounts}})
			if err != nil {
				return fmt.Errorf("observing %s: %w", record.ID, err)
			}
			k.programs = append(k.programs, observing.Program)
			group, name, _ := strings.Cut(record.Target.Symbol, ":")
			attached, err := link.Tracepoint(group, name, observing.Program,
				&link.TracepointOptions{Cookie: uint64(index)})
			if err != nil {
				return fmt.Errorf("observing %s: %w", record.ID, err)
			}
			k.links = append(k.links, attached)
			continue
		}
		if err := k.observeProbe(record, event.owner, hostRoot, uint64(index)); err != nil {
			return fmt.Errorf("observing %s: %w", record.ID, err)
		}
	}
	return nil
}

// observeProbe attaches a USDT probe at its sites in every file of the service's containers, which must hold the
// record's build.
func (k *kernel) observeProbe(record hookRecord, owner service, hostRoot int, cookie uint64) error {
	files, err := openContainerFiles(owner, record.Target.File, hostRoot)
	if err != nil {
		return err
	}
	k.eventFiles = append(k.eventFiles, files...)
	_, build, executables, err := readBuild(files)
	if err != nil {
		return err
	}
	if build != record.Target.BuildID {
		return errors.New("the service's containers hold another build of the file than the catalog")
	}
	for _, executable := range executables {
		for _, location := range record.Target.Locations {
			attached, err := executable.Uprobe(record.Target.Symbol, k.objects.ObserveUsdt, &link.UprobeOptions{
				Address: location, RefCtrOffset: record.Target.Semaphore, Cookie: cookie})
			if err != nil {
				return err
			}
			k.links = append(k.links, attached)
		}
	}
	return nil
}
