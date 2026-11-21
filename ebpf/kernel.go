package main

//go:generate sh -c "bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h"
//go:generate sh -c "go tool bpf2go -tags linux -target bpfel -type trigger -type syscall_point -type syscall_rule -type syscall_rule_list -type packet_side -type packet_rule -type packet_rule_list -type natural_key -type register_name -type result_type -type error_rule -type native_action -type native_site -type native_write -type native_rule -type native_rule_list -type native_key -cflags \"-O2 -g -Wall -Werror -Wno-missing-declarations -mcpu=v3 -I$(go list -m -f '{{.Dir}}' github.com/cilium/ebpf)/examples/headers\" points bpf/points.bpf.c"

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	syscallTracepointGroup = "syscalls"
	syscallExitPrefix      = "sys_exit_"
	qdiscFq                = "fq"
)

// syscallEntryPrefixes name the syscall entry functions of each architecture, which are on the kernel's error
// injection list, so a kprobe on them may override their return.
var syscallEntryPrefixes = map[string]string{"amd64": "__x64_sys_", "arm64": "__arm64_sys_"}

// kernel holds what lives as long as the agent, including the triggers, so a rule set's injections stay readable
// after it is detached, the native points with the probes at their returns, and the event points with their probes.
type kernel struct {
	spec    *ebpf.CollectionSpec
	objects struct {
		ObserveSyscall    *ebpf.Program `ebpf:"observe_syscall"`
		LeaveNative       *ebpf.Program `ebpf:"leave_native"`
		ObserveUsdt       *ebpf.Program `ebpf:"observe_usdt"`
		ObserveTracepoint *ebpf.Program `ebpf:"observe_tracepoint"`
		CgroupServices    *ebpf.Map     `ebpf:"cgroup_services"`
		Marks             *ebpf.Map     `ebpf:"marks"`
		Natural           *ebpf.Map     `ebpf:"natural"`
		Triggers          *ebpf.Map     `ebpf:"triggers"`
		NativeSites       *ebpf.Map     `ebpf:"native_sites"`
		NativeRules       *ebpf.Map     `ebpf:"native_rules"`
		NativeOutcomes    *ebpf.Map     `ebpf:"native_outcomes"`
		EventServices     *ebpf.Map     `ebpf:"event_services"`
		EventCounts       *ebpf.Map     `ebpf:"event_counts"`
	}
	points     []nativePoint
	events     []eventPoint
	eventFiles []*os.File
	links      []link.Link
}

// injector holds what one rule set attached; closing it detaches every program, removes the qdiscs it installed and
// the native rules it put.
type injector struct {
	objects struct {
		InjectSyscall *ebpf.Program `ebpf:"inject_syscall"`
		EnterNative   *ebpf.Program `ebpf:"enter_native"`
		SyscallRules  *ebpf.Map     `ebpf:"syscall_rules"`
		PacketRules   *ebpf.Map     `ebpf:"packet_rules"`
	}
	programs    []*ebpf.Program
	links       []link.Link
	handles     []*netlink.Handle
	qdiscs      []installedQdisc
	nativeRules *ebpf.Map
	natives     []uint32
}

type installedQdisc struct {
	handle *netlink.Handle
	qdisc  netlink.Qdisc
}

func loadKernel(services []service) (*kernel, error) {
	spec, err := loadPoints()
	if err != nil {
		return nil, err
	}
	var levels uint32
	for _, configured := range services {
		for _, level := range configured.cgroups {
			if level >= 32 {
				return nil, fmt.Errorf("service %s has a cgroup %d levels deep; the agent reaches 31", configured.name, level)
			}
			levels |= 1 << level
		}
	}
	if err := spec.Variables[pointsVarCgroupLevels].Set(levels); err != nil {
		return nil, err
	}
	loaded := &kernel{spec: spec}
	if err := spec.LoadAndAssign(&loaded.objects, nil); err != nil {
		return nil, err
	}
	for _, configured := range services {
		for cgroup := range configured.cgroups {
			if err := loaded.objects.CgroupServices.Put(cgroup, configured.index); err != nil {
				return nil, errors.Join(err, loaded.Close())
			}
		}
	}
	return loaded, nil
}

// observe counts the natural outcomes of syscalls at their exit; the cookie is the syscall's number in the table.
func (k *kernel) observe(syscalls syscallTable) error {
	for number, name := range syscalls {
		attached, err := link.Tracepoint(syscallTracepointGroup, syscallExitPrefix+name, k.objects.ObserveSyscall,
			&link.TracepointOptions{Cookie: uint64(number)})
		if err != nil {
			return fmt.Errorf("observing syscall %s: %w", name, err)
		}
		k.links = append(k.links, attached)
	}
	return nil
}

// observeFunctions attaches a probe at every return of the native points, which counts their results and negates a
// check, for as long as the agent runs; the entries are probed only while a rule injects there.
func (k *kernel) observeFunctions(points []nativePoint, sites []pointsNativeSite) error {
	k.points = points
	for cookie, site := range sites {
		if err := k.objects.NativeSites.Put(uint32(cookie), site); err != nil {
			return fmt.Errorf("the agent probes at most %d native sites: %w", k.objects.NativeSites.MaxEntries(), err)
		}
	}
	for _, point := range points {
		attached, err := attachSites(point, point.returns, k.objects.LeaveNative)
		k.links = append(k.links, attached...)
		if err != nil {
			return err
		}
	}
	return nil
}

func (k *kernel) Close() error {
	var errs []error
	for _, attached := range k.links {
		errs = append(errs, attached.Close())
	}
	for _, point := range k.points {
		errs = append(errs, closeFiles(point.files))
	}
	errs = append(errs, closeFiles(k.eventFiles), k.objects.ObserveSyscall.Close(), k.objects.LeaveNative.Close(),
		k.objects.ObserveUsdt.Close(), k.objects.ObserveTracepoint.Close(), k.objects.CgroupServices.Close(),
		k.objects.Marks.Close(), k.objects.Natural.Close(), k.objects.Triggers.Close(), k.objects.NativeSites.Close(),
		k.objects.NativeRules.Close(), k.objects.NativeOutcomes.Close(), k.objects.EventServices.Close(),
		k.objects.EventCounts.Close())
	return errors.Join(errs...)
}

// inject loads a rule set's maps and attaches its programs: a kprobe on the entry of each syscall a rule names, a tc
// program on the egress of each device that transmits packets a rule names, and a uprobe on the entries of each native
// point a fail or crash rule names.
func (k *kernel) inject(rules *kernelRules, services []service, syscalls syscallTable) (*injector, error) {
	attached := &injector{nativeRules: k.objects.NativeRules}
	if err := attached.attach(k, rules, services, syscalls); err != nil {
		return nil, errors.Join(err, attached.Close())
	}
	return attached, nil
}

func (i *injector) attach(k *kernel, rules *kernelRules, services []service, syscalls syscallTable) error {
	err := k.spec.LoadAndAssign(&i.objects, &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{
		pointsMapCgroupServices: k.objects.CgroupServices, pointsMapMarks: k.objects.Marks,
		pointsMapTriggers: k.objects.Triggers, pointsMapNativeSites: k.objects.NativeSites,
		pointsMapNativeRules: k.objects.NativeRules, pointsMapNativeOutcomes: k.objects.NativeOutcomes}})
	if err != nil {
		return err
	}
	for index, trigger := range rules.triggers {
		if err := k.objects.Triggers.Put(uint32(index), trigger); err != nil {
			return err
		}
	}
	prefix, known := syscallEntryPrefixes[runtime.GOARCH]
	if len(rules.syscalls) > 0 && !known {
		return fmt.Errorf("the agent does not know the syscall entry functions of %s", runtime.GOARCH)
	}
	probed := map[uint32]bool{}
	for point, list := range rules.syscalls {
		if err := i.objects.SyscallRules.Put(point, list); err != nil {
			return err
		}
		if probed[point.Syscall] {
			continue
		}
		probed[point.Syscall] = true
		attached, err := link.Kprobe(prefix+syscalls[point.Syscall], i.objects.InjectSyscall,
			&link.KprobeOptions{Cookie: uint64(point.Syscall)})
		if err != nil {
			return fmt.Errorf("injecting at syscall %s: %w", syscalls[point.Syscall], err)
		}
		i.links = append(i.links, attached)
	}
	for side, list := range rules.packets {
		if err := i.objects.PacketRules.Put(side, list); err != nil {
			return err
		}
		for _, device := range services[side.Service].devices {
			if directions[device.Transmits] != pointsDirection(side.Direction) {
				continue
			}
			if err := i.attachDevice(k, device, side, rules.delayed[side]); err != nil {
				return fmt.Errorf("device %s in %q: %w", device.Name, device.Netns, err)
			}
		}
	}
	for point, list := range rules.natives {
		if err := k.objects.NativeRules.Put(point, list); err != nil {
			return err
		}
		i.natives = append(i.natives, point)
		if !slices.ContainsFunc(list.Rules[:list.Count], func(rule pointsNativeRule) bool {
			return rule.Action != pointsNativeActionNEGATE
		}) {
			continue
		}
		attached, err := attachSites(k.points[point], k.points[point].entries, i.objects.EnterNative)
		i.links = append(i.links, attached...)
		if err != nil {
			return err
		}
	}
	return nil
}

// attachDevice loads the packet program for one service and direction, so the program needs no lookup to know them,
// and attaches it on the device's egress, where fq holds a delayed packet until the departure time it sets.
func (i *injector) attachDevice(k *kernel, device deviceOptions, side pointsPacketSide, delayed bool) error {
	spec := k.spec.Copy()
	if err := spec.Variables[pointsVarPacketService].Set(side.Service); err != nil {
		return err
	}
	if err := spec.Variables[pointsVarPacketDirection].Set(pointsDirection(side.Direction)); err != nil {
		return err
	}
	var objects struct {
		InjectPacket *ebpf.Program `ebpf:"inject_packet"`
	}
	err := spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{
		pointsMapTriggers: k.objects.Triggers, pointsMapPacketRules: i.objects.PacketRules}})
	if err != nil {
		return err
	}
	i.programs = append(i.programs, objects.InjectPacket)
	var namespace netns.NsHandle
	if device.Netns == "" {
		namespace, err = netns.Get()
	} else {
		namespace, err = netns.GetFromPath(device.Netns)
	}
	if err != nil {
		return err
	}
	defer namespace.Close()
	handle, err := netlink.NewHandleAt(namespace)
	if err != nil {
		return err
	}
	i.handles = append(i.handles, handle)
	found, err := handle.LinkByName(device.Name)
	if err != nil {
		return err
	}
	if delayed {
		if err := i.installFq(handle, found); err != nil {
			return err
		}
	}
	attached, err := inNamespace(namespace, func() (link.Link, error) {
		return link.AttachTCX(link.TCXOptions{Interface: found.Attrs().Index, Program: objects.InjectPacket,
			Attach: ebpf.AttachTCXEgress})
	})
	if err != nil {
		return err
	}
	i.links = append(i.links, attached)
	return nil
}

// installFq makes fq the device's root qdisc unless it already is; it only replaces a root the kernel attached by
// default, which deleting fq restores, and refuses to replace one somebody configured.
func (i *injector) installFq(handle *netlink.Handle, device netlink.Link) error {
	root, err := rootQdisc(handle, device)
	if err != nil || root.Type() == qdiscFq {
		return err
	}
	if root.Attrs().Handle != netlink.HANDLE_NONE {
		return fmt.Errorf("the root qdisc is a configured %s; a delay needs fq there", root.Type())
	}
	if err := handle.QdiscReplace(netlink.NewFq(netlink.QdiscAttrs{LinkIndex: device.Attrs().Index,
		Parent: netlink.HANDLE_ROOT})); err != nil {
		return err
	}
	installed, err := rootQdisc(handle, device)
	if err != nil {
		return err
	}
	i.qdiscs = append(i.qdiscs, installedQdisc{handle: handle, qdisc: installed})
	return nil
}

func rootQdisc(handle *netlink.Handle, device netlink.Link) (netlink.Qdisc, error) {
	qdiscs, err := handle.QdiscList(device)
	if err != nil {
		return nil, err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Attrs().Parent == netlink.HANDLE_ROOT {
			return qdisc, nil
		}
	}
	return nil, fmt.Errorf("%s has no root qdisc", device.Attrs().Name)
}

// inNamespace runs attach on a thread that enters the namespace and ends with its goroutine, because the kernel reads
// a device index in the network namespace of the calling thread.
func inNamespace(namespace netns.NsHandle, attach func() (link.Link, error)) (link.Link, error) {
	type result struct {
		attached link.Link
		err      error
	}
	done := make(chan result)
	go func() {
		runtime.LockOSThread()
		if err := netns.Set(namespace); err != nil {
			done <- result{err: err}
			return
		}
		attached, err := attach()
		done <- result{attached: attached, err: err}
	}()
	outcome := <-done
	return outcome.attached, outcome.err
}

// Close detaches the rule set; a qdisc whose device has gone, with the container that owned it, is already removed.
func (i *injector) Close() error {
	var errs []error
	for _, attached := range i.links {
		errs = append(errs, attached.Close())
	}
	for _, point := range i.natives {
		errs = append(errs, i.nativeRules.Delete(point))
	}
	for _, installed := range i.qdiscs {
		if err := installed.handle.QdiscDel(installed.qdisc); !errors.Is(err, unix.ENODEV) {
			errs = append(errs, err)
		}
	}
	for _, handle := range i.handles {
		handle.Close()
	}
	for _, program := range i.programs {
		errs = append(errs, program.Close())
	}
	errs = append(errs, i.objects.InjectSyscall.Close(), i.objects.EnterNative.Close(), i.objects.SyscallRules.Close(),
		i.objects.PacketRules.Close())
	return errors.Join(errs...)
}
