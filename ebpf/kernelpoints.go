package main

import (
	"fmt"
	"path/filepath"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

const (
	// noArgument is an argument index of a kernel point whose function takes no argument of that type.
	noArgument   = -1
	sockaddrType = "sockaddr"
	fileType     = "file"
	intSize      = 4
)

// lsmErrnos are the errnos with which an LSM, by convention, denies an operation.
var lsmErrnos = []string{"EACCES", "EPERM"}

// operationErrnos are, for each security_ function whose caller the agent knows, the errnos the caller's own
// operation returns, so that an injected failure is one the operation can have: a connect to a closed or unreachable
// peer.
var operationErrnos = map[string][]string{
	"security_socket_connect": {"ECONNREFUSED", "ENETUNREACH", "EHOSTUNREACH"},
}

// kernelPoint is a selected record of a security_ function of vmlinux, whose result the agent changes with fmod_ret
// and observes with fexit. errors are the negative errnos a rule may fail it with: the LSM convention and the errnos
// of its caller's operation, within the record's values.
type kernelPoint struct {
	id       string
	function string
	errors   map[string]int32
	site     pointsKernelPoint
}

// kernelPoints makes a point of every selected record of a kernel function, finding in BTF which of the function's
// arguments the rules' conditions read.
func kernelPoints(selected []selectedRecord) ([]kernelPoint, error) {
	var points []kernelPoint
	var spec *btf.Spec
	for _, chosen := range selected {
		record := chosen.record
		if record.Kind != kindCall || filepath.IsAbs(record.Target.File) {
			continue
		}
		if record.Inject != mechanismFmodRet || record.Target.File != kernelObject {
			return nil, fmt.Errorf("record %s: the agent serves the security_ functions of %s, whose results %s "+
				"changes; exclude it from the selection", record.ID, kernelObject, mechanismFmodRet)
		}
		if spec == nil {
			build, err := kernelBuild()
			if err != nil {
				return nil, err
			}
			if record.Target.BuildID != build {
				return nil, fmt.Errorf("record %s is of a kernel build other than the running %s", record.ID, build)
			}
			if spec, err = btf.LoadKernelSpec(); err != nil {
				return nil, err
			}
		}
		var function *btf.Func
		if err := spec.TypeByName(record.Target.Symbol, &function); err != nil {
			return nil, fmt.Errorf("record %s: %w", record.ID, err)
		}
		prototype := function.Type.(*btf.FuncProto)
		result, isInt := btf.UnderlyingType(prototype.Return).(*btf.Int)
		if !isInt || result.Size != intSize || result.Encoding != btf.Signed {
			return nil, fmt.Errorf("record %s: the agent serves kernel functions that return an int", record.ID)
		}
		site := pointsKernelPoint{Service: chosen.owner.index, SockaddrArgument: noArgument, FileArgument: noArgument}
		for index, parameter := range prototype.Params {
			switch pointedStruct(parameter.Type) {
			case sockaddrType:
				site.SockaddrArgument = int32(index)
			case fileType:
				site.FileArgument = int32(index)
			}
		}
		legal := map[string]int32{}
		for _, name := range append(operationErrnos[record.Target.Symbol], lsmErrnos...) {
			value := -int64(errnos[name])
			if slices.ContainsFunc(record.Values, func(values valueRange) bool {
				return values.Min <= value && value <= values.Max
			}) {
				legal[name] = int32(value)
			}
		}
		points = append(points, kernelPoint{id: record.ID, function: record.Target.Symbol, errors: legal, site: site})
	}
	return points, nil
}

// pointedStruct is the name of the struct a parameter points to, empty when it points to none.
func pointedStruct(parameter btf.Type) string {
	pointer, isPointer := btf.UnderlyingType(parameter).(*btf.Pointer)
	if !isPointer {
		return ""
	}
	pointed, isStruct := btf.UnderlyingType(pointer.Target).(*btf.Struct)
	if !isStruct {
		return ""
	}
	return pointed.Name
}

// addKernelPoints puts the kernel points where their programs find them, indexed by the cookie of their links.
func (k *kernel) addKernelPoints(points []kernelPoint) error {
	k.kernels = points
	for index, point := range points {
		if err := k.objects.KernelPoints.Put(uint32(index), point.site); err != nil {
			return fmt.Errorf("the agent serves at most %d kernel points: %w", k.objects.KernelPoints.MaxEntries(), err)
		}
	}
	return nil
}

// observeKernelFunctions attaches an fexit program to the function of each kernel point for as long as the agent
// reports, since every call on the host pays for it; fmod_ret is attached only while a rule injects there.
func (k *kernel) observeKernelFunctions() error {
	for index, point := range k.kernels {
		var observing struct {
			Program *ebpf.Program `ebpf:"observe_kernel"`
		}
		if err := k.loadKernelProgram(point.function, &observing); err != nil {
			return fmt.Errorf("observing %s: %w", point.id, err)
		}
		k.programs = append(k.programs, observing.Program)
		attached, err := link.AttachTracing(link.TracingOptions{Program: observing.Program,
			AttachType: ebpf.AttachTraceFExit, Cookie: uint64(index)})
		if err != nil {
			return fmt.Errorf("observing %s: %w", point.id, err)
		}
		k.links = append(k.links, attached)
	}
	return nil
}

// loadKernelProgram loads a kernel point program for a function, since a tracing program names its function when it
// loads, into objects, a struct naming the one program, with the agent's maps.
func (k *kernel) loadKernelProgram(function string, objects any) error {
	spec := k.spec.Copy()
	spec.Programs[pointsProgInjectKernel].AttachTo = function
	spec.Programs[pointsProgObserveKernel].AttachTo = function
	return spec.LoadAndAssign(objects, &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{
		pointsMapCgroupServices: k.objects.CgroupServices, pointsMapTriggers: k.objects.Triggers,
		pointsMapKernelPoints: k.objects.KernelPoints, pointsMapKernelRules: k.objects.KernelRules,
		pointsMapKernelFlights: k.objects.KernelFlights, pointsMapKernelOutcomes: k.objects.KernelOutcomes}})
}
