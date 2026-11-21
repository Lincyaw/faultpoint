package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"faultpoint"
)

const (
	scanCommand        = "scan"
	hooksDirectory     = "hooks"
	manifestsDirectory = "manifests"
	kindEvent          = "event"
	// languageNative is the manifest language of the points the agent places in machine code, whatever language the
	// code was written in.
	languageNative = "native"
)

// Mechanisms a record injects or observes with.
const (
	mechanismUprobeEntry    = "uprobe_entry"
	mechanismUprobeReturns  = "uprobe_returns"
	mechanismUSDT           = "usdt"
	mechanismKprobeOverride = "kprobe_override"
	mechanismFmodRet        = "fmod_ret"
	mechanismFexit          = "fexit"
	mechanismTracepoint     = "tracepoint"
	mechanismSyscallExit    = "syscall_exit_tracepoint"
)

// Layers of a record, as the search names them.
const (
	layerLibrary  = "library"
	layerUpstream = "upstream"
	layerKernel   = "kernel"
)

// Costs of a hit: a kernel program on a kernel path, or a breakpoint trap from user space.
const (
	costKernel = "kernel"
	costTrap   = "trap"
)

// Trap scopes: every process of the host hits a kernel probe, and every process mapping a file's inode hits a uprobe;
// the programs filter by cgroup, which keeps out the injection but not the cost.
const (
	trapsHost  = "host"
	trapsInode = "inode"
)

const (
	uprobeSafety  = "an entry injection skips the function's body, so its out-parameters and side effects do not happen"
	usdtSafety    = "attaching sets the probe's semaphore in every process mapping the file, which runs its argument code"
	kernelSafety  = "the agent filters by cgroup; the agent serves no kernel call point yet"
	fmodRetSafety = "fmod_ret on security_ without the BPF LSM is not verified; the agent serves no kernel call point yet"
	syscallSafety = "the override returns before the syscall runs, for the service's cgroups only"
)

// hookOptions select a service's records for its manifest, in the shape of placement.scope (design §6.4): a record is
// selected when its key, its locator without the build, starts with an include whose kinds, if given, hold the
// record's kind, and with no exclude. Upstream marks an infrastructure component, all of whose records are upstream.
type hookOptions struct {
	Upstream bool        `json:"upstream"`
	Scope    []hookScope `json:"scope"`
	Exclude  []string    `json:"exclude"`
}

type hookScope struct {
	Include string   `json:"include"`
	Kinds   []string `json:"kinds"`
}

// hookRecord is one (target, mechanism) of the catalog (design §6.6). Values are the legal values a rule may give, with
// their provenance; observed values stay empty until a control run fills them in. File offsets locate the probes.
type hookRecord struct {
	ID        string         `json:"id"`
	Key       string         `json:"key"`
	Kind      string         `json:"kind"`
	Layer     string         `json:"layer"`
	Inject    string         `json:"inject,omitempty"`
	Observe   string         `json:"observe,omitempty"`
	Target    hookTarget     `json:"target"`
	Signature *hookSignature `json:"signature,omitempty"`
	Actions   []string       `json:"actions"`
	Values    []valueRange   `json:"values"`
	Observed  []valueRange   `json:"observed"`
	Cost      string         `json:"cost"`
	Traps     string         `json:"traps"`
	Safety    string         `json:"safety,omitempty"`
	Coverage  *hookCoverage  `json:"coverage,omitempty"`
	Selected  bool           `json:"selected"`
}

type hookTarget struct {
	File      string      `json:"file"`
	BuildID   string      `json:"build_id"`
	Symbol    string      `json:"symbol"`
	Aliases   []string    `json:"aliases,omitempty"`
	Entry     uint64      `json:"entry,omitempty"`
	Returns   []uint64    `json:"returns,omitempty"`
	Clones    []hookClone `json:"clones,omitempty"`
	Locations []uint64    `json:"locations,omitempty"`
	Semaphore uint64      `json:"semaphore,omitempty"`
	Arguments string      `json:"arguments,omitempty"`
}

// hookClone is a compiler clone of a record's function; a cold part is entered by a jump, not a call.
type hookClone struct {
	Symbol  string   `json:"symbol"`
	Entry   uint64   `json:"entry"`
	Returns []uint64 `json:"returns"`
	Cold    bool     `json:"cold,omitempty"`
}

type hookSignature struct {
	Source  string        `json:"source"`
	Text    string        `json:"text"`
	Returns returnClass   `json:"returns,omitempty"`
	Size    int64         `json:"size,omitempty"`
	Results []returnClass `json:"results,omitempty"`
	Line    int           `json:"line,omitempty"`
}

// hookCoverage is what a function's probes cannot see: results through tail calls, and possibly through indirect jumps,
// and the code past an instruction that does not decode.
type hookCoverage struct {
	TailCalls     int    `json:"tail_calls"`
	IndirectJumps int    `json:"indirect_jumps"`
	Undecodable   string `json:"undecodable,omitempty"`
}

// hookCatalog is one service's hook records with what the scan read: the kernel and every mapped file.
type hookCatalog struct {
	Service  string          `json:"service"`
	Upstream bool            `json:"upstream"`
	Kernel   kernelSummary   `json:"kernel"`
	Files    []binarySummary `json:"files"`
	Refused  []refusedFile   `json:"refused"`
	Records  []hookRecord    `json:"records"`
}

// manifest and pointEntry are spec/manifest.schema.json, so that the search reads the selected records as it reads the
// points of an SDK.
type manifest struct {
	Service  string       `json:"service"`
	Language string       `json:"language"`
	Points   []pointEntry `json:"points"`
	Errors   []string     `json:"errors"`
}

type pointEntry struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function"`
	Code     string `json:"code"`
}

// scan writes the hook catalog and the manifest of every configured service under a directory, as hooks/<service>.json
// and manifests/<service>.json; it reads files and kernel lists and attaches nothing.
func scan(directory string) error {
	options, err := scanOptions()
	if err != nil {
		return err
	}
	services, err := options.services()
	if err != nil {
		return err
	}
	for name := range options.Hooks {
		if _, configured := options.Services[name]; !configured {
			return fmt.Errorf("options.%s.hooks selects records of %s, which is not a configured service", optionsName, name)
		}
	}
	hostRoot, err := hostRootMount()
	if err != nil {
		return err
	}
	kernel, err := readKernel()
	if err != nil {
		return err
	}
	for _, name := range []string{hooksDirectory, manifestsDirectory} {
		if err := os.MkdirAll(filepath.Join(directory, name), 0o755); err != nil {
			return err
		}
	}
	for _, configured := range services {
		catalog, err := scanService(configured, options.Hooks[configured.name], kernel, hostRoot)
		if err != nil {
			return fmt.Errorf("service %s: %w", configured.name, err)
		}
		listed := catalogManifest(catalog)
		if err := writeJSON(filepath.Join(directory, hooksDirectory, configured.name+".json"), catalog); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(directory, manifestsDirectory, configured.name+".json"), listed); err != nil {
			return err
		}
		fmt.Printf("%s: %d files, %d refused, %d records, %d selected\n", configured.name, len(catalog.Files),
			len(catalog.Refused), len(catalog.Records), len(listed.Points))
	}
	return nil
}

// scanOptions reads options.ebpf from FAULTPOINT_CONFIG; the core reads no configuration in a process that neither
// injects nor reports, which a scan is.
func scanOptions() (agentOptions, error) {
	data, err := os.ReadFile(os.Getenv(environmentPrefix + "CONFIG"))
	if err != nil {
		return agentOptions{}, fmt.Errorf("a scan reads its services from the file FAULTPOINT_CONFIG names: %w", err)
	}
	var configuration struct {
		Options map[string]json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(data, &configuration); err != nil {
		return agentOptions{}, err
	}
	var options agentOptions
	return options, decodeParams(configuration.Options[optionsName], &options)
}

// scanService reads every file a service's processes map and the kernel's lists into records, and selects them.
func scanService(owner service, options hookOptions, kernel kernelInventory, hostRoot int) (hookCatalog, error) {
	catalog := hookCatalog{Service: owner.name, Upstream: options.Upstream, Kernel: kernel.summary}
	targets, refused, err := openBinaries(owner, hostRoot)
	if err != nil {
		return catalog, err
	}
	catalog.Refused = refused
	fileLayer, kernelLayer := options.layers()
	for _, target := range targets {
		summary, functions, probes, err := readBinary(target, hostRoot)
		if closed := target.file.Close(); err == nil {
			err = closed
		}
		if err != nil {
			return catalog, fmt.Errorf("%s: %w", target.path, err)
		}
		catalog.Files = append(catalog.Files, summary)
		for _, function := range functions {
			catalog.Records = append(catalog.Records, functionRecord(owner.name, fileLayer, target, function))
		}
		for _, probe := range probes {
			catalog.Records = append(catalog.Records, probeRecord(owner.name, fileLayer, target, probe))
		}
	}
	catalog.Records = append(catalog.Records, kernelRecords(owner.name, kernelLayer, kernel)...)
	for index := range catalog.Records {
		catalog.Records[index].Selected = options.selects(catalog.Records[index])
	}
	return catalog, nil
}

// layers are the layers of a service's records in its files and in the kernel: a dependency library and the kernel
// under a business service, and all of an upstream component.
func (options hookOptions) layers() (string, string) {
	if options.Upstream {
		return layerUpstream, layerUpstream
	}
	return layerLibrary, layerKernel
}

// selects is whether a service's hook options select a record, by its key or the key one of its aliases would give.
func (options hookOptions) selects(record hookRecord) bool {
	keys := []string{record.Key}
	object, _, _ := strings.Cut(record.Key, ":")
	for _, alias := range record.Target.Aliases {
		keys = append(keys, object+":"+alias)
	}
	matches := func(prefix string) bool {
		return slices.ContainsFunc(keys, func(key string) bool { return strings.HasPrefix(key, prefix) })
	}
	included := slices.ContainsFunc(options.Scope, func(scope hookScope) bool {
		return matches(scope.Include) && (len(scope.Kinds) == 0 || slices.Contains(scope.Kinds, record.Kind))
	})
	return included && !slices.ContainsFunc(options.Exclude, matches)
}

// functionRecord is a function's record: a bool result makes it a check, which a negate at its returns changes, and any
// other a call, which a fail at its entry changes, unless its result is one the agent cannot write.
func functionRecord(service, layer string, target mappedBinary, function fileFunction) hookRecord {
	kind, inject, actions := kindCall, mechanismUprobeEntry, []string{actionFail, actionCrash}
	var signature *hookSignature
	if function.result != nil {
		result := function.result
		signature = &hookSignature{Source: "dwarf", Text: fmt.Sprintf("%s %s", result.class, function.symbol),
			Returns: result.class, Size: result.size, Results: result.results, Line: result.line}
		switch result.class {
		case classBool:
			kind, inject, actions = kindCheck, mechanismUprobeReturns, []string{actionNegate, actionCrash}
		case classVoid, classFloat, classAggregate:
			actions = []string{actionCrash}
		}
	}
	coverage := &hookCoverage{TailCalls: function.exits.tailCalls, IndirectJumps: function.exits.indirect,
		Undecodable: function.undecodable}
	var clones []hookClone
	for _, clone := range function.clones {
		clones = append(clones, hookClone{Symbol: clone.symbol, Entry: clone.entry, Returns: clone.returns,
			Cold: strings.Contains(strings.TrimPrefix(clone.symbol, function.symbol), ".cold")})
		coverage.TailCalls += clone.exits.tailCalls
		coverage.IndirectJumps += clone.exits.indirect
	}
	file := filepath.Base(target.path)
	return hookRecord{
		ID:  faultpoint.PointID(service, kind, fmt.Sprintf("%s@%s:%s", file, target.build[:buildIDDigits], function.symbol)),
		Key: file + ":" + function.symbol, Kind: kind, Layer: layer, Inject: inject, Observe: mechanismUprobeReturns,
		Target: hookTarget{File: target.path, BuildID: target.build, Symbol: function.symbol, Aliases: function.aliases,
			Entry: function.entry, Returns: function.returns, Clones: clones},
		Signature: signature, Actions: actions, Values: []valueRange{}, Observed: []valueRange{}, Cost: costTrap,
		Traps: trapsInode, Safety: uprobeSafety, Coverage: coverage,
	}
}

// probeRecord is a USDT probe's record, an event at every site of the probe.
func probeRecord(service, layer string, target mappedBinary, probe usdtProbe) hookRecord {
	file, name := filepath.Base(target.path), probe.provider+":"+probe.name
	return hookRecord{
		ID:  faultpoint.PointID(service, kindEvent, fmt.Sprintf("%s@%s:%s", file, target.build[:buildIDDigits], name)),
		Key: file + ":" + name, Kind: kindEvent, Layer: layer, Observe: mechanismUSDT,
		Target: hookTarget{File: target.path, BuildID: target.build, Symbol: name, Locations: probe.locations,
			Semaphore: probe.semaphore, Arguments: probe.arguments},
		Actions: []string{}, Values: []valueRange{}, Observed: []valueRange{}, Cost: costTrap, Traps: trapsInode,
		Safety: usdtSafety,
	}
}

// kernelRecords are the records of the host kernel for one service: its syscalls, the functions whose results a kernel
// mechanism can change, and the tracepoints, each filtered by the service's cgroups.
func kernelRecords(service, layer string, kernel kernelInventory) []hookRecord {
	var records []hookRecord
	for _, syscall := range kernel.syscalls {
		record := hookRecord{ID: faultpoint.PointID(service, kindSyscall, syscall.name), Key: syscall.name,
			Kind: kindSyscall, Layer: layer, Target: hookTarget{File: kernelObject, BuildID: kernel.build,
				Symbol: syscall.entry},
			Actions: []string{actionCrash}, Values: []valueRange{}, Observed: []valueRange{}, Cost: costKernel,
			Traps: trapsHost, Safety: syscallSafety}
		if syscall.exitEvent {
			record.Observe = mechanismSyscallExit
		}
		if syscall.injectable {
			record.Inject, record.Actions = mechanismKprobeOverride, []string{actionFail, actionCrash}
			record.Values = injectionValues(injectErrno)
		}
		records = append(records, record)
	}
	for _, function := range kernel.functions {
		records = append(records, kernelFunctionRecord(service, layer, function))
	}
	for _, event := range kernel.tracepoints {
		records = append(records, tracepointRecord(service, layer, kernel.build, event))
	}
	return records
}

// kernelFunctionRecord is the record of a kernel function whose result an override or fmod_ret can change.
func kernelFunctionRecord(service, layer string, function kernelFunction) hookRecord {
	object := function.symbol.module
	if object == "" {
		object = kernelObject
	}
	record := hookRecord{
		ID: faultpoint.PointID(service, kindCall, fmt.Sprintf("%s@%s:%s", object, function.build[:buildIDDigits],
			function.symbol.name)),
		Key: object + ":" + function.symbol.name, Kind: kindCall, Layer: layer, Inject: function.inject,
		Target:  hookTarget{File: object, BuildID: function.build, Symbol: function.symbol.name},
		Actions: []string{}, Values: append([]valueRange{}, function.values...), Observed: []valueRange{},
		Cost: costKernel, Traps: trapsHost, Safety: kernelSafety,
	}
	if function.signature != "" {
		record.Signature = &hookSignature{Source: "btf", Text: function.signature}
	}
	if function.inject != "" {
		record.Actions = []string{actionFail}
	}
	if function.inject == mechanismFmodRet {
		record.Safety = fmodRetSafety
	}
	if function.traceable {
		record.Observe = mechanismFexit
	}
	return record
}

// tracepointRecord is a kernel tracepoint's record, an event, named group:name as tracefs lists it.
func tracepointRecord(service, layer, build, event string) hookRecord {
	return hookRecord{
		ID:  faultpoint.PointID(service, kindEvent, fmt.Sprintf("%s@%s:%s", kernelObject, build[:buildIDDigits], event)),
		Key: kernelObject + ":" + event, Kind: kindEvent, Layer: layer, Observe: mechanismTracepoint,
		Target:  hookTarget{File: kernelObject, BuildID: build, Symbol: event},
		Actions: []string{}, Values: []valueRange{}, Observed: []valueRange{}, Cost: costKernel, Traps: trapsHost,
	}
}

// catalogManifest lists a catalog's selected records as the points of a manifest.
func catalogManifest(catalog hookCatalog) manifest {
	listed := manifest{Service: catalog.Service, Language: languageNative, Points: []pointEntry{}, Errors: []string{}}
	for _, record := range catalog.Records {
		if !record.Selected {
			continue
		}
		entry := pointEntry{ID: record.ID, Kind: record.Kind, File: record.Target.File, Function: record.Target.Symbol,
			Code: record.Target.Symbol}
		if record.Signature != nil {
			entry.Line, entry.Code = record.Signature.Line, record.Signature.Text
		}
		listed.Points = append(listed.Points, entry)
	}
	return listed
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
