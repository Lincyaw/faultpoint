package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"maps"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/btf"
)

// The kernel's listings are lines of tab- or space-separated fields, which no library reads.
const (
	kallsymsFile         = "/proc/kallsyms"
	errorInjectionFile   = "/sys/kernel/debug/error_injection/list"
	ftraceFunctionsFile  = "/sys/kernel/tracing/available_filter_functions"
	tracepointsFile      = "/sys/kernel/tracing/available_events"
	kernelNotesFile      = "/sys/kernel/notes"
	moduleNotesFile      = "/sys/module/%s/notes/.note.gnu.build-id"
	kernelObject         = "vmlinux"
	errorInjectionPrefix = "_eil_addr_"
	securityPrefix       = "security_"
	lsmHookPrefix        = "bpf_lsm_"
	syscallExitGroup     = "syscalls:" + syscallExitPrefix
	maxErrno             = 4095
)

// errorInjectionType is the EI_ETYPE an ALLOW_ERROR_INJECTION declares, which bounds what bpf_override_return may make
// the function return.
type errorInjectionType string

const (
	injectErrno     errorInjectionType = "ERRNO"
	injectNull      errorInjectionType = "NULL"
	injectErrnoNull errorInjectionType = "ERRNO_NULL"
	injectTrue      errorInjectionType = "TRUE"
)

// Provenances of a record's legal values.
const (
	provenanceErrorInjection = "error_injection"
	provenanceLSM            = "lsm"
)

// syscallWrapperPrefixes begin the entries SYSCALL_DEFINE generates for each ABI, which are syscalls rather than
// kernel functions; this architecture's native entries become syscall records, and the 32-bit ones are not served.
var syscallWrapperPrefixes = []string{"__x64_sys_", "__ia32_sys_", "__ia32_compat_sys_", "__x64_compat_sys_",
	"__arm64_sys_", "__arm64_compat_sys_", "__do_sys_", "__se_sys_"}

// boolLSMHooks are the hooks bpf_lsm_get_retval_range in kernel/bpf/bpf_lsm.c lets return only 0 or 1; every other int
// hook returns 0 or a negative errno.
var boolLSMHooks = []string{"xfrm_state_pol_flow_match", "audit_rule_known", "inode_xattr_skipcap"}

// valueRange is a range of values a record may be made to return, with where the range comes from.
type valueRange struct {
	Min        int64  `json:"min"`
	Max        int64  `json:"max"`
	Provenance string `json:"provenance"`
}

// kernelSymbol is a kernel text symbol, by its name and the module it is in, empty for vmlinux.
type kernelSymbol struct {
	name   string
	module string
}

// kernelFunction is a function of the kernel or of a module whose result a kernel mechanism can change: one on the
// error-injection list, or a security_ function.
type kernelFunction struct {
	symbol    kernelSymbol
	build     string
	inject    string
	traceable bool
	values    []valueRange
	signature string
}

// kernelSyscall is a syscall with an entry function of this architecture.
type kernelSyscall struct {
	name       string
	entry      string
	injectable bool
	exitEvent  bool
}

// kernelSummary is what a catalog reports of the host kernel, in the hook survey's terms so that the two compare: the
// debugfs list's lines and the distinct functions they name, whose types are counted, the _eil_addr_ symbols, and
// the syscall entries kallsyms and BTF have, since BTF omits an entry that is an alias of its __do_sys_ function.
type kernelSummary struct {
	BuildID                  string         `json:"build_id"`
	ErrorInjectionEntries    int            `json:"error_injection_entries"`
	ErrorInjectionFunctions  int            `json:"error_injection_functions"`
	ErrorTypes               map[string]int `json:"error_types"`
	DeclaredErrorInjection   int            `json:"declared_error_injection_symbols"`
	SyscallEntries           int            `json:"syscall_entries"`
	SyscallEntriesInBTF      int            `json:"syscall_entries_in_btf"`
	SyscallEntriesInjectable int            `json:"syscall_entries_injectable"`
	SecurityFunctions        int            `json:"security_functions_in_btf"`
	SecurityTraceable        int            `json:"security_functions_traceable"`
	SecurityWithLSMRange     int            `json:"security_functions_with_lsm_range"`
	Tracepoints              int            `json:"tracepoints"`
}

// kernelInventory is what the host kernel offers to hook: its build, the syscalls, the functions whose results a
// kernel mechanism can change, and the tracepoints.
type kernelInventory struct {
	build       string
	syscalls    []kernelSyscall
	functions   []kernelFunction
	tracepoints []string
	summary     kernelSummary
}

// readKernel reads the host kernel's hook lists: kallsyms, the error-injection list, which it names functions in by the
// _eil_addr_ symbols ALLOW_ERROR_INJECTION declares, since the debugfs list prints the first alias at an address, the
// ftrace function table, the tracepoints and the BTF of vmlinux.
func readKernel() (kernelInventory, error) {
	build, err := kernelBuild()
	if err != nil {
		return kernelInventory{}, err
	}
	addresses, declared, err := readKallsyms()
	if err != nil {
		return kernelInventory{}, err
	}
	types, listed, err := errorInjectionTypes(addresses)
	if err != nil {
		return kernelInventory{}, err
	}
	traceable, err := readLines(ftraceFunctionsFile)
	if err != nil {
		return kernelInventory{}, err
	}
	events, err := readLines(tracepointsFile)
	if err != nil {
		return kernelInventory{}, err
	}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return kernelInventory{}, err
	}
	inventory := kernelInventory{build: build, tracepoints: slices.Sorted(maps.Keys(events)),
		summary: kernelSummary{BuildID: build, ErrorInjectionEntries: listed, ErrorInjectionFunctions: len(types),
			ErrorTypes: map[string]int{}, DeclaredErrorInjection: len(declared), Tracepoints: len(events)}}
	for _, kind := range types {
		inventory.summary.ErrorTypes[string(kind)]++
	}
	functions := map[string]*btf.Func{}
	for typ, err := range spec.All() {
		if err != nil {
			return kernelInventory{}, err
		}
		if function, isFunction := typ.(*btf.Func); isFunction {
			functions[function.Name] = function
		}
	}
	builds := map[string]string{"": build}
	for _, symbol := range slices.SortedFunc(maps.Keys(declared), compareSymbols) {
		address, known := addresses[symbol]
		if !known {
			return kernelInventory{}, fmt.Errorf("%s declares %s for error injection, which kallsyms lacks", kallsymsFile,
				ftraceName(symbol))
		}
		if err := inventory.addDeclared(symbol, types[address], functions, traceable, builds); err != nil {
			return kernelInventory{}, err
		}
	}
	inventory.addSecurity(functions, traceable)
	inventory.addSyscalls(addresses, functions, declared, events)
	return inventory, nil
}

// kernelBuild reads the build-id of the running kernel, which the ids of its points name.
func kernelBuild() (string, error) {
	notes, err := os.ReadFile(kernelNotesFile)
	if err != nil {
		return "", err
	}
	return gnuBuildID(notes, binary.NativeEndian)
}

func compareSymbols(one, other kernelSymbol) int {
	return strings.Compare(one.module+":"+one.name, other.module+":"+other.name)
}

// readKallsyms returns the address of every text symbol and the functions ALLOW_ERROR_INJECTION declared.
func readKallsyms() (map[kernelSymbol]uint64, map[kernelSymbol]bool, error) {
	file, err := os.Open(kallsymsFile)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	addresses := map[kernelSymbol]uint64{}
	declared := map[kernelSymbol]bool{}
	shown := false
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) < 3 {
			return nil, nil, fmt.Errorf("%s has a line without an address, a type and a name: %q", kallsymsFile, lines.Text())
		}
		symbol := kernelSymbol{name: fields[2]}
		if len(fields) > 3 {
			symbol.module = strings.Trim(fields[3], "[]")
		}
		address, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			return nil, nil, err
		}
		shown = shown || address != 0
		switch {
		case strings.HasPrefix(symbol.name, errorInjectionPrefix):
			declared[kernelSymbol{name: strings.TrimPrefix(symbol.name, errorInjectionPrefix), module: symbol.module}] = true
		case strings.ContainsAny(fields[1], "tTwW"):
			if _, seen := addresses[symbol]; !seen {
				addresses[symbol] = address
			}
		}
	}
	if !shown {
		return nil, nil, fmt.Errorf("%s shows no addresses, which the agent needs CAP_SYSLOG to read", kallsymsFile)
	}
	return addresses, declared, lines.Err()
}

// errorInjectionTypes maps the address of each function on the debugfs error-injection list to its type, since the
// list names a function by the first alias at its address; it also returns the list's length.
func errorInjectionTypes(addresses map[kernelSymbol]uint64) (map[uint64]errorInjectionType, int, error) {
	file, err := os.Open(errorInjectionFile)
	if err != nil {
		return nil, 0, fmt.Errorf("reading the error-injection list needs debugfs at /sys/kernel/debug: %w", err)
	}
	defer file.Close()
	types := map[uint64]errorInjectionType{}
	listed := 0
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		named, kind, found := strings.Cut(lines.Text(), "\t")
		if !found {
			return nil, 0, fmt.Errorf("%s has a line without a type: %q", errorInjectionFile, lines.Text())
		}
		name, module, _ := strings.Cut(named, " [")
		symbol := kernelSymbol{name: name, module: strings.TrimSuffix(module, "]")}
		address, known := addresses[symbol]
		if !known {
			return nil, 0, fmt.Errorf("%s names %s, which kallsyms lacks", errorInjectionFile, named)
		}
		types[address] = errorInjectionType(kind)
		listed++
	}
	return types, listed, lines.Err()
}

// readLines returns the lines of a kernel listing as a set.
func readLines(path string) (map[string]bool, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(contents)), "\n") {
		lines[line] = true
	}
	return lines, nil
}

// moduleBuild reads the build-id of a module, which its point ids name as vmlinux's do.
func moduleBuild(module string, builds map[string]string) (string, error) {
	if build, known := builds[module]; known {
		return build, nil
	}
	notes, err := os.ReadFile(fmt.Sprintf(moduleNotesFile, module))
	if err != nil {
		return "", err
	}
	build, err := gnuBuildID(notes, binary.NativeEndian)
	builds[module] = build
	return build, err
}

// addDeclared adds a function on the error-injection list other than a syscall entry, whose legal values its type gives.
func (inventory *kernelInventory) addDeclared(symbol kernelSymbol, kind errorInjectionType, functions map[string]*btf.Func,
	traceable map[string]bool, builds map[string]string) error {
	if slices.ContainsFunc(syscallWrapperPrefixes, func(prefix string) bool { return strings.HasPrefix(symbol.name, prefix) }) {
		return nil
	}
	build, err := moduleBuild(symbol.module, builds)
	if err != nil {
		return err
	}
	function := kernelFunction{symbol: symbol, build: build, inject: mechanismKprobeOverride,
		traceable: traceable[ftraceName(symbol)], values: injectionValues(kind)}
	if declaration, known := functions[symbol.name]; known && symbol.module == "" {
		function.signature = cSignature(declaration)
	}
	inventory.functions = append(inventory.functions, function)
	return nil
}

// ftraceName is how available_filter_functions lists a function.
func ftraceName(symbol kernelSymbol) string {
	if symbol.module == "" {
		return symbol.name
	}
	return symbol.name + " [" + symbol.module + "]"
}

// injectionValues are the values an error-injection type allows.
func injectionValues(kind errorInjectionType) []valueRange {
	provenance := provenanceErrorInjection + ":" + string(kind)
	errno, null := valueRange{Min: -maxErrno, Max: -1, Provenance: provenance}, valueRange{Provenance: provenance}
	switch kind {
	case injectErrno:
		return []valueRange{errno}
	case injectNull:
		return []valueRange{null}
	case injectErrnoNull:
		return []valueRange{errno, null}
	case injectTrue:
		return []valueRange{{Min: 1, Max: 1, Provenance: provenance}}
	}
	return nil
}

// addSecurity adds the security_ functions of vmlinux, which fmod_ret can make return a value of the range the LSM
// hook of the same name has.
func (inventory *kernelInventory) addSecurity(functions map[string]*btf.Func, traceable map[string]bool) {
	for _, name := range slices.Sorted(maps.Keys(functions)) {
		if !strings.HasPrefix(name, securityPrefix) {
			continue
		}
		function := kernelFunction{symbol: kernelSymbol{name: name}, build: inventory.build,
			traceable: traceable[name], signature: cSignature(functions[name])}
		if function.traceable {
			function.inject = mechanismFmodRet
		}
		hook := strings.TrimPrefix(name, securityPrefix)
		if declaration, known := functions[lsmHookPrefix+hook]; known {
			function.values = lsmValues(hook, declaration)
		}
		inventory.summary.SecurityFunctions++
		inventory.summary.SecurityTraceable += boolCount(function.traceable)
		inventory.summary.SecurityWithLSMRange += boolCount(len(function.values) > 0)
		inventory.functions = append(inventory.functions, function)
	}
}

// lsmValues is the range bpf_lsm_get_retval_range gives an LSM hook; a void hook returns nothing.
func lsmValues(hook string, declaration *btf.Func) []valueRange {
	if _, void := declaration.Type.(*btf.FuncProto).Return.(*btf.Void); void {
		return nil
	}
	if slices.Contains(boolLSMHooks, hook) {
		return []valueRange{{Min: 0, Max: 1, Provenance: provenanceLSM}}
	}
	return []valueRange{{Min: -maxErrno, Max: 0, Provenance: provenanceLSM}}
}

// addSyscalls adds the syscalls with an entry function of this architecture in kallsyms; the agent injects at the entry
// when ALLOW_ERROR_INJECTION declares it.
func (inventory *kernelInventory) addSyscalls(addresses map[kernelSymbol]uint64, functions map[string]*btf.Func,
	declared map[kernelSymbol]bool, events map[string]bool) {
	prefix := syscallEntryPrefixes[runtime.GOARCH]
	for _, symbol := range slices.SortedFunc(maps.Keys(addresses), compareSymbols) {
		name, isEntry := strings.CutPrefix(symbol.name, prefix)
		if !isEntry || symbol.module != "" {
			continue
		}
		syscall := kernelSyscall{name: name, entry: symbol.name, injectable: declared[symbol],
			exitEvent: events[syscallExitGroup+name]}
		_, inBTF := functions[symbol.name]
		inventory.summary.SyscallEntries++
		inventory.summary.SyscallEntriesInBTF += boolCount(inBTF)
		inventory.summary.SyscallEntriesInjectable += boolCount(syscall.injectable)
		inventory.syscalls = append(inventory.syscalls, syscall)
	}
}

// cSignature renders a BTF function as a C declaration without qualifiers.
func cSignature(function *btf.Func) string {
	prototype := function.Type.(*btf.FuncProto)
	parameters := make([]string, len(prototype.Params))
	for index, parameter := range prototype.Params {
		parameters[index] = cType(parameter.Type)
	}
	return fmt.Sprintf("%s %s(%s)", cType(prototype.Return), function.Name, strings.Join(parameters, ", "))
}

func cType(typ btf.Type) string {
	switch typed := typ.(type) {
	case *btf.Void:
		return "void"
	case *btf.Pointer:
		return cType(typed.Target) + " *"
	case *btf.Const:
		return cType(typed.Type)
	case *btf.Volatile:
		return cType(typed.Type)
	case *btf.Restrict:
		return cType(typed.Type)
	case *btf.TypeTag:
		return cType(typed.Type)
	case *btf.Array:
		return cType(typed.Type) + "[]"
	case *btf.Struct:
		return "struct " + typed.Name
	case *btf.Union:
		return "union " + typed.Name
	case *btf.Enum:
		return "enum " + typed.Name
	case *btf.Fwd:
		return typed.Kind.String() + " " + typed.Name
	case *btf.FuncProto:
		return "fn"
	}
	return typ.TypeName()
}
