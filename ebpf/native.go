package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"faultpoint"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/arch/x86/x86asm"
)

const (
	kindCall       = "call"
	kindCheck      = "check"
	outcomeError   = "error"
	outcomeTrue    = "true"
	outcomeFalse   = "false"
	buildIDSection = ".note.gnu.build-id"
	buildIDDigits  = 12
	detailValue    = "value"
	// cloneSuffix is what GCC appends to the name of a copy of a function it specializes, splits or moves out of line.
	cloneSuffix = `(\.(constprop|isra|part|cold)(\.\d+)?)+$`
)

var registers = map[string]pointsRegisterName{"ax": pointsRegisterNameAX, "bx": pointsRegisterNameBX,
	"cx": pointsRegisterNameCX, "dx": pointsRegisterNameDX, "si": pointsRegisterNameSI, "di": pointsRegisterNameDI,
	"r8": pointsRegisterNameR8, "r9": pointsRegisterNameR9, "r10": pointsRegisterNameR10, "r11": pointsRegisterNameR11}

var resultTypes = map[string]pointsResultType{"int32": pointsResultTypeINT32, "int64": pointsResultTypeINT64,
	"pointer": pointsResultTypePOINTER, "bool": pointsResultTypeBOOL}

var errorRules = map[string]pointsErrorRule{"nonzero": pointsErrorRuleNONZERO, "negative": pointsErrorRuleNEGATIVE,
	"zero": pointsErrorRuleZERO}

// nativeLocator is the shape of a native point's locator, <file name>@<build-id prefix>:<symbol>.
var nativeLocator = regexp.MustCompile(`^[^/:@]+@[0-9a-f]{12}:.`)

// endbr64 begins every indirect branch target of a CET build, and x86asm does not decode it.
var endbr64 = []byte{0xf3, 0x0f, 0x1e, 0xfa}

// functionOptions configure a native function point of a service: the file in the service's containers that holds the
// function, how its result is read, the errors a fail rule may name, and the predicate on argument registers under
// which its entry injects. Clones maps a compiler clone of the function to its own options, or to null to only
// observe it.
type functionOptions struct {
	Service   string                    `json:"service"`
	File      string                    `json:"file"`
	Symbol    string                    `json:"symbol"`
	Kind      string                    `json:"kind"`
	Result    resultOptions             `json:"result"`
	Errors    map[string][]injectedWord `json:"errors"`
	Predicate *predicateOptions         `json:"predicate"`
	Clones    map[string]*cloneOptions  `json:"clones"`
}

// resultOptions give the registers of a function's result in order, and how the outcome register is read: as an int32,
// int64 or pointer that fails when it is nonzero, negative or zero, or as a bool in its low byte.
type resultOptions struct {
	Registers []string `json:"registers"`
	Outcome   string   `json:"outcome"`
	Type      string   `json:"type"`
	Error     string   `json:"error"`
}

// predicateOptions hold at an entry where the register's value masked by mask equals equals.
type predicateOptions struct {
	Register string `json:"register"`
	Mask     uint64 `json:"mask"`
	Equals   uint64 `json:"equals"`
}

// cloneOptions give a clone its own predicate, since a clone's arguments differ from the function's.
type cloneOptions struct {
	Predicate *predicateOptions `json:"predicate"`
}

// injectedWord is a constant, or the word at a symbol of the file plus an offset in the process's memory, such as a
// word of a Go error variable.
type injectedWord struct {
	Constant int64  `json:"constant"`
	Symbol   string `json:"symbol"`
	Offset   uint64 `json:"offset"`
}

// nativePoint is a configured function as the agent found it in its service's containers: an open file for each inode
// that holds it, since a uprobe is set on an inode, and the probe sites, which are alike in every file of one build. A
// failed call with an integer result records the integer as its detail; a pointer's value is an address, unbounded.
type nativePoint struct {
	id          string
	kind        string
	service     uint32
	valued      bool
	errors      map[string][]pointsNativeWrite
	files       []*os.File
	executables []*link.Executable
	entries     []probeSite
	returns     []probeSite
}

// probeSite is an instruction a native program is attached to, at an offset of the file; its cookie indexes
// native_sites.
type probeSite struct {
	symbol string
	offset uint64
	cookie uint32
}

// foundSite is a function's entry, with the predicate under which it injects, or one of its returns.
type foundSite struct {
	symbol    string
	address   uint64
	entry     bool
	predicate *predicateOptions
}

// locateFunctions finds each configured function in the containers of its service; the cookies of the points' sites
// index the sites it returns.
func locateFunctions(configured []functionOptions, services []service) ([]nativePoint, []pointsNativeSite, error) {
	if len(configured) == 0 {
		return nil, nil, nil
	}
	if runtime.GOARCH != "amd64" {
		return nil, nil, fmt.Errorf("native function points read x86-64 code and registers, not %s", runtime.GOARCH)
	}
	hostRoot, err := hostRootMount()
	if err != nil {
		return nil, nil, err
	}
	var points []nativePoint
	var sites []pointsNativeSite
	for _, function := range configured {
		point, located, err := locateFunction(function, services, hostRoot, uint32(len(points)), uint32(len(sites)))
		if err != nil {
			return nil, nil, fmt.Errorf("function %s in %s of service %s: %w", function.Symbol, function.File, function.Service, err)
		}
		if slices.ContainsFunc(points, func(other nativePoint) bool { return other.id == point.id }) {
			return nil, nil, fmt.Errorf("point %s is configured twice", point.id)
		}
		points, sites = append(points, point), append(sites, located...)
	}
	return points, sites, nil
}

// locateFunction opens the function's file in each container of its service, once per inode, and lays out its sites
// from the code of one of them, since all are one build.
func locateFunction(function functionOptions, services []service, hostRoot int, index, firstCookie uint32) (nativePoint, []pointsNativeSite, error) {
	owner := slices.IndexFunc(services, func(s service) bool { return s.name == function.Service })
	if owner < 0 || len(services[owner].cgroupPaths) == 0 {
		return nativePoint{}, nil, errors.New("the service is not configured with a cgroup to find the file in")
	}
	if err := function.validate(); err != nil {
		return nativePoint{}, nil, err
	}
	files, err := openContainerFiles(services[owner], function.File, hostRoot)
	if err != nil {
		return nativePoint{}, nil, err
	}
	parsed, build, executables, err := readBuild(files)
	if err != nil {
		return nativePoint{}, nil, err
	}
	symbols, err := symbolTable(parsed)
	if err != nil {
		return nativePoint{}, nil, err
	}
	found, err := functionSites(parsed, symbols, function)
	if err != nil {
		return nativePoint{}, nil, err
	}
	injected, err := injectedWrites(function, symbols)
	if err != nil {
		return nativePoint{}, nil, err
	}
	var entries, returns []probeSite
	sites := make([]pointsNativeSite, 0, len(found))
	for _, site := range found {
		offset, err := fileOffset(parsed, site.address)
		if err != nil {
			return nativePoint{}, nil, err
		}
		probe := probeSite{symbol: site.symbol, offset: offset, cookie: firstCookie + uint32(len(sites))}
		if site.entry {
			entries = append(entries, probe)
		} else {
			returns = append(returns, probe)
		}
		sites = append(sites, kernelSite(function, index, services[owner].index, site))
	}
	return nativePoint{
		id: faultpoint.PointID(function.Service, function.Kind,
			fmt.Sprintf("%s@%s:%s", filepath.Base(function.File), build[:buildIDDigits], function.Symbol)),
		kind: function.Kind, service: services[owner].index, errors: injected, files: files, executables: executables,
		entries: entries, returns: returns,
		valued: function.Kind == kindCall && resultTypes[function.Result.Type] != pointsResultTypePOINTER,
	}, sites, nil
}

// readBuild parses the files of a function, which must be one build of x86-64 code, and opens each for uprobes
// through the agent's descriptor, so that the kernel resolves no path again.
func readBuild(files []*os.File) (*elf.File, string, []*link.Executable, error) {
	var parsed *elf.File
	var build string
	var executables []*link.Executable
	for _, file := range files {
		candidate, err := elf.NewFile(file)
		if err != nil {
			return nil, "", nil, err
		}
		id, err := buildID(candidate)
		if err != nil {
			return nil, "", nil, err
		}
		if parsed != nil && id != build {
			return nil, "", nil, fmt.Errorf("the service's containers hold different builds of the file: %s and %s", build, id)
		}
		if candidate.Machine != elf.EM_X86_64 {
			return nil, "", nil, fmt.Errorf("the file is for %s, not x86-64", candidate.Machine)
		}
		executable, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
		if err != nil {
			return nil, "", nil, err
		}
		parsed, build, executables = candidate, id, append(executables, executable)
	}
	return parsed, build, executables, nil
}

// validate checks what the kernel programs rely on: known registers, a classification that fits the kind, and errors
// that give a word for each result register.
func (function functionOptions) validate() error {
	result := function.Result
	resultType, typed := resultTypes[result.Type]
	_, ruled := errorRules[result.Error]
	switch {
	case !filepath.IsAbs(function.File) || function.Symbol == "":
		return errors.New("a function has an absolute file path and a symbol")
	case function.Kind != kindCall && function.Kind != kindCheck:
		return fmt.Errorf("a native function is a %s or a %s point, not %q", kindCall, kindCheck, function.Kind)
	case len(result.Registers) == 0 || len(result.Registers) > len(pointsNativeRule{}.Write) ||
		!slices.Contains(result.Registers, result.Outcome):
		return fmt.Errorf("a result has 1 to %d registers, the outcome register among them: %+v",
			len(pointsNativeRule{}.Write), result)
	case !typed || (function.Kind == kindCheck) != (resultType == pointsResultTypeBOOL) || (function.Kind == kindCall) != ruled:
		return fmt.Errorf("a call's result is an int32, int64 or pointer whose error is nonzero, negative or zero, and a check's is a bool: %+v", result)
	}
	named := slices.Clone(result.Registers)
	for _, clone := range function.Clones {
		if clone != nil && clone.Predicate != nil {
			named = append(named, clone.Predicate.Register)
		}
	}
	if function.Predicate != nil {
		named = append(named, function.Predicate.Register)
	}
	for _, name := range named {
		if _, known := registers[name]; !known {
			return fmt.Errorf("the registers are ax, bx, cx, dx, si, di, r8, r9, r10 and r11, not %q", name)
		}
	}
	for name, words := range function.Errors {
		if len(words) != len(result.Registers) || slices.ContainsFunc(words, func(word injectedWord) bool {
			return word.Symbol != "" && word.Constant != 0
		}) {
			return fmt.Errorf("error %s gives each result register a constant or a symbol's word: %+v", name, words)
		}
	}
	return nil
}

// buildID reads the GNU build-id note, whose layout debug/elf does not read.
func buildID(file *elf.File) (string, error) {
	section := file.Section(buildIDSection)
	if section == nil {
		return "", fmt.Errorf("the file has no %s, so a point id cannot name its build", buildIDSection)
	}
	data, err := section.Data()
	if err != nil {
		return "", err
	}
	var header struct{ NameSize, DescriptionSize, Type uint32 }
	if err := binary.Read(bytes.NewReader(data), file.ByteOrder, &header); err != nil {
		return "", err
	}
	start := uint64(binary.Size(header)) + uint64(header.NameSize+3)&^3
	end := start + uint64(header.DescriptionSize)
	if header.DescriptionSize < buildIDDigits/2 || end > uint64(len(data)) {
		return "", fmt.Errorf("the file's %s holds no build-id of %d hex digits", buildIDSection, buildIDDigits)
	}
	return hex.EncodeToString(data[start:end]), nil
}

// symbolTable maps the names of a file's symbols, static and dynamic, to their first definition; a stripped file has
// only dynamic ones.
func symbolTable(file *elf.File) (map[string]elf.Symbol, error) {
	static, err := file.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	dynamic, err := file.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	table := map[string]elf.Symbol{}
	for _, symbol := range append(static, dynamic...) {
		if _, seen := table[symbol.Name]; !seen && symbol.Value != 0 {
			table[symbol.Name] = symbol
		}
	}
	return table, nil
}

// functionSites finds a function and its compiler clones in a file: the entry of each that is called, which a clone
// moved out of line (.cold) is not, and every ret instruction. A function without a ret cannot be observed.
func functionSites(file *elf.File, symbols map[string]elf.Symbol, function functionOptions) ([]foundSite, error) {
	clone := regexp.MustCompile("^" + regexp.QuoteMeta(function.Symbol) + cloneSuffix)
	names := []string{function.Symbol}
	for name := range symbols {
		if clone.MatchString(name) {
			names = append(names, name)
		}
	}
	slices.Sort(names[1:])
	var found []foundSite
	var unguarded []string
	returns := 0
	for _, name := range names {
		symbol, known := symbols[name]
		if !known {
			return nil, errors.New("the file has no such symbol")
		}
		code, err := functionCode(file, symbol)
		if err != nil {
			return nil, err
		}
		options, listed := function.Clones[name]
		switch {
		case strings.Contains(strings.TrimPrefix(name, function.Symbol), ".cold"), listed && options == nil:
		case listed:
			found = append(found, foundSite{symbol: name, address: symbol.Value, entry: true, predicate: options.Predicate})
		case name != function.Symbol && function.Predicate != nil:
			unguarded = append(unguarded, name)
		default:
			found = append(found, foundSite{symbol: name, address: symbol.Value, entry: true, predicate: function.Predicate})
		}
		offsets, err := returnOffsets(code)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		for _, offset := range offsets {
			found = append(found, foundSite{symbol: name, address: symbol.Value + offset})
		}
		returns += len(offsets)
	}
	for name := range function.Clones {
		if !slices.Contains(names[1:], name) {
			return nil, fmt.Errorf("the file has no clone %s; its clones are %v", name, names[1:])
		}
	}
	if len(unguarded) > 0 {
		return nil, fmt.Errorf("the function injects under a predicate on its arguments, which its clones %v do not take; "+
			"give each under clones a predicate of its own, {} to inject without one, or null to only observe it", unguarded)
	}
	if returns == 0 {
		return nil, errors.New("the function and its clones have no ret instruction, so their results cannot be observed")
	}
	return found, nil
}

// functionCode returns a function's bytes from the executable section that holds them.
func functionCode(file *elf.File, symbol elf.Symbol) ([]byte, error) {
	for _, section := range file.Sections {
		if section.Flags&elf.SHF_EXECINSTR != 0 && symbol.Size > 0 && section.Addr <= symbol.Value &&
			symbol.Value+symbol.Size <= section.Addr+section.Size {
			code := make([]byte, symbol.Size)
			_, err := section.ReadAt(code, int64(symbol.Value-section.Addr))
			return code, err
		}
	}
	return nil, fmt.Errorf("the bytes of %s, %d at %#x, are in no executable section", symbol.Name, symbol.Size, symbol.Value)
}

// returnOffsets decodes a function and returns the offsets of its ret instructions.
func returnOffsets(code []byte) ([]uint64, error) {
	var offsets []uint64
	for offset := 0; offset < len(code); {
		if bytes.HasPrefix(code[offset:], endbr64) {
			offset += len(endbr64)
			continue
		}
		instruction, err := x86asm.Decode(code[offset:], 64)
		if err != nil {
			return nil, fmt.Errorf("cannot decode the instruction at offset %d: %w", offset, err)
		}
		if instruction.Op == x86asm.RET {
			offsets = append(offsets, uint64(offset))
		}
		offset += instruction.Len
	}
	return offsets, nil
}

// fileOffset converts the link-time address of an instruction into its offset in the file, where a uprobe is set.
func fileOffset(file *elf.File, address uint64) (uint64, error) {
	for _, segment := range file.Progs {
		if segment.Type == elf.PT_LOAD && segment.Flags&elf.PF_X != 0 && segment.Vaddr <= address &&
			address < segment.Vaddr+segment.Filesz {
			return address - segment.Vaddr + segment.Off, nil
		}
	}
	return 0, fmt.Errorf("no executable segment of the file holds %#x", address)
}

// injectedWrites resolves the words of each error a fail rule may name; a symbol's word is read at its link-time
// address plus the load bias of the file in the process.
func injectedWrites(function functionOptions, symbols map[string]elf.Symbol) (map[string][]pointsNativeWrite, error) {
	resolved := map[string][]pointsNativeWrite{}
	for name, words := range function.Errors {
		for index, word := range words {
			write := pointsNativeWrite{Target: registers[function.Result.Registers[index]], Value: uint64(word.Constant)}
			if word.Symbol != "" {
				symbol, known := symbols[word.Symbol]
				if !known {
					return nil, fmt.Errorf("error %s reads symbol %s, which the file does not have", name, word.Symbol)
				}
				write.FromMemory, write.Value = 1, symbol.Value+word.Offset
			}
			resolved[name] = append(resolved[name], write)
		}
	}
	return resolved, nil
}

// kernelSite is what the kernel programs read of a site: its point and service, how the point's result is classified,
// its address and, for an entry, its predicate.
func kernelSite(function functionOptions, point, service uint32, site foundSite) pointsNativeSite {
	result := function.Result
	translated := pointsNativeSite{Point: point, Service: service, Address: site.address,
		Outcome: registers[result.Outcome], Type: resultTypes[result.Type], Error: errorRules[result.Error]}
	if site.predicate != nil {
		translated.Conditional, translated.Condition = 1, registers[site.predicate.Register]
		translated.Mask, translated.Equals = site.predicate.Mask, site.predicate.Equals
	}
	return translated
}

// attachSites attaches a program at the given sites of every file of a native point; it returns what it attached
// before an error too, so that the caller detaches it.
func attachSites(point nativePoint, sites []probeSite, program *ebpf.Program) ([]link.Link, error) {
	var attached []link.Link
	for _, executable := range point.executables {
		for _, site := range sites {
			probe, err := executable.Uprobe(site.symbol, program,
				&link.UprobeOptions{Address: site.offset, Cookie: uint64(site.cookie)})
			if err != nil {
				return attached, fmt.Errorf("probing %s at %#x for %s: %w", site.symbol, site.offset, point.id, err)
			}
			attached = append(attached, probe)
		}
	}
	return attached, nil
}

// outcome names a native point's outcome as its kind does.
func (point nativePoint) outcome(flagged uint16) string {
	switch {
	case point.kind == kindCheck && flagged != 0:
		return outcomeTrue
	case point.kind == kindCheck:
		return outcomeFalse
	case flagged != 0:
		return outcomeError
	}
	return outcomeOK
}
