package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	gnuNoteName    = "GNU\x00"
	// gnuBuildIDType is NT_GNU_BUILD_ID, a note type debug/elf does not name.
	gnuBuildIDType = 3
	detailValue    = "value"
	// cloneSuffix is what GCC appends to the name of a copy of a function it specializes, splits or moves out of line.
	cloneSuffix = `(\.(constprop|isra|part|cold)(\.\d+)?)+$`
)

var registers = map[string]pointsRegisterName{"ax": pointsRegisterNameAX, "bx": pointsRegisterNameBX,
	"cx": pointsRegisterNameCX, "dx": pointsRegisterNameDX, "si": pointsRegisterNameSI, "di": pointsRegisterNameDI,
	"r8": pointsRegisterNameR8, "r9": pointsRegisterNameR9, "r10": pointsRegisterNameR10, "r11": pointsRegisterNameR11}

// The types a native function's result is read as, and the rules for which result is a failure.
const (
	typeInt32     = "int32"
	typeInt64     = "int64"
	typePointer   = "pointer"
	typeBool      = "bool"
	errorNonzero  = "nonzero"
	errorNegative = "negative"
	errorZero     = "zero"
)

var resultTypes = map[string]pointsResultType{typeInt32: pointsResultTypeINT32, typeInt64: pointsResultTypeINT64,
	typePointer: pointsResultTypePOINTER, typeBool: pointsResultTypeBOOL}

var errorRules = map[string]pointsErrorRule{errorNonzero: pointsErrorRuleNONZERO, errorNegative: pointsErrorRuleNEGATIVE,
	errorZero: pointsErrorRuleZERO}

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

// nativeFunction is a function the agent places a point in: one the functions configuration names, or one generated
// from a selected record of a scan's catalog, whose point id the record gives; negatable is whether a negate is legal,
// which a generated check is once controls observed both its results.
type nativeFunction struct {
	options   functionOptions
	record    string
	negatable bool
}

// nativePoint is a function as the agent found it in its service's containers: an open file for each inode that holds
// it, since a uprobe is set on an inode, and the probe sites, which are alike in every file of one build. A failed call
// with an integer result records the integer as its detail; a pointer's value is an address, unbounded.
type nativePoint struct {
	id          string
	kind        string
	service     uint32
	valued      bool
	negatable   bool
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

// locateFunctions finds each function in the containers of its service, a generated one with the point id of its
// record; the cookies of the points' sites index the sites it returns.
func locateFunctions(functions []nativeFunction, services []service) ([]nativePoint, []pointsNativeSite, error) {
	if len(functions) == 0 {
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
	for _, function := range functions {
		options := function.options
		point, located, err := locateFunction(options, function.negatable, services, hostRoot, uint32(len(points)),
			uint32(len(sites)))
		if err == nil && function.record != "" && point.id != function.record {
			err = fmt.Errorf("the containers hold another build than the catalog's record %s", function.record)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("function %s in %s of service %s: %w", options.Symbol, options.File, options.Service, err)
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
func locateFunction(function functionOptions, negatable bool, services []service, hostRoot int, index,
	firstCookie uint32) (nativePoint, []pointsNativeSite, error) {
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
		entries: entries, returns: returns, negatable: negatable,
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

// buildID reads the GNU build-id note of a file.
func buildID(file *elf.File) (string, error) {
	section := file.Section(buildIDSection)
	if section == nil {
		return "", fmt.Errorf("the file has no %s, so a point id cannot name its build", buildIDSection)
	}
	data, err := section.Data()
	if err != nil {
		return "", err
	}
	return gnuBuildID(data, file.ByteOrder)
}

// gnuBuildID finds the GNU build-id among ELF notes, whose layout debug/elf does not read: a header of name size,
// description size and type, then the name and the description, each padded to four bytes.
func gnuBuildID(notes []byte, order binary.ByteOrder) (string, error) {
	var header struct{ NameSize, DescriptionSize, Type uint32 }
	for reader := bytes.NewReader(notes); reader.Len() > 0; {
		if err := binary.Read(reader, order, &header); err != nil {
			return "", err
		}
		name := make([]byte, (header.NameSize+3)&^3)
		description := make([]byte, (header.DescriptionSize+3)&^3)
		if _, err := io.ReadFull(reader, name); err != nil {
			return "", err
		}
		if _, err := io.ReadFull(reader, description); err != nil {
			return "", err
		}
		if header.Type == gnuBuildIDType && string(name[:header.NameSize]) == gnuNoteName &&
			header.DescriptionSize >= buildIDDigits/2 {
			return hex.EncodeToString(description[:header.DescriptionSize]), nil
		}
	}
	return "", fmt.Errorf("the notes hold no GNU build-id of %d hex digits", buildIDDigits)
}

// symbolTable maps the names of a file's defined symbols, static and dynamic, to their definitions as symbolNames names
// them; a stripped file has only dynamic ones.
func symbolTable(file *elf.File) (map[string]elf.Symbol, error) {
	static, err := file.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	dynamic, err := file.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, err
	}
	return symbolNames(slices.DeleteFunc(append(static, dynamic...), func(symbol elf.Symbol) bool {
		return symbol.Value == 0 || symbol.Section == elf.SHN_UNDEF
	})), nil
}

// symbolNames gives every definition among a file's symbols a name of its own: a version that is not the default one,
// such as glibc's realpath@GLIBC_2.2.5, follows the name after @, and when definitions at several addresses share a
// name, the global one keeps it and the local ones are qualified with their address after #, as dictFind#207360 is
// the copy of hiredis in redis-server.
func symbolNames(symbols []elf.Symbol) map[string]elf.Symbol {
	definitions := map[string][]elf.Symbol{}
	for _, symbol := range symbols {
		name := symbol.Name
		if symbol.HasVersion && symbol.VersionIndex.IsHidden() && symbol.Version != "" {
			name += "@" + symbol.Version
		}
		if !slices.ContainsFunc(definitions[name], func(known elf.Symbol) bool { return known.Value == symbol.Value }) {
			definitions[name] = append(definitions[name], symbol)
		}
	}
	named := map[string]elf.Symbol{}
	for name, defined := range definitions {
		for _, symbol := range defined {
			if len(defined) > 1 && elf.ST_BIND(symbol.Info) == elf.STB_LOCAL {
				named[fmt.Sprintf("%s#%x", name, symbol.Value)] = symbol
				continue
			}
			named[name] = symbol
		}
	}
	return named
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
		exits, err := decodeExits(code)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		for _, offset := range exits.returns {
			found = append(found, foundSite{symbol: name, address: symbol.Value + offset})
		}
		returns += len(exits.returns)
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

// codeExits are what a function's decoded code says of how it ends: the offsets of its ret instructions, the direct
// jumps out of it, which are tail calls whose results no ret probe sees, and its indirect jumps, which may be tail
// calls or jump tables; its conditional branches are the sites a forced branch could use.
type codeExits struct {
	returns      []uint64
	tailCalls    int
	indirect     int
	conditionals int
}

// conditionalJumps are the x86 instructions that branch on a condition.
var conditionalJumps = []x86asm.Op{x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE, x86asm.JCXZ, x86asm.JE, x86asm.JECXZ,
	x86asm.JG, x86asm.JGE, x86asm.JL, x86asm.JLE, x86asm.JNE, x86asm.JNO, x86asm.JNP, x86asm.JNS, x86asm.JO, x86asm.JP,
	x86asm.JRCXZ, x86asm.JS}

// decodeExits decodes a function's code.
func decodeExits(code []byte) (codeExits, error) {
	var exits codeExits
	for offset := 0; offset < len(code); {
		if bytes.HasPrefix(code[offset:], endbr64) {
			offset += len(endbr64)
			continue
		}
		instruction, err := x86asm.Decode(code[offset:], 64)
		if err != nil {
			return exits, fmt.Errorf("cannot decode the instruction at offset %d: %w", offset, err)
		}
		relative, direct := instruction.Args[0].(x86asm.Rel)
		destination := offset + instruction.Len + int(relative)
		switch {
		case instruction.Op == x86asm.RET:
			exits.returns = append(exits.returns, uint64(offset))
		case instruction.Op == x86asm.JMP && !direct:
			exits.indirect++
		case instruction.Op == x86asm.JMP && (destination < 0 || destination >= len(code)):
			exits.tailCalls++
		case slices.Contains(conditionalJumps, instruction.Op):
			exits.conditionals++
		}
		offset += instruction.Len
	}
	return exits, nil
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
