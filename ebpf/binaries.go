package main

import (
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/parca-dev/usdt"
)

const (
	goLineTableSection = ".gopclntab"
	textSection        = ".text"
	stapsdtSection     = ".note.stapsdt"
	symbolTableSection = ".symtab"
	staticSymbols      = "symtab"
	dynamicSymbols     = "dynsym"
	runtimePackage     = "runtime"
)

// cloneName splits a compiler clone's name into the function it copies and the suffix of the copy.
var cloneName = regexp.MustCompile("^(.+?)" + cloneSuffix)

// symbolSuffix finds the suffixes a compiler or linker gives a function's copies and renamed locals, as a catalog
// counts them; only those cloneSuffix names are copies of a function a probe on it must cover.
var symbolSuffix = regexp.MustCompile(`\.(constprop|isra|part|cold|lto_priv|localalias|clone|llvm)(\.\d+)*(\.|$)`)

// mappedBinary is an executable file a process of a service maps, opened in that process's root.
type mappedBinary struct {
	path  string
	pid   string
	file  *os.File
	elf   *elf.File
	build string
}

// refusedFile is a mapped file the scan did not read, with the reason, such as a mount other than the container's root.
type refusedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// binarySummary is what a catalog reports of one file: its build, its symbol tables and debug information, and the
// coverage of its code.
type binarySummary struct {
	Path      string         `json:"path"`
	BuildID   string         `json:"build_id"`
	Symtab    bool           `json:"symtab"`
	Debug     string         `json:"debug,omitempty"`
	Functions functionCounts `json:"functions"`
	Code      codeCounts     `json:"code"`
	Dwarf     *dwarfCounts   `json:"dwarf,omitempty"`
	Go        *goCounts      `json:"go,omitempty"`
	USDT      *usdtCounts    `json:"usdt,omitempty"`
}

// functionCounts count a file's function symbols as the hook survey's enumerate.py does: names, exported ones, entries,
// and the suffixes of copies and renamed locals.
type functionCounts struct {
	Named               int            `json:"named"`
	Exported            int            `json:"exported"`
	LocalOnly           int            `json:"local_only"`
	DistinctEntries     int            `json:"distinct_entries"`
	ZeroSize            int            `json:"zero_size"`
	Suffixes            map[string]int `json:"suffixes"`
	SuffixesWithoutBase int            `json:"suffixes_without_base"`
}

// codeCounts count what decoding the entries found: ret sites, exits by tail call, indirect jumps and conditional
// branches.
type codeCounts struct {
	Entries        int `json:"entries"`
	Undecodable    int `json:"undecodable"`
	RetSites       int `json:"ret_sites"`
	TailCalls      int `json:"tail_calls"`
	IndirectJumps  int `json:"indirect_jumps"`
	Conditionals   int `json:"conditional_branches"`
	WithoutRet     int `json:"entries_without_ret"`
	WithSeveralRet int `json:"entries_with_several_ret"`
}

type goCounts struct {
	Version          string         `json:"version"`
	PclntabFunctions int            `json:"pclntab_functions"`
	ByPackage        map[string]int `json:"by_package"`
}

type usdtCounts struct {
	Sites         int `json:"sites"`
	WithSemaphore int `json:"with_semaphore"`
	Names         int `json:"names"`
}

// functionEntry is an address where a file's code starts, with the names its symbols give it and its size.
type functionEntry struct {
	names []string
	size  uint64
}

// fileFunction is one entry of a file's code with the names it has, its exits and its compiler clones, and what DWARF
// says of it; entry and returns are file offsets, where uprobes are set.
type fileFunction struct {
	symbol      string
	aliases     []string
	entry       uint64
	returns     []uint64
	exits       codeExits
	undecodable string
	clones      []fileFunction
	result      *dwarfResult
}

// usdtProbe is one statically defined probe of a file with every site it has; locations and the semaphore are file
// offsets.
type usdtProbe struct {
	provider  string
	name      string
	locations []uint64
	semaphore uint64
	arguments string
}

// openBinaries opens every executable file the processes of a service map, once per path, in the root of a process
// that maps it; a file the agent refuses to open, or that has no build-id, is listed with the reason.
func openBinaries(owner service, hostRoot int) ([]mappedBinary, []refusedFile, error) {
	mapped := map[string]string{}
	for _, cgroup := range owner.cgroupPaths {
		files, err := mappedFiles(cgroup)
		if err != nil {
			return nil, nil, err
		}
		for path, pid := range files {
			if _, seen := mapped[path]; !seen {
				mapped[path] = pid
			}
		}
	}
	var opened []mappedBinary
	refused := []refusedFile{}
	for _, path := range slices.Sorted(maps.Keys(mapped)) {
		target, err := openBinary(path, mapped[path], hostRoot)
		if err != nil {
			refused = append(refused, refusedFile{Path: path, Reason: err.Error()})
			continue
		}
		opened = append(opened, target)
	}
	return opened, refused, nil
}

func openBinary(path, pid string, hostRoot int) (mappedBinary, error) {
	file, _, err := openInProcessRoot(pid, path, hostRoot)
	if err != nil {
		return mappedBinary{}, err
	}
	parsed, err := elf.NewFile(file)
	if err != nil {
		return mappedBinary{}, errors.Join(err, file.Close())
	}
	build, err := buildID(parsed)
	if err != nil {
		return mappedBinary{}, errors.Join(err, file.Close())
	}
	return mappedBinary{path: path, pid: pid, file: file, elf: parsed, build: build}, nil
}

// readBinary reads a file's hook targets: its function entries with their clones, exits and DWARF results, and its USDT
// probes, with what a catalog reports of the file.
func readBinary(target mappedBinary, hostRoot int) (binarySummary, []fileFunction, []usdtProbe, error) {
	summary := binarySummary{Path: target.path, BuildID: target.build,
		Symtab: target.elf.Section(symbolTableSection) != nil}
	symbols, err := functionSymbols(target.elf)
	if err != nil {
		return summary, nil, nil, err
	}
	summary.Functions = countFunctions(symbols)
	entries := entriesBySymbol(symbols)
	if target.elf.Section(goLineTableSection) != nil {
		if entries, summary.Go, err = goEntries(target); err != nil {
			return summary, nil, nil, err
		}
	}
	files, debug, err := readDwarf(target, hostRoot)
	if err != nil {
		return summary, nil, nil, err
	}
	results := map[uint64]dwarfResult{}
	if files != nil {
		summary.Debug = debug
		var counts dwarfCounts
		if results, counts, err = files.functions(); err != nil {
			return summary, nil, nil, err
		}
		summary.Dwarf = &counts
	}
	functions, err := decodeFunctions(target.elf, entries, results, &summary.Code)
	if err != nil {
		return summary, nil, nil, err
	}
	probes, err := fileProbes(target)
	if len(probes) > 0 {
		summary.USDT = &usdtCounts{Names: len(probes)}
	}
	for _, probe := range probes {
		summary.USDT.Sites += len(probe.locations)
		summary.USDT.WithSemaphore += len(probe.locations) * boolCount(probe.semaphore != 0)
	}
	return summary, functions, probes, err
}

// functionSymbols returns the defined function symbols of a file's static and dynamic tables, by table; a stripped file
// has only dynamic ones.
func functionSymbols(file *elf.File) (map[string][]elf.Symbol, error) {
	tables := map[string][]elf.Symbol{}
	for table, read := range map[string]func() ([]elf.Symbol, error){staticSymbols: file.Symbols,
		dynamicSymbols: file.DynamicSymbols} {
		symbols, err := read()
		if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			return nil, err
		}
		tables[table] = slices.DeleteFunc(symbols, func(symbol elf.Symbol) bool {
			kind := elf.ST_TYPE(symbol.Info)
			return (kind != elf.STT_FUNC && kind != elf.STT_GNU_IFUNC) || symbol.Section == elf.SHN_UNDEF ||
				symbol.Value == 0
		})
	}
	return tables, nil
}

// countFunctions counts function symbols as the hook survey's enumerate.py does, so the two can be compared.
func countFunctions(tables map[string][]elf.Symbol) functionCounts {
	names := map[string]map[string]bool{}
	addresses := map[uint64]bool{}
	counts := functionCounts{Suffixes: map[string]int{}}
	for table, symbols := range tables {
		sizes := map[string]uint64{}
		for _, symbol := range symbols {
			if names[symbol.Name] == nil {
				names[symbol.Name] = map[string]bool{}
			}
			names[symbol.Name][table] = true
			addresses[symbol.Value] = true
			sizes[symbol.Name] = symbol.Size
		}
		for _, size := range sizes {
			counts.ZeroSize += boolCount(size == 0)
		}
	}
	for name, tablesOf := range names {
		counts.Exported += boolCount(tablesOf[dynamicSymbols])
		counts.LocalOnly += boolCount(tablesOf[staticSymbols] && !tablesOf[dynamicSymbols])
		if found := symbolSuffix.FindStringSubmatchIndex(name); found != nil {
			counts.Suffixes[name[found[2]:found[3]]]++
			_, based := names[name[:found[0]]]
			counts.SuffixesWithoutBase += boolCount(!based)
		}
	}
	counts.Named, counts.DistinctEntries = len(names), len(addresses)
	return counts
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

// entriesBySymbol groups a file's function symbols, named as symbolNames names them, by address, leaving out IFUNC
// resolvers, which run once at load; the names of an entry come in the order preferredNames gives.
func entriesBySymbol(tables map[string][]elf.Symbol) map[uint64]functionEntry {
	var functions []elf.Symbol
	for _, symbols := range tables {
		for _, symbol := range symbols {
			if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
				functions = append(functions, symbol)
			}
		}
	}
	entries := map[uint64]functionEntry{}
	for name, symbol := range symbolNames(functions) {
		entry := entries[symbol.Value]
		entries[symbol.Value] = functionEntry{names: append(entry.names, name), size: max(entry.size, symbol.Size)}
	}
	for address, entry := range entries {
		slices.SortFunc(entry.names, preferredNames)
		entries[address] = entry
	}
	return entries
}

// preferredNames orders the names of one entry: a name without a leading underscore first, then the shorter, then by
// order, so that fopen names the entry glibc also calls _IO_fopen.
func preferredNames(name, other string) int {
	public, otherPublic := !strings.HasPrefix(name, "_"), !strings.HasPrefix(other, "_")
	switch {
	case public != otherPublic && public:
		return -1
	case public != otherPublic:
		return 1
	case len(name) != len(other):
		return len(name) - len(other)
	}
	return strings.Compare(name, other)
}

// goEntries lists a Go file's functions from its .gopclntab, which a stripped Go build keeps.
func goEntries(target mappedBinary) (map[uint64]functionEntry, *goCounts, error) {
	data, err := target.elf.Section(goLineTableSection).Data()
	if err != nil {
		return nil, nil, err
	}
	text := target.elf.Section(textSection)
	if text == nil {
		return nil, nil, fmt.Errorf("the Go file has no %s", textSection)
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	if err != nil {
		return nil, nil, err
	}
	information, err := buildinfo.Read(target.file)
	if err != nil {
		return nil, nil, err
	}
	counts := &goCounts{Version: information.GoVersion, PclntabFunctions: len(table.Funcs), ByPackage: map[string]int{}}
	entries := map[uint64]functionEntry{}
	for _, function := range table.Funcs {
		entries[function.Entry] = functionEntry{names: []string{function.Name}, size: function.End - function.Entry}
		counts.ByPackage[goPackageClass(function.PackageName())]++
	}
	return entries, counts, nil
}

// goPackageClass is runtime, std for a package of the standard library, whose first path element has no dot, or module.
func goPackageClass(name string) string {
	first, _, _ := strings.Cut(name, "/")
	switch {
	case name == runtimePackage:
		return runtimePackage
	case !strings.Contains(first, "."):
		return "std"
	}
	return "module"
}

// decodeFunctions decodes every entry and attaches each compiler clone to the function it copies; a clone whose
// function has no symbol of its own stays an entry. An entry that does not decode stays with what it decoded.
func decodeFunctions(file *elf.File, entries map[uint64]functionEntry, results map[uint64]dwarfResult,
	counts *codeCounts) ([]fileFunction, error) {
	addresses := slices.Sorted(maps.Keys(entries))
	named := map[string]uint64{}
	decoded := map[uint64]*fileFunction{}
	for _, address := range addresses {
		function, err := decodeFunction(file, address, entries[address], results, counts)
		if err != nil {
			return nil, err
		}
		named[function.symbol], decoded[address] = address, &function
	}
	cloned := map[uint64]bool{}
	for _, address := range addresses {
		clone := cloneName.FindStringSubmatch(decoded[address].symbol)
		if clone == nil {
			continue
		}
		if base, based := named[clone[1]]; based {
			decoded[base].clones = append(decoded[base].clones, *decoded[address])
			cloned[address] = true
		}
	}
	var functions []fileFunction
	for _, address := range addresses {
		if !cloned[address] {
			functions = append(functions, *decoded[address])
		}
	}
	return functions, nil
}

func decodeFunction(file *elf.File, address uint64, symbols functionEntry, results map[uint64]dwarfResult,
	counts *codeCounts) (fileFunction, error) {
	entry, err := fileOffset(file, address)
	if err != nil {
		return fileFunction{}, err
	}
	function := fileFunction{symbol: symbols.names[0], aliases: symbols.names[1:], entry: entry}
	if result, known := results[address]; known {
		function.result = &result
	}
	counts.Entries++
	code, err := functionCode(file, elf.Symbol{Name: function.symbol, Value: address, Size: symbols.size})
	if err == nil {
		function.exits, err = decodeExits(code)
	}
	if err != nil {
		function.undecodable = err.Error()
		counts.Undecodable++
	}
	for _, offset := range function.exits.returns {
		function.returns = append(function.returns, entry+offset)
	}
	counts.RetSites += len(function.returns)
	counts.TailCalls += function.exits.tailCalls
	counts.IndirectJumps += function.exits.indirect
	counts.Conditionals += function.exits.conditionals
	counts.WithoutRet += boolCount(len(function.returns) == 0)
	counts.WithSeveralRet += boolCount(len(function.returns) > 1)
	return function, nil
}

// fileProbes reads a file's USDT notes, one probe per provider and name with all its sites.
func fileProbes(target mappedBinary) ([]usdtProbe, error) {
	if target.elf.Section(stapsdtSection) == nil {
		return nil, nil
	}
	reader, err := usdt.NewStdlibELFReader(target.file)
	if err != nil {
		return nil, err
	}
	notes, err := usdt.ParseProbes(reader)
	if err != nil {
		return nil, err
	}
	var probes []usdtProbe
	for _, note := range notes {
		index := slices.IndexFunc(probes, func(probe usdtProbe) bool {
			return probe.provider == note.Provider && probe.name == note.Name
		})
		if index < 0 {
			probes = append(probes, usdtProbe{provider: note.Provider, name: note.Name, semaphore: note.SemaphoreOffset,
				arguments: note.Arguments})
			index = len(probes) - 1
		}
		probes[index].locations = append(probes[index].locations, note.Location)
	}
	return probes, nil
}
