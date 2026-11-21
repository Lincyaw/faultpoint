package main

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
)

const (
	debugBuildIDDirectory      = "/usr/lib/debug/.build-id"
	debugSuffix                = ".debug"
	debugInfoSection           = ".debug_info"
	compressedDebugInfoSection = ".zdebug_info"
	debugStringsSection        = ".debug_str"
	altLinkSection             = ".gnu_debugaltlink"
	inlinedExamples            = 40
	goErrorType                = "error"
	pointerSize                = 8
	// dwarfLanguageGo is DW_LANG_Go, which debug/dwarf does not name.
	dwarfLanguageGo = 0x16
	// dwarfBoolean, dwarfComplexFloat, dwarfFloat and dwarfDecimalFloat are DW_ATE encodings of base types, which
	// debug/dwarf does not name.
	dwarfBoolean      = 0x02
	dwarfComplexFloat = 0x03
	dwarfFloat        = 0x04
	dwarfDecimalFloat = 0x0f
)

// returnClass is the class of a function's result, which decides the values an injection may write and whether its
// point is a call or a check.
type returnClass string

const (
	classInteger   returnClass = "integer"
	classPointer   returnClass = "pointer"
	classBool      returnClass = "bool"
	classEnum      returnClass = "enum"
	classFloat     returnClass = "float"
	classAggregate returnClass = "aggregate"
	classError     returnClass = "error"
	classVoid      returnClass = "void"
	classUnknown   returnClass = "unknown"
)

// dwarfCounts count which source functions have an entry a uprobe can use and which exist only inlined, in the hook
// survey's terms so that the two compare.
type dwarfCounts struct {
	FunctionsWithEntry  int                 `json:"functions_with_entry"`
	Returns             map[returnClass]int `json:"returns_of_functions_with_entry"`
	InlinedSomewhere    int                 `json:"functions_inlined_somewhere"`
	OnlyInlined         int                 `json:"functions_only_inlined"`
	InlinedAndOutOfLine int                 `json:"functions_inlined_and_out_of_line"`
	InlinedCallSites    int                 `json:"inlined_call_sites"`
	ExamplesOnlyInlined []string            `json:"examples_only_inlined"`
}

// dwarfResult is what DWARF says of a function with an entry: the class and size of its result, the classes of a Go
// function's results, and the line it is declared on.
type dwarfResult struct {
	class   returnClass
	size    int64
	results []returnClass
	line    int
}

// dwarfDIE is an entry of a file's DWARF or of its dwz supplement, where shared entries move.
type dwarfDIE struct {
	alt   bool
	entry *dwarf.Entry
}

// dwarfReference is where an entry is: its offset in the file's DWARF or in the supplement.
type dwarfReference struct {
	alt    bool
	offset dwarf.Offset
}

// dwarfFiles are a file's DWARF and its dwz supplement with the supplement's strings.
type dwarfFiles struct {
	main       *dwarf.Data
	alt        *dwarf.Data
	altStrings []byte
}

// readDwarf reads a file's DWARF from the file itself, or from the debug file its build-id names in the same container,
// with the dwz supplement that one links to; it returns where it read it, and nothing when neither has DWARF.
func readDwarf(target mappedBinary, hostRoot int) (*dwarfFiles, string, error) {
	if target.elf.Section(debugInfoSection) != nil || target.elf.Section(compressedDebugInfoSection) != nil {
		main, err := target.elf.DWARF()
		return &dwarfFiles{main: main}, target.path, err
	}
	debugPath := fmt.Sprintf("%s/%s/%s%s", debugBuildIDDirectory, target.build[:2], target.build[2:], debugSuffix)
	main, link, _, err := readDebugFile(target.pid, debugPath, hostRoot)
	if main == nil || err != nil {
		return nil, "", err
	}
	files := &dwarfFiles{main: main}
	if link == "" {
		return files, debugPath, nil
	}
	if !path.IsAbs(link) {
		link = path.Join(path.Dir(debugPath), link)
	}
	files.alt, _, files.altStrings, err = readDebugFile(target.pid, link, hostRoot)
	if files.alt == nil || err != nil {
		return nil, "", errors.Join(fmt.Errorf("%s links to the dwz file %s, which the container lacks", debugPath, link), err)
	}
	return files, debugPath, nil
}

// readDebugFile reads the DWARF of a debug file in a container, the path of the dwz supplement it links to, and its
// strings, which a file linking to it may name; nothing when the container has no such file.
func readDebugFile(pid, path string, hostRoot int) (*dwarf.Data, string, []byte, error) {
	file, _, err := openInProcessRoot(pid, path, hostRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil, nil
	}
	if err != nil {
		return nil, "", nil, err
	}
	defer file.Close()
	debug, err := elf.NewFile(file)
	if err != nil {
		return nil, "", nil, err
	}
	data, err := debug.DWARF()
	if err != nil {
		return nil, "", nil, err
	}
	var linked, stringTable []byte
	if section := debug.Section(altLinkSection); section != nil {
		contents, err := section.Data()
		if err != nil {
			return nil, "", nil, err
		}
		linked, _, _ = bytes.Cut(contents, []byte{0})
	}
	if section := debug.Section(debugStringsSection); section != nil {
		stringTable, err = section.Data()
	}
	return data, string(linked), stringTable, err
}

// functions walks a file's DWARF: the result of every function with an entry, keyed by its address, and the counts
// of functions that have an entry, exist only inlined, or both. A function's identity is the abstract entry its
// concrete and inlined copies refer to, or its own entry; a Go function's results follow it as its parameters that
// are variable parameters.
func (files dwarfFiles) functions() (map[uint64]dwarfResult, dwarfCounts, error) {
	concrete := map[dwarfReference]returnClass{}
	inlined := map[dwarfReference]int{}
	results := map[uint64]dwarfResult{}
	reader := files.main.Reader()
	goUnit, depth, goDepth, goAddress, goKey := false, 0, -1, uint64(0), dwarfReference{}
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, dwarfCounts{}, err
		}
		if entry == nil {
			break
		}
		if entry.Tag == 0 {
			depth--
			continue
		}
		if depth <= goDepth {
			goDepth = -1
		}
		key, hasOrigin := files.reference(dwarfDIE{entry: entry}, dwarf.AttrAbstractOrigin, dwarf.AttrSpecification)
		if !hasOrigin {
			key = dwarfReference{offset: entry.Offset}
		}
		switch entry.Tag {
		case dwarf.TagCompileUnit, dwarf.TagPartialUnit:
			language, _ := entry.Val(dwarf.AttrLanguage).(int64)
			goUnit = language == dwarfLanguageGo
		case dwarf.TagSubprogram:
			address, hasCode, err := files.entryAddress(entry)
			if err != nil {
				return nil, dwarfCounts{}, err
			}
			if !hasCode {
				break
			}
			result, err := files.result(dwarfDIE{entry: entry}, goUnit)
			if err != nil {
				return nil, dwarfCounts{}, err
			}
			if _, seen := concrete[key]; !seen {
				concrete[key] = result.class
			}
			results[address] = result
			if goUnit {
				goDepth, goAddress, goKey = depth, address, key
			}
		case dwarf.TagInlinedSubroutine:
			if hasOrigin {
				inlined[key]++
			}
		case dwarf.TagFormalParameter:
			if parameter, _ := entry.Val(dwarf.AttrVarParam).(bool); parameter && goDepth >= 0 && depth == goDepth+1 {
				class, _, err := files.typeClass(dwarfDIE{entry: entry}, true)
				if err != nil {
					return nil, dwarfCounts{}, err
				}
				result := results[goAddress]
				result.results, result.class = append(result.results, class), class
				results[goAddress], concrete[goKey] = result, class
			}
		}
		if entry.Children {
			depth++
		}
	}
	counts, err := files.count(concrete, inlined)
	return results, counts, err
}

// count counts the functions with an entry by the class of their result, and the inlined ones, naming some of those
// only inlined.
func (files dwarfFiles) count(concrete map[dwarfReference]returnClass, inlined map[dwarfReference]int) (dwarfCounts, error) {
	counts := dwarfCounts{FunctionsWithEntry: len(concrete), Returns: map[returnClass]int{},
		InlinedSomewhere: len(inlined)}
	for _, class := range concrete {
		counts.Returns[class]++
	}
	var onlyInlined []string
	for key, sites := range inlined {
		counts.InlinedCallSites += sites
		if _, out := concrete[key]; out {
			counts.InlinedAndOutOfLine++
			continue
		}
		counts.OnlyInlined++
		die, err := files.entry(key.alt, key.offset)
		if err != nil {
			return dwarfCounts{}, err
		}
		if name := files.name(die); name != "" {
			onlyInlined = append(onlyInlined, name)
		}
	}
	slices.Sort(onlyInlined)
	unique := slices.Compact(onlyInlined)
	counts.ExamplesOnlyInlined = unique[:min(inlinedExamples, len(unique))]
	return counts, nil
}

// entryAddress is where a function with code starts: its low pc, or the start of its first range when its code is
// split, as a function with a cold part is.
func (files dwarfFiles) entryAddress(entry *dwarf.Entry) (uint64, bool, error) {
	if low, has := entry.Val(dwarf.AttrLowpc).(uint64); has {
		return low, true, nil
	}
	if entry.AttrField(dwarf.AttrRanges) == nil {
		return 0, false, nil
	}
	ranges, err := files.main.Ranges(entry)
	if err != nil || len(ranges) == 0 {
		return 0, false, err
	}
	return ranges[0][0], true, nil
}

// reference reads the first of the given reference attributes an entry has, which points into the supplement when it
// is an alternate reference, or when the entry itself is in the supplement.
func (files dwarfFiles) reference(die dwarfDIE, attributes ...dwarf.Attr) (dwarfReference, bool) {
	for _, attribute := range attributes {
		field := die.entry.AttrField(attribute)
		switch {
		case field == nil:
		case field.Class == dwarf.ClassReference:
			return dwarfReference{alt: die.alt, offset: field.Val.(dwarf.Offset)}, true
		case field.Class == dwarf.ClassReferenceAlt:
			return dwarfReference{alt: true, offset: dwarf.Offset(field.Val.(int64))}, true
		}
	}
	return dwarfReference{}, false
}

func (files dwarfFiles) entry(alt bool, offset dwarf.Offset) (dwarfDIE, error) {
	data := files.main
	if alt {
		data = files.alt
	}
	if data == nil {
		return dwarfDIE{}, errors.New("DWARF refers to a dwz supplement the file does not link to")
	}
	reader := data.Reader()
	reader.Seek(offset)
	entry, err := reader.Next()
	if err == nil && entry == nil {
		err = fmt.Errorf("no DWARF entry at %#x", offset)
	}
	return dwarfDIE{alt: alt, entry: entry}, err
}

// follow returns the entry a reference attribute of an entry points to.
func (files dwarfFiles) follow(die dwarfDIE, attributes ...dwarf.Attr) (dwarfDIE, bool, error) {
	target, found := files.reference(die, attributes...)
	if !found {
		return dwarfDIE{}, false, nil
	}
	followed, err := files.entry(target.alt, target.offset)
	return followed, true, err
}

// name is an entry's name, which dwz may have moved into the supplement's strings.
func (files dwarfFiles) name(die dwarfDIE) string {
	field := die.entry.AttrField(dwarf.AttrName)
	switch {
	case field == nil:
		return ""
	case field.Class == dwarf.ClassStringAlt && int(field.Val.(int64)) < len(files.altStrings):
		text, _, _ := bytes.Cut(files.altStrings[field.Val.(int64):], []byte{0})
		return string(text)
	}
	text, _ := field.Val.(string)
	return text
}

// result is what DWARF says of a function's result: a C function's return type, found on the function or on the
// declaration or abstract function it refers to, and its declared line; the walk adds a Go function's results.
func (files dwarfFiles) result(die dwarfDIE, goFunction bool) (dwarfResult, error) {
	line, _ := die.entry.Val(dwarf.AttrDeclLine).(int64)
	for die.entry.AttrField(dwarf.AttrType) == nil && !goFunction {
		origin, found, err := files.follow(die, dwarf.AttrAbstractOrigin, dwarf.AttrSpecification)
		if err != nil || !found {
			return dwarfResult{class: classVoid, line: int(line)}, err
		}
		die = origin
		if declared, has := die.entry.Val(dwarf.AttrDeclLine).(int64); has && line == 0 {
			line = declared
		}
	}
	if goFunction {
		return dwarfResult{class: classVoid, line: int(line)}, nil
	}
	class, size, err := files.typeClass(die, false)
	return dwarfResult{class: class, size: size, line: int(line)}, err
}

// typeClass classifies the type an entry has, through typedefs and qualifiers; Go's error is an interface named error.
func (files dwarfFiles) typeClass(die dwarfDIE, goType bool) (returnClass, int64, error) {
	typed, found, err := files.follow(die, dwarf.AttrType)
	if err != nil || !found {
		return classVoid, 0, err
	}
	for {
		size, _ := typed.entry.Val(dwarf.AttrByteSize).(int64)
		if goType && files.name(typed) == goErrorType {
			return classError, size, nil
		}
		switch typed.entry.Tag {
		case dwarf.TagPointerType, dwarf.TagReferenceType, dwarf.TagRvalueReferenceType:
			return classPointer, pointerSize, nil
		case dwarf.TagEnumerationType:
			return classEnum, size, nil
		case dwarf.TagStructType, dwarf.TagUnionType, dwarf.TagClassType:
			return classAggregate, size, nil
		case dwarf.TagBaseType:
			encoding, _ := typed.entry.Val(dwarf.AttrEncoding).(int64)
			switch encoding {
			case dwarfBoolean:
				return classBool, size, nil
			case dwarfFloat, dwarfComplexFloat, dwarfDecimalFloat:
				return classFloat, size, nil
			}
			return classInteger, size, nil
		}
		next, found, err := files.follow(typed, dwarf.AttrType)
		if err != nil || !found {
			return classUnknown, 0, err
		}
		typed = next
	}
}
