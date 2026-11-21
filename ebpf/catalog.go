package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"faultpoint"
)

const (
	mergeCommand       = "merge"
	provenanceObserved = "observed"
	// resultRegister is where a C function returns an integer, a pointer or a bool.
	resultRegister = "ax"
	nullError      = "NULL"
)

// selectedRecord is a record of a scan's catalog that the configuration selects, with the service it belongs to and
// the include that selects it.
type selectedRecord struct {
	record hookRecord
	owner  service
	scope  hookScope
}

func readCatalog(path string) (hookCatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return hookCatalog{}, err
	}
	var catalog hookCatalog
	return catalog, json.Unmarshal(data, &catalog)
}

// selectedRecords reads the catalog a scan wrote for each service the hooks options name and keeps the records the
// options select now, so that the agent attaches what its configuration says even when the scan selected otherwise.
func selectedRecords(options agentOptions, services []service) ([]selectedRecord, error) {
	if len(options.Hooks) > 0 && options.Catalog == "" {
		return nil, fmt.Errorf("options.%s.hooks selects records of the catalog options.%s.catalog names", optionsName,
			optionsName)
	}
	var selected []selectedRecord
	for _, owner := range services {
		selection, selecting := options.Hooks[owner.name]
		if !selecting {
			continue
		}
		catalog, err := readCatalog(filepath.Join(options.Catalog, hooksDirectory, owner.name+".json"))
		if err != nil {
			return nil, fmt.Errorf("the hook catalog of service %s: %w", owner.name, err)
		}
		for _, record := range catalog.Records {
			if scope, selects := selection.selects(record); selects {
				selected = append(selected, selectedRecord{record: record, owner: owner, scope: scope})
			}
		}
	}
	return selected, nil
}

// nativeFunctions are the functions the agent places points in: those its functions configuration names, and every
// selected record of a user-space function the configuration does not name, so that controls observe it before any
// value is known.
func nativeFunctions(selected []selectedRecord, configured []functionOptions) ([]nativeFunction, error) {
	var functions []nativeFunction
	for _, function := range configured {
		functions = append(functions, nativeFunction{options: function, negatable: true})
	}
	for _, chosen := range selected {
		record := chosen.record
		named := slices.ContainsFunc(configured, func(function functionOptions) bool {
			return function.Service == chosen.owner.name && function.File == record.Target.File &&
				function.Symbol == record.Target.Symbol
		})
		if named || (record.Inject != mechanismUprobeEntry && record.Inject != mechanismUprobeReturns) {
			continue
		}
		function, err := recordFunction(chosen)
		if err != nil {
			return nil, fmt.Errorf("record %s: %w", record.ID, err)
		}
		functions = append(functions, function)
	}
	return functions, nil
}

// recordFunction is the point of a selected record: its result in ax read by its return class, a failure as the
// selecting include says or as the class has it, a negative integer and a NULL pointer, and as errors only the failed
// values controls observed; a check may be negated once controls observed both of its results.
func recordFunction(chosen selectedRecord) (nativeFunction, error) {
	record, signature := chosen.record, chosen.record.Signature
	if signature == nil || len(signature.Results) > 0 {
		return nativeFunction{}, errors.New("the agent places points from the C return class DWARF gives, which it lacks")
	}
	returns := len(record.Target.Returns)
	for _, clone := range record.Target.Clones {
		returns += len(clone.Returns)
	}
	if returns == 0 {
		return nativeFunction{}, errors.New("the function has no ret instruction to observe it at; exclude it from the selection")
	}
	function := functionOptions{Service: chosen.owner.name, File: record.Target.File, Symbol: record.Target.Symbol,
		Kind: record.Kind, Result: resultOptions{Registers: []string{resultRegister}, Outcome: resultRegister},
		Errors: map[string][]injectedWord{}}
	values := map[int64]bool{}
	for _, observed := range record.Observed {
		values[observed.Min] = true
	}
	switch {
	case signature.Returns == classBool:
		function.Result.Type = typeBool
		return nativeFunction{options: function, record: record.ID, negatable: values[0] && values[1]}, nil
	case signature.Returns == classPointer:
		function.Result.Type, function.Result.Error = typePointer, errorZero
	case (signature.Returns == classInteger || signature.Returns == classEnum) && signature.Size == 4:
		function.Result.Type, function.Result.Error = typeInt32, errorNegative
	case (signature.Returns == classInteger || signature.Returns == classEnum) && signature.Size == 8:
		function.Result.Type, function.Result.Error = typeInt64, errorNegative
	default:
		return nativeFunction{}, fmt.Errorf("the agent reads no %s result of %d bytes", signature.Returns, signature.Size)
	}
	if chosen.scope.Error != "" {
		function.Result.Error = chosen.scope.Error
	}
	for _, value := range slices.Sorted(maps.Keys(values)) {
		name := strconv.FormatInt(value, 10)
		if function.Result.Type == typePointer {
			name = nullError
		}
		if failed(value, function.Result.Error) {
			function.Errors[name] = []injectedWord{{Constant: value}}
		}
	}
	return nativeFunction{options: function, record: record.ID}, nil
}

// failed is whether a result fails by an error rule, as the kernel programs classify it.
func failed(value int64, rule string) bool {
	switch rule {
	case errorNegative:
		return value < 0
	case errorZero:
		return value == 0
	}
	return value != 0
}

// merge adds to the records of a scan's catalogs the values the natural results of a control experiment gave, each
// with the experiment as its provenance, and lists the experiment among each catalog's controls.
func merge(directory, observations, experiment string) error {
	file, err := os.Open(observations)
	if err != nil {
		return err
	}
	defer file.Close()
	results := map[string][]faultpoint.ObservationRecord{}
	for decoder := json.NewDecoder(file); decoder.More(); {
		var observation faultpoint.ObservationRecord
		if err := decoder.Decode(&observation); err != nil {
			return err
		}
		if observation.Experiment == experiment && observation.Rule == nil {
			results[observation.Service] = append(results[observation.Service], observation)
		}
	}
	if len(results) == 0 {
		return fmt.Errorf("%s holds no natural result of experiment %s", observations, experiment)
	}
	for _, service := range slices.Sorted(maps.Keys(results)) {
		path := filepath.Join(directory, hooksDirectory, service+".json")
		catalog, err := readCatalog(path)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("%s: no catalog, so its results are not merged\n", service)
			continue
		}
		if err != nil {
			return err
		}
		added, err := catalog.addObserved(results[service], experiment)
		if err != nil {
			return fmt.Errorf("service %s: %w", service, err)
		}
		if err := writeJSON(path, catalog); err != nil {
			return err
		}
		fmt.Printf("%s: %d observed values added from %s\n", service, added, experiment)
	}
	return nil
}

// addObserved adds the values a control's results at a catalog's records give, and returns how many were new.
func (catalog *hookCatalog) addObserved(results []faultpoint.ObservationRecord, experiment string) (int, error) {
	indexes := map[string]int{}
	for index, record := range catalog.Records {
		indexes[record.ID] = index
	}
	added := 0
	for _, result := range results {
		index, known := indexes[result.Point]
		if !known {
			continue
		}
		value, gives, err := observedValue(catalog.Records[index], result)
		if err != nil {
			return added, err
		}
		entry := valueRange{Min: value, Max: value, Provenance: provenanceObserved + ":" + experiment}
		if gives && !slices.Contains(catalog.Records[index].Observed, entry) {
			catalog.Records[index].Observed = append(catalog.Records[index].Observed, entry)
			added++
		}
	}
	if !slices.Contains(catalog.Controls, experiment) {
		catalog.Controls = append(catalog.Controls, experiment)
	}
	return added, nil
}

// observedValue is the value a natural result at a record gives: a failed call's integer, which its detail holds,
// NULL for a failed call of a pointer, a check's result as 1 or 0, and a failed syscall's negative errno.
func observedValue(record hookRecord, result faultpoint.ObservationRecord) (int64, bool, error) {
	value, valued := result.Detail[detailValue]
	pointer := record.Signature != nil && record.Signature.Returns == classPointer
	switch {
	case record.Kind == kindCall && result.Outcome == outcomeError && valued:
		parsed, err := strconv.ParseInt(value, 10, 64)
		return parsed, err == nil, err
	case record.Kind == kindCall && result.Outcome == outcomeError && pointer:
		return 0, true, nil
	case record.Kind == kindCheck:
		return int64(boolCount(result.Outcome == outcomeTrue)), true, nil
	case record.Kind == kindSyscall && result.Outcome != outcomeOK:
		errno, named := errnos[result.Outcome]
		return -int64(errno), named, nil
	}
	return 0, false, nil
}
