package faultpoint

import (
	"encoding/json"
	"os"
	"slices"
	"strconv"
)

const (
	environmentPrefix = "FAULTPOINT_"
	defaultScopeKey   = "fp.scope"
	jsonlOptionsName  = "jsonl"
)

// settings are the FAULTPOINT_ environment variables and the configuration file FAULTPOINT_CONFIG names.
type settings struct {
	service  string
	rules    string
	report   string
	scopeKey string
	seed     int64
	config   configuration
}

// configuration enables plugins and gives their options; placement belongs to the rewriter, which reads the same file.
type configuration struct {
	Plugins   []string                   `json:"plugins"`
	Options   map[string]json.RawMessage `json:"options"`
	Placement json.RawMessage            `json:"placement"`
}

func readSettings() settings {
	read := settings{
		service:  os.Getenv(environmentPrefix + "SERVICE"),
		rules:    os.Getenv(environmentPrefix + "RULES"),
		report:   os.Getenv(environmentPrefix + "REPORT"),
		scopeKey: defaultScopeKey,
	}
	if key := os.Getenv(environmentPrefix + "SCOPE_KEY"); key != "" {
		read.scopeKey = key
	}
	if text := os.Getenv(environmentPrefix + "SEED"); text != "" {
		seed, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			Abort("FAULTPOINT_SEED is an integer: %q", text)
		}
		read.seed = seed
	}
	if read.rules == "" && read.report == "" {
		return read
	}
	if path := os.Getenv(environmentPrefix + "CONFIG"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			Abort("cannot read the configuration: %v", err)
		}
		if err := decodeStrict(data, &read.config); err != nil {
			Abort("invalid configuration in %s: %v", path, err)
		}
	}
	return read
}

// enables is whether a plugin is on; without a plugin list every plugin of the build is.
func (c configuration) enables(name string) bool {
	return c.Plugins == nil || slices.Contains(c.Plugins, name)
}

// Options fills the options of a named component, which hold their defaults, from the configuration; a process
// that is not enabled reads no configuration and keeps the defaults.
func Options(name string, options any) {
	given, found := current.settings.config.Options[name]
	if !found {
		return
	}
	if options == nil {
		Abort("%s takes no options", name)
	}
	if err := decodeStrict(given, options); err != nil {
		Abort("options of %s: %v", name, err)
	}
}

// checkNames ends the process when the configuration names a plugin this build does not contain.
func (c configuration) checkNames(registered []string) {
	for _, name := range c.Plugins {
		if !slices.Contains(registered, name) {
			Abort("the configuration enables plugin %q, which this build does not contain", name)
		}
	}
	for name := range c.Options {
		if name != jsonlOptionsName && !slices.Contains(registered, name) {
			Abort("the configuration gives options to %q, which this build does not contain", name)
		}
	}
}
