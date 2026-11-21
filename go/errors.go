package faultpoint

import (
	"errors"
	"fmt"
	"slices"
	"sync"
)

// registry holds the errors registered by name: the sentinels a call fail rule can return, and the names an
// observation gives the errors that are or wrap them.
var registry struct {
	sync.RWMutex
	names  []string
	errors map[string]error
}

// RegisterError names an error, such as a package-level sentinel the rewriter registers as <package path>.<name>.
func RegisterError(name string, err error) {
	registry.Lock()
	defer registry.Unlock()
	if registry.errors == nil {
		registry.errors = map[string]error{}
	}
	if _, known := registry.errors[name]; !known {
		registry.names = append(registry.names, name)
		slices.Sort(registry.names)
	}
	registry.errors[name] = err
}

// RegisteredError is the error registered under a name.
func RegisteredError(name string) (error, bool) {
	registry.RLock()
	defer registry.RUnlock()
	err, found := registry.errors[name]
	return err, found
}

// ErrorName is how an observation names an error: the name of the first registered error, in name order, that it is
// or wraps, otherwise its type, so that the name is bounded and never carries a message.
func ErrorName(err error) string {
	registry.RLock()
	defer registry.RUnlock()
	for _, name := range registry.names {
		if errors.Is(err, registry.errors[name]) {
			return name
		}
	}
	return fmt.Sprintf("%T", err)
}
