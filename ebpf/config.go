package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	optionsName      = "ebpf"
	jsonlOptionsName = "jsonl"
)

// agentOptions are given under "ebpf" in the file FAULTPOINT_CONFIG names; syscalls are those whose natural results the
// observations report, every syscall when it is absent, functions the native functions of the services' containers
// that carry points, hooks the records a scan selects per service, and catalog the directory a scan wrote, whose
// selected records the agent attaches.
type agentOptions struct {
	Services  map[string]serviceOptions `json:"services"`
	Syscalls  []string                  `json:"syscalls"`
	Functions []functionOptions         `json:"functions"`
	Hooks     map[string]hookOptions    `json:"hooks"`
	Catalog   string                    `json:"catalog"`
}

// serviceOptions say where a service runs: the cgroups of its processes and the devices that carry its packets.
type serviceOptions struct {
	Cgroups []string        `json:"cgroups"`
	Devices []deviceOptions `json:"devices"`
}

// deviceOptions name a network device and the direction, relative to the service, of the packets it transmits:
// a container's own interface transmits its egress, and the host-side peer of that interface transmits its ingress.
type deviceOptions struct {
	Netns     string `json:"netns"`
	Name      string `json:"name"`
	Transmits string `json:"transmits"`
}

// service is a configured service with its index in the kernel maps.
type service struct {
	name        string
	index       uint32
	cgroups     map[uint64]int
	cgroupPaths []string
	devices     []deviceOptions
}

// services resolves each configured service's cgroups to the ids and levels the kernel reports.
func (options agentOptions) services() ([]service, error) {
	if len(options.Services) == 0 {
		return nil, fmt.Errorf("FAULTPOINT_CONFIG gives the agent's services under options.%s.services", optionsName)
	}
	names := make([]string, 0, len(options.Services))
	for name := range options.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	resolved := make([]service, 0, len(names))
	for index, name := range names {
		configured := options.Services[name]
		next := service{name: name, index: uint32(index), cgroups: map[uint64]int{}, cgroupPaths: configured.Cgroups,
			devices: configured.Devices}
		for _, path := range configured.Cgroups {
			id, level, err := cgroupIdentity(path)
			if err != nil {
				return nil, fmt.Errorf("service %s: %w", name, err)
			}
			next.cgroups[id] = level
		}
		for _, device := range configured.Devices {
			if device.Name == "" || (device.Transmits != directionEgress && device.Transmits != directionIngress) {
				return nil, fmt.Errorf("service %s: a device has a name and transmits %s or %s: %+v",
					name, directionEgress, directionIngress, device)
			}
		}
		resolved = append(resolved, next)
	}
	return resolved, nil
}

// cgroupIdentity returns a cgroup's id, which is the inode of its directory, and how many levels below the root it is.
func cgroupIdentity(path string) (uint64, int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	level := 0
	for parent := filepath.Dir(filepath.Clean(path)); ; parent = filepath.Dir(parent) {
		var filesystem unix.Statfs_t
		if err := unix.Statfs(parent, &filesystem); err != nil {
			return 0, 0, err
		}
		if filesystem.Type != unix.CGROUP2_SUPER_MAGIC {
			break
		}
		level++
	}
	if level == 0 {
		return 0, 0, fmt.Errorf("%s is not a cgroup below the root of a cgroup v2 hierarchy", path)
	}
	return info.Sys().(*syscall.Stat_t).Ino, level, nil
}
