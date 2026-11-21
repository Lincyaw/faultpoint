package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	hostPid = "1"
	// handleFID is AT_HANDLE_FID, which x/sys/unix lacks: it gives a file's identity on file systems such as overlayfs
	// that cannot open a file by its handle, and a lower layer's file has one identity in every container.
	handleFID = 0x200
)

// hostRootMount returns the id of the mount that is the root of the host, as its first process sees it.
func hostRootMount() (int, error) {
	root, mount, err := openRoot(hostPid)
	if err == nil {
		unix.Close(root)
	}
	return mount, err
}

// openRoot opens the root directory of a process and returns it with the id of its mount.
func openRoot(pid string) (int, int, error) {
	root, err := unix.Open("/proc/"+pid+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, 0, err
	}
	_, mount, err := unix.NameToHandleAt(root, "", unix.AT_EMPTY_PATH|handleFID)
	if err != nil {
		unix.Close(root)
	}
	return root, mount, err
}

// openContainerFiles opens a file in each container of a service, keeping one file per inode.
func openContainerFiles(owner service, path string, hostRoot int) ([]*os.File, error) {
	var files []*os.File
	seen := map[string]bool{}
	for _, cgroup := range owner.cgroupPaths {
		file, identity, err := openInContainer(cgroup, path, hostRoot)
		if err != nil {
			return nil, errors.Join(err, closeFiles(files))
		}
		if seen[identity] {
			file.Close()
			continue
		}
		seen[identity] = true
		files = append(files, file)
	}
	return files, nil
}

func closeFiles(files []*os.File) error {
	var errs []error
	for _, file := range files {
		errs = append(errs, file.Close())
	}
	return errors.Join(errs...)
}

// openInContainer opens a file of the container a cgroup holds and returns it with its identity. It resolves the path
// inside the root of the cgroup's first process, so that no symlink leads out of it, and refuses a file on another
// mount, such as a volume or a bind mount of the host, as well as a process whose root is the host's.
func openInContainer(cgroup, path string, hostRoot int) (*os.File, string, error) {
	procs, err := os.ReadFile(filepath.Join(cgroup, "cgroup.procs"))
	if err != nil {
		return nil, "", err
	}
	pid, _, _ := strings.Cut(string(procs), "\n")
	if pid == "" || pid == "0" {
		return nil, "", fmt.Errorf("the agent sees no process of %s, which it needs the host's pid namespace for", cgroup)
	}
	root, rootMount, err := openRoot(pid)
	if err != nil {
		return nil, "", err
	}
	defer unix.Close(root)
	if rootMount == hostRoot {
		return nil, "", fmt.Errorf("process %s of %s runs in the host's root file system", pid, cgroup)
	}
	descriptor, err := unix.Openat2(root, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, "", fmt.Errorf("opening %s in the root of process %s: %w", path, pid, err)
	}
	file := os.NewFile(uintptr(descriptor), fmt.Sprintf("/proc/%s/root%s", pid, path))
	handle, mount, err := unix.NameToHandleAt(descriptor, "", unix.AT_EMPTY_PATH|handleFID)
	if err == nil && mount != rootMount {
		err = fmt.Errorf("%s is on another mount than the root of process %s, so it may be a file of the host", path, pid)
	}
	if err != nil {
		return nil, "", errors.Join(err, file.Close())
	}
	return file, fmt.Sprintf("%d:%x", handle.Type(), handle.Bytes()), nil
}
