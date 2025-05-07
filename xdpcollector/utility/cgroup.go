// xdpcollector/utility/cgroup.go
package utility

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// CgroupManager is an interface that defines methods for managing cgroups.
type CgroupManager interface {
	Init() error
	AddPID(pid int) error
	RemovePID(pid int) error
	Destroy() error
	Path() error
}

// LinuxCgroupManager is a struct that implements the CgroupManager interface for Linux cgroups.
type LinuxCgroupManager struct {
	basePath string // e.g. "/sys/fs/cgroup"
	groupDir string // e.g. "ddos-protect"
	fullPath string // e.g. basePath + "/" + groupDir
}

// NewCgroupManager creates a new LinuxCgroupManager with the specified base path and group directory.
func NewCgroupManager(basePath, groupDir string) *LinuxCgroupManager {
	return &LinuxCgroupManager{
		basePath: basePath,
		groupDir: groupDir,
		fullPath: filepath.Join(basePath, groupDir),
	}
}

// Init initializes the LinuxCgroupManager with the base path and group directory.
func (lcm *LinuxCgroupManager) Init() error {
	// Ensure mount exists
	if _, err := os.Stat(lcm.basePath); err != nil {
		return fmt.Errorf("cgroup base path %s does not exist: %v", lcm.basePath, err)
	}

	// Create the cgroup
	if err := os.MkdirAll(lcm.fullPath, 0755); err != nil {
		return fmt.Errorf("failed to create cgroup directory %s: %v", lcm.fullPath, err)
	}

	return nil
}

// AddPID adds a process ID to the cgroup.
// (CGroup v2 supports this for removal too.)
func (lcm *LinuxCgroupManager) AddPID(pid int) error {
	p := filepath.Join(lcm.fullPath, "cgroup.procs")
	return os.WriteFile(p, []byte(strconv.Itoa(pid)), 0644)
}

// RemovePID removes a process ID from the cgroup.
func (lcm *LinuxCgroupManager) RemovePID(pid int) error {
	return lcm.AddPID(pid)
}

// Destroy removes the (empty) cgroup directory.
func (lcm *LinuxCgroupManager) Destroy() error {
	if err := os.Remove(lcm.fullPath); err != nil {
		return fmt.Errorf("remove %s: %w", lcm.fullPath, err)
	}
	return nil
}

// Path returns the full cgroup directory path.
func (lcm *LinuxCgroupManager) Path() string {
	return lcm.fullPath
}
