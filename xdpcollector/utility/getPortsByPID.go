// xdpcollector/utility/getPortsByPID.go
package utility

import (
	"fmt"

	"github.com/shirou/gopsutil/v3/process"
)

// GetPortsByPID returns all local ports that the given PID has open.
// PID is int32 to match gopsutil’s API.
func GetPortsByPID(pid int32) ([]uint32, error) {
	p, err := process.NewProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to create process handle for PID %d: %w", pid, err)
	}

	conns, err := p.Connections()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch connections for PID %d: %w", pid, err)
	}

	ports := make([]uint32, 0, len(conns))
	seen := make(map[uint32]struct{}, len(conns))

	for _, c := range conns {
		if c.Laddr.Port == 0 {
			continue
		}
		port := c.Laddr.Port
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}

	return ports, nil
}
