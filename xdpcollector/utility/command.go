// xdpcollector/utility/command.go
package utility

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Opcode represents the type of command to apply in the eBPF program.
type Opcode int

const (
	OpDeny         Opcode = iota + 1 // drop matching traffic
	OpAllow                          // allow matching traffic
	OpSetThreshold                   // set threshold for rate limiting
	OpProtect                        // start protecting the PID's port
	OpUnprotect                      // stop protecting the PID's port
)

type Command struct {
	Op    Opcode
	IP    net.IP // for deny/allow
	PID   int32  // for protect/unprotect
	Value uint64 // for setThreshold
}

func ParseCommand(input string) (*Command, error) {
	parts := strings.Fields(strings.TrimSpace(input))
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid command %q", input)
	}

	switch parts[0] {
	case "deny":
		// "deny" is followed by an IP address
		// "deny" blocks traffic from the given IP address
		ip := net.ParseIP(parts[1]).To4()
		if ip == nil {
			return nil, fmt.Errorf("bad IP %q", parts[1])
		}
		return &Command{Op: OpDeny, IP: ip}, nil

	case "allow":
		// "allow" is followed by an IP address
		// "allow" allows traffic from the given IP address
		ip := net.ParseIP(parts[1]).To4()
		if ip == nil {
			return nil, fmt.Errorf("bad IP %q", parts[1])
		}
		return &Command{Op: OpAllow, IP: ip}, nil

	case "setThreshold":
		// "setThreshold" is followed by a number
		// "setThreshold" sets the threshold for rate limiting
		v, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil || v == 0 {
			return nil, fmt.Errorf("invalid threshold %q", parts[1])
		}
		return &Command{Op: OpSetThreshold, Value: v}, nil

	case "protect":
		// "protect" is followed by a PID
		// "protect" starts protecting the PID's port
		pid, err := strconv.ParseInt(parts[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid PID %q", parts[1])
		}
		return &Command{Op: OpProtect, PID: int32(pid)}, nil

	case "unprotect":
		// "unprotect" is followed by a PID
		// "unprotect" stops protecting the PID's port
		pid, err := strconv.ParseInt(parts[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid PID %q", parts[1])
		}
		return &Command{Op: OpUnprotect, PID: int32(pid)}, nil

	default:
		return nil, fmt.Errorf("unknown op %q", parts[0])
	}
}
