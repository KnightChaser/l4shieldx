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
)

type Command struct {
	Op    Opcode
	IP    net.IP // for deny/allow
	Value uint64 // for setThreshold
}

func ParseCommand(input string) (*Command, error) {
	parts := strings.Fields(strings.TrimSpace(input))
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid command %q", input)
	}

	switch parts[0] {
	case "deny":
		ip := net.ParseIP(parts[1]).To4()
		if ip == nil {
			return nil, fmt.Errorf("bad IP %q", parts[1])
		}
		return &Command{Op: OpDeny, IP: ip}, nil

	case "allow":
		ip := net.ParseIP(parts[1]).To4()
		if ip == nil {
			return nil, fmt.Errorf("bad IP %q", parts[1])
		}
		return &Command{Op: OpAllow, IP: ip}, nil

	case "setThreshold":
		v, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil || v == 0 {
			return nil, fmt.Errorf("invalid threshold %q", parts[1])
		}
		return &Command{Op: OpSetThreshold, Value: v}, nil

	default:
		return nil, fmt.Errorf("unknown op %q", parts[0])
	}
}
