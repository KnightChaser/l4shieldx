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
	OpDeny          Opcode = iota + 1 // drop matching traffic
	OpAllow                           // allow matching traffic
	OpSetThreshold                    // set threshold for rate limiting
	OpProtect                         // protect the given target (Add into cgroup)
	OpUnprotect                       // unprotect the given target (Delete from cgroup)
	OpShowProtected                   // show all protected tasks (List elements in group)
)

type Command struct {
	Op    Opcode
	IP    net.IP // for deny/allow
	Value uint64 // for setThreshold
	Pid   int    // for protect/unprotect
}

func ParseCommand(input string) (*Command, error) {
	parts := strings.Fields(strings.TrimSpace(input))

	switch parts[0] {
	case "deny":
		// "deny" command should be followed by an IP address
		if len(parts) != 2 {
			return nil, fmt.Errorf("usage: deny <IP>")
		}
		ip := net.ParseIP(parts[1]).To4()
		if ip == nil {
			return nil, fmt.Errorf("bad IP %q", parts[1])
		}
		return &Command{Op: OpDeny, IP: ip}, nil

	case "allow":
		// "allow" command should be followed by an IP address
		if len(parts) != 2 {
			return nil, fmt.Errorf("usage: allow <IP>")
		}
		ip := net.ParseIP(parts[1]).To4()
		if ip == nil {
			return nil, fmt.Errorf("bad IP %q", parts[1])
		}
		return &Command{Op: OpAllow, IP: ip}, nil

	case "setThreshold":
		// "setThreshold" command should be followed by a positive integer
		if len(parts) != 2 {
			return nil, fmt.Errorf("usage: setThreshold <positive integer>")
		}
		v, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil || v == 0 {
			return nil, fmt.Errorf("invalid threshold %q", parts[1])
		}
		return &Command{Op: OpSetThreshold, Value: v}, nil

	case "protect":
		// "protect" command should be followed by a PID
		if len(parts) != 2 {
			return nil, fmt.Errorf("usage: protect <PID>")
		}
		pid, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid PID %q", parts[1])
		}
		return &Command{Op: OpProtect, Pid: pid}, nil

	case "unprotect":
		// "unprotect" command should be followed by a PID
		if len(parts) != 2 {
			return nil, fmt.Errorf("usage: unprotect <PID>")
		}
		pid, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid PID %q", parts[1])
		}
		return &Command{Op: OpUnprotect, Pid: pid}, nil

	case "show":
		// "show" command can be followed by "protected"
		if len(parts) == 2 && parts[1] == "protected" {
			return &Command{Op: OpShowProtected}, nil
		}
		return nil, fmt.Errorf("usage: show <target>")

	default:
		return nil, fmt.Errorf("unknown op %q", parts[0])
	}
}
