// xdpcollector/utility/command.go
package utility

import (
	"fmt"
	"net"
	"strings"
)

// Opcode represents the type of command to apply in the eBPF program.
type Opcode int

const (
	OpDeny  Opcode = iota // drop matching traffic
	OpAllow               // allow matching traffic
)

// String returns a string representation of the Opcode.
func (o Opcode) String() string {
	switch o {
	case OpDeny:
		return "deny"
	case OpAllow:
		return "allow"
	default:
		return "unknown"
	}
}

// Command encapsulates a parsed user command.
type Command struct {
	Op Opcode // Opcode to apply (e.g. OpDeny, OpAllow)
	IP net.IP // IPv4 address to apply the operation(Op) to
}

// ParseCommand validates and parses an input string of the form
//
//	"deny <IPv4>" or "allow <IPv4>"
//
// Returns a Command with the appropriate Opcode and IP, or an error.
func ParseCommand(input string) (*Command, error) {
	text := strings.TrimSpace(input)
	parts := strings.Fields(text)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid command format: %q, expected 'deny <IP>' or 'allow <IP>'", text)
	}

	var op Opcode
	switch parts[0] {
	case "deny":
		op = OpDeny
	case "allow":
		op = OpAllow
	default:
		return nil, fmt.Errorf("unknown command %q, expected 'deny' or 'allow'", parts[0])
	}

	ip := net.ParseIP(parts[1]).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %q", parts[1])
	}

	return &Command{Op: op, IP: ip}, nil
}
