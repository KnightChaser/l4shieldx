// xdpcollector/event.go
package xdpcollector

// Event mirrors the C struct emitted by the XDP program.
// Ts is the BPF timestamp in nanoseconds since boot.
// Saddr/Daddr are IPv4 source/destination in host byte order.
// Sport/Dport are their TCP ports.
type Event struct {
	Ts    uint64
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

// Traffic verdict constants — used as map keys.
const (
	TRAFFIC_ALLOWED = 0
	TRAFFIC_DENIED  = 1
)
