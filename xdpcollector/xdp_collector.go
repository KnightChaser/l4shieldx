// xdpcollector/collector.go
package xdpcollector

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"l4shieldx/xdpcollector/utility"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Collector runs the XDP program, enforces blocklist, and emits events/stats.
type Collector interface {
	// Run attaches XDP, consumes events, and pumps stats until ctx cancellation.
	Run(ctx context.Context) error
	// Close tears down XDP and frees resources.
	Close()

	// Block inserts ip into the blocked_ips map.
	Block(ip net.IP) error
	// Unblock removes ip from the blocked_ips map.
	Unblock(ip net.IP) error

	// Network stats returns: allowedPkts, allowedBytes, deniedPkts, deniedBytes.
	Stats() (uint64, uint64, uint64, uint64, error)
}

type collector struct {
	iface     string
	coll      *ebpf.Collection
	link      link.Link
	rd        *ringbuf.Reader
	buf       bytes.Buffer  // for binary.Read
	netChan   chan<- string // formatted event strings
	allowChan chan<- utility.TrafficStat
	denyChan  chan<- utility.TrafficStat
	blocked   *ebpf.Map // blocklist map
}

// New loads the eBPF program (xdp_prog.o), attaches it to ifaceName,
// and returns a Collector that will push raw events to netChan
// and periodic TrafficStat into allowChan/denyChan.
//
//	ifaceName: name of network interface (e.g. "eth0")
//	netChan:   chan<- string  — formatted “src:port → dst:port at TIMESTAMP”
//	allowChan: chan<- utility.TrafficStat
//	denyChan:  chan<- utility.TrafficStat
func New(
	ifaceName string,
	netChan chan<- string,
	allowChan chan<- utility.TrafficStat,
	denyChan chan<- utility.TrafficStat,
) (Collector, error) {
	// Validate interface
	if strings.TrimSpace(ifaceName) == "" {
		return nil, fmt.Errorf("interface name is required")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %q: %w", ifaceName, err)
	}

	// Locate compiled program
	root, err := utility.GetProjectRoot()
	if err != nil {
		return nil, fmt.Errorf("get project root: %w", err)
	}
	obj := filepath.Join(root, "xdpcollector", "xdp_prog.o")

	// Load & create collection
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create collection: %w", err)
	}

	// Attach XDP
	prog := coll.Programs["xdp_tcp_hello"]
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach XDP: %w", err)
	}

	// Prepare ring buffer reader for Event structs
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		lnk.Close()
		coll.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	// Ensure blocked_ips map exists
	blockedMap := coll.Maps["blocked_ips"]
	if blockedMap == nil {
		lnk.Close()
		coll.Close()
		return nil, fmt.Errorf("blocked_ips map not found")
	}

	return &collector{
		iface:     ifaceName,
		coll:      coll,
		link:      lnk,
		rd:        rd,
		buf:       bytes.Buffer{},
		netChan:   netChan,
		allowChan: allowChan,
		denyChan:  denyChan,
		blocked:   blockedMap,
	}, nil
}
