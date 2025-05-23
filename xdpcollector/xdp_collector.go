// xdpcollector/collector.go
package xdpcollector

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"

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
	// Protect scans listening ports for pid and updates the protected_ports BPF map.
	Protect(pid int32) error
	// Unprotect removes pid from the protected_ports BPF map.
	Unprotect(pid int32) error
	// SetThreshold sets the rate limit threshold (X pkts/sec).
	SetThreshold(threshold uint64)
	// ShowProtectedPorts returns a map of PIDs and their protected ports.
	ShowProtected() map[int32][]uint16

	// Network stats returns: allowedPkts, allowedBytes, deniedPkts, deniedBytes.
	Stats() (uint64, uint64, uint64, uint64, error)
}

type collector struct {
	iface             string
	coll              *ebpf.Collection
	link              link.Link
	rd                *ringbuf.Reader
	buf               bytes.Buffer               // for binary.Read
	sysChan           chan<- string              // formatted system messages
	netChan           chan<- string              // formatted event strings
	allowChan         chan<- utility.TrafficStat // formatted allowed traffic stats
	denyChan          chan<- utility.TrafficStat // formatted denied traffic stats
	ipCountMap        *ebpf.Map                  // per-CPU map for IP count
	blocked           *ebpf.Map                  // blocklist map
	protectedMap      map[int32][]uint16         // map of protected ports (PID -> list of protected ports)
	protectedMapMutex sync.Mutex                 // mutex for protectedMap
	threshold         uint64                     // rate limit threshold (X pkts/sec)
	thresholdMap      *ebpf.Map                  // map for threshold (Value threshold passed to eBPF via this)
}

// New loads the eBPF program (xdp_prog.o), attaches it to ifaceName,
// and returns a Collector that will push raw events to netChan
// and periodic TrafficStat into allowChan/denyChan.
//
//	ifaceName: name of network interface (e.g. "eth0")
//	sysChan:   chan<- string  — formatted system messages
//	netChan:   chan<- string  — formatted “src:port → dst:port at TIMESTAMP”
//	allowChan: chan<- utility.TrafficStat
//	denyChan:  chan<- utility.TrafficStat
func New(
	ifaceName string,
	sysChan chan<- string,
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
	obj := filepath.Join(root, "xdpcollector", "bpf", "xdp_prog.o")

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
	prog := coll.Programs["xdp_tcp_protect"]
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

	// Ensure ip_count map exists
	ipCountMap := coll.Maps["ip_count_map"]
	if ipCountMap == nil {
		lnk.Close()
		coll.Close()
		return nil, fmt.Errorf("ip_count_map not found")
	}

	// Ensure blocked_ips map exists
	blockedMap := coll.Maps["blocked_ips"]
	if blockedMap == nil {
		lnk.Close()
		coll.Close()
		return nil, fmt.Errorf("blocked_ips map not found")
	}

	// Ensure threshold map exists
	thresholdMap := coll.Maps["threshold_map"]
	if thresholdMap == nil {
		lnk.Close()
		coll.Close()
		return nil, fmt.Errorf("threshold_map not found")
	}

	// Default packet threshold (25 pkts/sec)
	defaultThreshold := uint64(25)
	if err := thresholdMap.Update(uint32(0), defaultThreshold, ebpf.UpdateAny); err != nil {
		lnk.Close()
		coll.Close()
		return nil, fmt.Errorf("put threshold: %w", err)
	}
	sysChan <- fmt.Sprintf("[collector] default threshold set to %d pkts/sec", defaultThreshold)

	return &collector{
		iface:        ifaceName,
		coll:         coll,
		link:         lnk,
		rd:           rd,
		buf:          bytes.Buffer{},
		sysChan:      sysChan,
		netChan:      netChan,
		allowChan:    allowChan,
		denyChan:     denyChan,
		ipCountMap:   ipCountMap,
		blocked:      blockedMap,
		protectedMap: make(map[int32][]uint16),
		threshold:    defaultThreshold,
		thresholdMap: thresholdMap,
	}, nil
}
