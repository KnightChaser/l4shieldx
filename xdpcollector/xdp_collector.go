// xdpcollector/xdp_collector.go
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
	// AddPID adds a process to the cgroup so its sockets get filtered.
	AddPID(pid int) error
	// RemovePID removes a process from the cgroup so its sockets get filtered.
	RemovePID(pid int) error
	// Run attaches XDP, consumes events, and pumps stats until ctx cancellation.
	Run(ctx context.Context) error
	// Close tears down XDP and frees resources.
	Close()

	// Block inserts ip into the blocked_ips map.
	Block(ip net.IP) error
	// Unblock removes ip from the blocked_ips map.
	Unblock(ip net.IP) error
	// SetThreshold sets the rate limit threshold (X pkts/sec).
	SetThreshold(threshold uint64)

	// Network stats returns: allowedPkts, allowedBytes, deniedPkts, deniedBytes.
	Stats() (uint64, uint64, uint64, uint64, error)
}

type collector struct {
	iface         string
	coll          *ebpf.Collection
	link          link.Link
	cgroupLink    link.Link                   // cgroup link for the process
	cgroupManager *utility.LinuxCgroupManager // cgroup manager for the process
	rd            *ringbuf.Reader
	buf           bytes.Buffer               // for binary.Read
	sysChan       chan<- string              // formatted system messages
	netChan       chan<- string              // formatted event strings
	allowChan     chan<- utility.TrafficStat // formatted allowed traffic stats
	denyChan      chan<- utility.TrafficStat // formatted denied traffic stats
	ipCountMap    *ebpf.Map                  // per-CPU map for IP count
	blocked       *ebpf.Map                  // blocklist map
	threshold     uint64                     // rate limit threshold (X pkts/sec)
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
	xdpProg := coll.Programs["xdp_tcp_hello"]
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
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
		xdpLink.Close()
		coll.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	// Initialize cgroup manager
	cg := utility.NewCgroupManager("/sys/fs/cgroup", "l4shieldx")
	if err := cg.Init(); err != nil {
		xdpLink.Close()
		coll.Close()
		return nil, fmt.Errorf("cgroup init: %w", err)
	}

	// Create cgroup for the process and attach it to the XDP program
	cgProg := coll.Programs["cgroup_tcp_hello"]
	if cgProg == nil {
		xdpLink.Close()
		cg.Destroy()
		coll.Close()
		return nil, fmt.Errorf("cgroup_sk_ingress program not found")
	}

	cgLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cg.Path(),
		Program: cgProg,
		Attach:  ebpf.AttachCGroupInetIngress,
	})

	if err != nil {
		xdpLink.Close()
		cg.Destroy()
		coll.Close()
		return nil, fmt.Errorf("attach cgroup: %w", err)
	}

	// Ensure ip_count map exists
	ipCountMap := coll.Maps["ip_count_map"]
	if ipCountMap == nil {
		xdpLink.Close()
		coll.Close()
		return nil, fmt.Errorf("ip_count_map not found")
	}

	// Ensure blocked_ips map exists
	blockedMap := coll.Maps["blocked_ips"]
	if blockedMap == nil {
		xdpLink.Close()
		coll.Close()
		return nil, fmt.Errorf("blocked_ips map not found")
	}

	// Default packet threshold (1,000 pkts/sec)
	defaultThreshold := uint64(1000)
	sysChan <- fmt.Sprintf("[collector] default threshold set to %d pkts/sec", defaultThreshold)

	return &collector{
		iface:         ifaceName,
		coll:          coll,
		link:          xdpLink,
		cgroupLink:    cgLink,
		cgroupManager: cg,
		rd:            rd,
		buf:           bytes.Buffer{},
		sysChan:       sysChan,
		netChan:       netChan,
		allowChan:     allowChan,
		denyChan:      denyChan,
		ipCountMap:    ipCountMap,
		blocked:       blockedMap,
		threshold:     defaultThreshold,
	}, nil
}
