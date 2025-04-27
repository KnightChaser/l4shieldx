// xdpcollector/xdp_collector.go
package xdpcollector

import (
	"C"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strings"

	"l4shieldx/xdpcollector/utility"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sync/errgroup"
)

// Event mirrors the C struct from the eBPF program.
type Event struct {
	Ts    uint64
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

const (
	TRAFFIC_ALLOWED = 0
	TRAFFIC_DENIED  = 1
)

// Collector defines Run/Close behavior.
type Collector interface {
	// Basic Collector methods
	Run(ctx context.Context) error
	Close()

	// Enforce network policies
	Block(ip net.IP) error
	Unblock(ip net.IP) error

	// Stats returns allowedPkts, allowedBytes, deniedPkts, deniedBytes
	Stats() (uint64, uint64, uint64, uint64, error)
}

// New loads, attaches, and returns an XDP collector.
func New(ifaceName string, netChan chan string) (Collector, error) {
	if strings.TrimSpace(ifaceName) == "" {
		return nil, fmt.Errorf("interface name is required")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %q: %w", ifaceName, err)
	}

	root, err := utility.GetProjectRoot()
	if err != nil {
		return nil, fmt.Errorf("get project root: %w", err)
	}
	obj := filepath.Join(root, "xdpcollector", "xdp_prog.o")

	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create collection: %w", err)
	}

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

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		lnk.Close()
		coll.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	blockedMap := coll.Maps["blocked_ips"]
	if blockedMap == nil {
		lnk.Close()
		coll.Close()
		return nil, fmt.Errorf("blocked_ips map not found")
	}

	return &collector{
		iface:   ifaceName,
		coll:    coll,
		link:    lnk,
		rd:      rd,
		buf:     bytes.Buffer{},
		netChan: netChan,
		blocked: blockedMap,
	}, nil
}

type collector struct {
	iface   string           // network interface name
	coll    *ebpf.Collection // eBPF collection
	link    link.Link        // XDP link
	rd      *ringbuf.Reader  // ring buffer reader
	buf     bytes.Buffer     // buffer for raw sample
	netChan chan string      //	channel for network events
	blocked *ebpf.Map        // blocked IPs map (IPv4 address, block status)
}

// Run attaches and consumes events until context cancellation.
func (c *collector) Run(ctx context.Context) error {
	defer c.Close()
	log.Printf("XDP collector attached to %s – waiting for TCP traffic…", c.iface)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return c.consume(gctx) })
	return g.Wait()
}

// consume reads raw samples, decodes Event, and pushes to channels.
func (c *collector) consume(ctx context.Context) error {
	var ev Event
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		rec, err := c.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, context.Canceled) {
				return nil
			}
			log.Printf("[xdp] ringbuf read: %v", err)
			continue
		}

		c.buf.Reset()
		c.buf.Write(rec.RawSample)
		if err := binary.Read(&c.buf, binary.LittleEndian, &ev); err != nil {
			log.Printf("[xdp] decode error: %v", err)
			continue
		}

		ts := utility.ConvertBpfNanotime(ev.Ts)
		msg := fmt.Sprintf("%s:%d → %s:%d at %s",
			utility.IntToIPv4(ev.Saddr), ev.Sport,
			utility.IntToIPv4(ev.Daddr), ev.Dport,
			ts,
		)

		c.netChan <- msg
	}
}

// Block adds the IP to the blocked_ips map.
func (c *collector) Block(ip net.IP) error {
	key := binary.BigEndian.Uint32(ip.To4())
	var one uint8 = 1
	return c.blocked.Update(key, one, ebpf.UpdateAny)
}

// Unblock removes the IP from the blocked_ips map.
func (c *collector) Unblock(ip net.IP) error {
	key := binary.BigEndian.Uint32(ip.To4())
	return c.blocked.Delete(key)
}

func (c *collector) Stats() (allowCnt, allowBytes, denyCnt, denyBytes uint64, err error) {
	// helper to read and sum per-CPU
	sumPerCPU := func(m *ebpf.Map, key uint32) (uint64, error) {
		var percpu []uint64
		if err := m.Lookup(key, &percpu); err != nil {
			return 0, err
		}
		var sum uint64
		for _, v := range percpu {
			sum += v
		}
		return sum, nil
	}

	// allowed/denied packet counts
	if allowCnt, err = sumPerCPU(c.coll.Maps["packet_count"], TRAFFIC_ALLOWED); err != nil {
		return
	}
	if denyCnt, err = sumPerCPU(c.coll.Maps["packet_count"], TRAFFIC_DENIED); err != nil {
		return
	}

	// allowed/denied byte counts
	if allowBytes, err = sumPerCPU(c.coll.Maps["packet_bytes"], TRAFFIC_ALLOWED); err != nil {
		return
	}
	if denyBytes, err = sumPerCPU(c.coll.Maps["packet_bytes"], TRAFFIC_DENIED); err != nil {
		return
	}
	return
}

// Close cleans up ring buffer, link, and collection.
func (c *collector) Close() {
	if c.rd != nil {
		c.rd.Close()
	}
	if c.link != nil {
		c.link.Close()
	}
	if c.coll != nil {
		c.coll.Close()
	}
}
