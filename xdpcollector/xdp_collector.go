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
	"time"

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

// Collector defines Run/Close behavior and policy control.
type Collector interface {
	Run(ctx context.Context) error
	Close()
	Block(ip net.IP) error
	Unblock(ip net.IP) error
	Stats() (uint64, uint64, uint64, uint64, error)
}

// New loads, attaches, and returns an XDP collector that reports events
// and periodically pushes traffic stats to the provided channels.
func New(
	ifaceName string,
	netChan chan<- string,
	allowChan chan<- utility.TrafficStat,
	denyChan chan<- utility.TrafficStat,
) (Collector, error) {
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

type collector struct {
	iface     string           // interface name
	coll      *ebpf.Collection
	link      link.Link
	rd        *ringbuf.Reader
	buf       bytes.Buffer
	netChan   chan<- string
	allowChan chan<- utility.TrafficStat
	denyChan  chan<- utility.TrafficStat
	blocked   *ebpf.Map
}

// Run starts consuming events and reporting stats until ctx cancellation.
func (c *collector) Run(ctx context.Context) error {
	defer c.Close()
	log.Printf("XDP collector attached to %s – waiting for TCP traffic…", c.iface)
	g, gctx := errgroup.WithContext(ctx)
	// pump events
	g.Go(func() error { return c.consume(gctx) })
	// pump stats
	g.Go(func() error {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-gctx.Done():
				return nil
			case <-t.C:
				allowPkts, allowBytes, denyPkts, denyBytes, err := c.Stats()
				if err != nil {
					log.Printf("[stats] error: %v", err)
					continue
				}
				c.allowChan <- utility.TrafficStat{Pkts: allowPkts, Bytes: allowBytes}
				c.denyChan <- utility.TrafficStat{Pkts: denyPkts, Bytes: denyBytes}
			}
		}
	})
	return g.Wait()
}

// consume reads raw samples, formats, and sends to netChan.
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

// Stats reads per-CPU maps and aggregates allowed/denied counts & bytes.
func (c *collector) Stats() (uint64, uint64, uint64, uint64, error) {
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
	allowPkts, err := sumPerCPU(c.coll.Maps["packet_count"], TRAFFIC_ALLOWED)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	denyPkts, err := sumPerCPU(c.coll.Maps["packet_count"], TRAFFIC_DENIED)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	allowBytes, err := sumPerCPU(c.coll.Maps["packet_bytes"], TRAFFIC_ALLOWED)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	denyBytes, err := sumPerCPU(c.coll.Maps["packet_bytes"], TRAFFIC_DENIED)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	return allowPkts, allowBytes, denyPkts, denyBytes, nil
}

// Close cleans up the ring buffer, link, and collection.
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

