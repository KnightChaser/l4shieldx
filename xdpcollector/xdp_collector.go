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

// Event mirrors the C struct emitted by the eBPF program.
type Event struct {
	Ts    uint64 // nanoseconds
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

// Collector encapsulates Run/Close.
type Collector interface {
	Run(ctx context.Context) error
	Close()
}

// New returns a ready-to-run Collector.
func New(ifaceName string, netChan chan string, countChan chan int) (Collector, error) {
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
	objPath := filepath.Join(root, "xdpcollector", "xdp_prog.o")

	spec, err := ebpf.LoadCollectionSpec(objPath)
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

	return &collector{
		iface:     ifaceName,
		coll:      coll,
		link:      lnk,
		rd:        rd,
		netChan:   netChan,
		countChan: countChan,
	}, nil
}

type collector struct {
	iface     string           // network interface name (e.g. wlo1)
	coll      *ebpf.Collection // eBPF collection
	link      link.Link        // eBPF collection
	rd        *ringbuf.Reader  // ring buffer reader
	buf       bytes.Buffer     // buffer for reading raw samples
	netChan   chan string      // channel for network events
	countChan chan int         // buffer for reading raw samples
	counter   int              // number of packets seen
}

// Run starts the collector and waits for TCP packets.
func (c *collector) Run(ctx context.Context) error {
	defer c.Close()
	log.Printf("XDP collector attached to %s – waiting for TCP traffic…", c.iface)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return c.consume(gctx) })
	return g.Wait()
}

// consume reads from the ring buffer and decodes events.
func (c *collector) consume(ctx context.Context) error {
	var ev Event

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Read from the ring buffer.
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

		// Log the event and send it to the channel.
		c.counter++
		c.countChan <- c.counter
		c.netChan <- msg
	}
}

// Close releases resources attached to the collector.
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
