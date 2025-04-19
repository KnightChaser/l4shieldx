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
	"os"
	"path/filepath"

	"l4shieldx/xdpcollector/utility"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sync/errgroup"
)

// -----------------------------------------------------------------------------
// Public surface
// -----------------------------------------------------------------------------

// Event mirrors the C structure emitted by the eBPF program.
type Event struct {
	Ts    uint64 // BPF timestamp in nanoseconds of the packet arrival.
	Saddr uint32 // Source address in network byte order.
	Daddr uint32 // Destination address in network byte order.
	Sport uint16 // Source port in network byte order.
	Dport uint16 // Destination port in network byte order.
}

// Collector is the only thing an external package needs to use.
type Collector interface {
	Run(ctx context.Context) error
	Close()
}

// New returns a ready‑to‑run Collector.  ifaceName may be empty to use the
// interface passed with ‑iface on the CLI (main.go) or “eth0” as fallback.
func New(ifaceName string) (Collector, error) {
	if ifaceName == "" {
		return nil, fmt.Errorf("interface name is required")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %q: %w", ifaceName, err)
	}

	// Load the eBPF program from the object file.
	obj := filepath.Join(projectRoot(), "xdpcollector", "xdp_prog.o")
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create collection: %w", err)
	}

	// Attach in generic mode for widest NIC compatibility.
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
		iface: ifaceName,
		coll:  coll,
		link:  lnk,
		rd:    rd,
	}, nil
}

// -----------------------------------------------------------------------------
// Internal implementation
// -----------------------------------------------------------------------------

type collector struct {
	iface string           // NIC(Network Interface Card) name
	coll  *ebpf.Collection // eBPF collection
	link  link.Link        // XDP link
	rd    *ringbuf.Reader  // Ring buffer reader for events
	buf   bytes.Buffer     // Buffer for reading events
}

func (c *collector) Run(ctx context.Context) error {
	defer c.Close()

	log.Printf("XDP collector attached to %s – waiting for TCP traffic…", c.iface)

	// Manage concurrency with errgroup.
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return c.consume(gctx) })
	return g.Wait()
}

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

		// Use bytes.Buffer to read the event to reduce GC pressure
		c.buf.Reset()
		c.buf.Write(rec.RawSample)
		if err := binary.Read(&c.buf, binary.LittleEndian, &ev); err != nil {
			log.Printf("[xdp] decode: %v", err)
			continue
		}

		timestamp := utility.ConvertBpfNanotime(ev.Ts)
		fmt.Printf("[TCP] %s:%d → %s:%d at %s\n",
			utility.IntToIPv4(ev.Saddr), ev.Sport, utility.IntToIPv4(ev.Daddr), ev.Dport, timestamp)
	}
}

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

// Project root is the directory containing the executable.
func projectRoot() string {
	exe, _ := os.Executable()
	return filepath.Dir(exe)
}
