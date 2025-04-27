// xdpcollector/xdp_collector_method.go
package xdpcollector

import (
	"C"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"l4shieldx/xdpcollector/utility"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sync/errgroup"
)

// Run starts both the event consumer and a periodic stats pump.
// It returns when the context is canceled or an error occurs.
func (c *collector) Run(ctx context.Context) error {
	defer c.Close()
	log.Printf("XDP collector attached to %s – waiting for TCP traffic…", c.iface)

	g, gctx := errgroup.WithContext(ctx)

	// Pump events
	g.Go(func() error { return c.consume(gctx) })

	// Pump stats every second
	g.Go(func() error {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-gctx.Done():
				return nil
			case <-ticker.C:
				// Fetch per-CPU aggregated stats
				allowPkts, allowBytes, denyPkts, denyBytes, err := c.Stats()
				if err != nil {
					msg := fmt.Sprintf("[stats] error: %v", err)
					c.sysChan <- msg
					continue
				}
				// Send TrafficStat structs to UI
				c.allowChan <- utility.TrafficStat{Pkts: allowPkts, Bytes: allowBytes}
				c.denyChan <- utility.TrafficStat{Pkts: denyPkts, Bytes: denyBytes}
			}
		}
	})

	return g.Wait()
}

// consume reads raw ringbuf samples, decodes Event, and pushes formatted
// strings onto netChan until context is done.
func (c *collector) consume(ctx context.Context) error {
	for {
		// Exit on cancellation
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
			msg := fmt.Sprintf("[xdp] ringbuf read: %v", err)
			c.sysChan <- msg
			continue
		}

		// Decode the Event struct
		var ev Event
		c.buf.Reset()
		c.buf.Write(rec.RawSample)
		if err := binary.Read(&c.buf, binary.LittleEndian, &ev); err != nil {
			msg := fmt.Sprintf("[xdp] decode error: %v", err)
			c.sysChan <- msg
			continue
		}

		// Format timestamp and message
		ts := utility.ConvertBpfNanotime(ev.Ts)
		msg := fmt.Sprintf("%s:%d → %s:%d at %s",
			utility.IntToIPv4(ev.Saddr), ev.Sport,
			utility.IntToIPv4(ev.Daddr), ev.Dport,
			ts,
		)
		c.netChan <- msg
	}
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

	// Capture allowed/denied packet and byte counts
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

// Block inserts ip into the eBPF blocked_ips map.
func (c *collector) Block(ip net.IP) error {
	key := binary.BigEndian.Uint32(ip.To4())
	var one uint8 = 1
	return c.blocked.Update(key, one, ebpf.UpdateAny)
}

// Unblock removes ip from the eBPF blocked_ips map.
func (c *collector) Unblock(ip net.IP) error {
	key := binary.BigEndian.Uint32(ip.To4())
	return c.blocked.Delete(key)
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
