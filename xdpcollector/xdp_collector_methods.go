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
	"sync/atomic"
	"time"

	"l4shieldx/ui"
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

				// Sweep & reset per-IP counts (every ticker)
				if err := c.flushIPCounts(MaxReqsPerSecond); err != nil {
					c.sysChan <- fmt.Sprintf("[flusher] error: %v", err.Error())
				}

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
		msg := ui.FormatNewViewMsg(ev.Ts, ev.Saddr, ev.Daddr, ev.Sport, ev.Dport)

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

// SetThreshold sets the rate limit threshold for the eBPF program.
func (c *collector) SetThreshold(threshold uint64) {
	old := atomic.SwapUint64(&c.threshold, threshold)
	// Update the BPF map so xdp_prog can see the new value immediately
	key := uint32(0)
	if err := c.thresholdMap.Update(key, threshold, ebpf.UpdateAny); err != nil {
		c.sysChan <- fmt.Sprintf("[xdp] error updating threshold map: %v", err)
		return
	}
	c.sysChan <- fmt.Sprintf("[xdp] threshold changed from %d pkts/sec to %d pkts/sec", old, threshold)
}

// Protect adds all current listening ports of pid into the protected_ports BPF map.
// It skips any ports already known to be protected for that PID.
func (c *collector) Protect(pid int32) error {
	c.protectedMapMutex.Lock()
	defer c.protectedMapMutex.Unlock()

	// Fetch all in-use ports for this PID
	ports32, err := utility.GetPortsByPID(pid)
	if err != nil {
		return fmt.Errorf("failed to get ports for PID %d: %w", pid, err)
	}
	if len(ports32) == 0 {
		return fmt.Errorf("no ports found for PID %d", pid)
	}

	bp := c.coll.Maps["protected_ports"]

	// Ensure there’s an entry slice to append into
	existing := c.protectedMap[pid]
	for _, p32 := range ports32 {
		port := uint16(p32)

		// Dedupe against existing protected ports for this PID
		already := false
		for _, ep := range existing {
			if ep == port {
				already = true
				break
			}
		}
		if already {
			c.sysChan <- fmt.Sprintf("[protect] PID %d port %d is already protected", pid, port)
			continue
		}

		// Insert into BPF map (XDP side)
		if err := bp.Update(port, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to update protected_ports for port %d: %w", port, err)
		}

		// Record it in-memory and log
		existing = append(existing, port)
		c.sysChan <- fmt.Sprintf("[protect] PID %d port %d added to protection list", pid, port)
	}

	// Commit updated slice back to protectedMap
	c.protectedMap[pid] = existing
	return nil
}

// Unprotect removes the protected ports for pid from the BPF map.
func (c *collector) Unprotect(pid int32) error {
	// Ensure thread safety when accessing the protectedMap
	c.protectedMapMutex.Lock()
	defer c.protectedMapMutex.Unlock()

	ports, ok := c.protectedMap[pid]
	if !ok {
		return fmt.Errorf("Unprotect: PID %d not protected yet", pid)
	}

	// Remove the ports from the protected_ports BPF map
	bp := c.coll.Maps["protected_ports"]
	for _, port := range ports {
		if err := bp.Delete(port); err != nil {
			return fmt.Errorf("Unprotect: failed to delete port %d: %w", port, err)
		}
	}

	// Remove the PID from the protectedMap
	delete(c.protectedMap, pid)
	c.sysChan <- fmt.Sprintf("[unprotect] PID %d(port: %v) was removed from protection list", pid, ports)

	// Remove the PID from the protectedMap
	if _, ok := c.protectedMap[pid]; ok {
		delete(c.protectedMap, pid)
	}

	return nil
}

// ShowProtected returns the list of protected ports for a given PID.
func (c *collector) ShowProtected() map[int32][]uint16 {
	return c.protectedMap
}

// flushIPCounts resets the per-IP counts in the eBPF map.
func (c *collector) flushIPCounts(maxReqsPerSecond uint64) error {
	// Check if the threshold is set in the eBPF map
	// If not, use the Go-side threshold
	var threshold uint64
	if err := c.thresholdMap.Lookup(uint32(0), &threshold); err != nil {
		// Fallback to the Go-side threshold if the map lookup fails
		threshold = atomic.LoadUint64(&c.threshold)
	}

	mapIterator := c.ipCountMap.Iterate()
	var key uint32
	var count uint64

	for mapIterator.Next(&key, &count) {
		if count > threshold {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, key)
			c.blocked.Update(key, uint8(1), ebpf.UpdateAny)
			c.sysChan <- fmt.Sprintf("[flusher] blocked %s (%d/%d pkts/sec)", ip, count, threshold)
		}
		c.ipCountMap.Delete(key)
	}
	return mapIterator.Err()
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
