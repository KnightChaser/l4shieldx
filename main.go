// main.go
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type event struct {
	Ts    uint64
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

func main() {
	// TODO: Make an interface name configurable
	ifaceName := "wlo1"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to get interface %s: %v", ifaceName, err)
	}

	spec, err := ebpf.LoadCollectionSpec("xdp_prog.o")
	if err != nil {
		log.Fatalf("failed to load collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("failed to create collection: %v", err)
	}
	defer coll.Close()

	// Call the program to load it into the kernel
	prog := coll.Programs["xdp_tcp_hello"]
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("failed to attach XDP program: %v", err)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Println("Listening for events...")
	for {
		select {
		case <-ctx.Done():
			return
		default:
			rec, err := rd.Read()
			if err != nil {
				if ctx.Err() != nil {
					return // Stop signal received
				}
				continue
			}

			var e event
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("failed to read event: %v", err)
				continue
			}

			fmt.Printf("[TCP] %s:%d → %s:%d at %d ns\n",
				intToIPv4(e.Saddr), e.Sport, intToIPv4(e.Daddr), e.Dport, e.Ts)
		}
	}
}

func intToIPv4(i uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}
