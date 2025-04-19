package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"l4shieldx/xdpcollector"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	iface := flag.String("iface", "", "network interface to attach XDP program to")
	flag.Parse()

	// Remove memory limit for the ring buffer.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
		return
	}

	coll, err := xdpcollector.New(*iface)
	if err != nil {
		log.Fatalf("collector init: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := coll.Run(ctx); err != nil {
		log.Fatalf("collector run: %v", err)
	}
}
