// main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"strings"
	"syscall"

	"l4shieldx/ui"
	"l4shieldx/xdpcollector"
	"l4shieldx/xdpcollector/utility"

	"github.com/cilium/ebpf/rlimit"
	"github.com/gdamore/tcell/v2"
)

func main() {
	iface := flag.String("iface", "", "network interface to attach XDP program to")
	flag.Parse()

	if *iface == "" {
		log.Fatal("Error: -iface flag is required")
	}

	// Create channels for communication
	sysChan := make(chan string, 200)
	netChan := make(chan string, 200)
	// Channels for pushing allowed/denied stats to the UI
	allowChan := make(chan utility.TrafficStat, 200)
	denyChan := make(chan utility.TrafficStat, 200)

	// Configure standard logger to write to the system log channel
	log.SetFlags(0)
	log.SetOutput(ui.ChannelWriter{Ch: sysChan})

	// Remove memory lock limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Initialize XDP Collector
	coll, err := xdpcollector.New(*iface, netChan, allowChan, denyChan)
	if err != nil {
		log.Fatalf("Collector initialization failed: %v", err)
	}
	log.Printf("Starting XDP collector on interface %s", *iface)

	// Setup UI
	app, layout, sysView, netView, allowedView, deniedView, input := ui.SetupUI(sysChan)

	// Handle text input for deny/allow commands
	input.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}
		text := input.GetText()
		cmd, err := utility.ParseCommand(text)
		if err != nil {
			sysChan <- fmt.Sprintf("[ERROR] %v", err)
		} else {
			var opErr error
			switch cmd.Op {
			case utility.OpDeny:
				opErr = coll.Block(cmd.IP)
			case utility.OpAllow:
				opErr = coll.Unblock(cmd.IP)
			}

			if opErr != nil {
				sysChan <- fmt.Sprintf("[ERROR] %s %s failed: %v",
					cmd.Op, cmd.IP, opErr)
			} else {
				sysChan <- fmt.Sprintf("[SYS] %s %s succeeded",
					strings.ToUpper(cmd.Op.String()), cmd.IP)
			}
		}
		input.SetText("")
		app.SetFocus(input)
	})

	// Buffers to keep only the last maxLines entries for logs
	var sysLines, netLines []string

	// Start goroutines to pump data from channels to UI views
	go ui.PumpTextview(app, sysView, sysChan, &sysLines)
	go ui.PumpTextview(app, netView, netChan, &netLines)

	// Pump allowed/denied counts to UI
	go ui.PumpCounterView(app, allowedView, allowChan)
	go ui.PumpCounterView(app, deniedView, denyChan)

	// Handle graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run the XDP collector in a separate goroutine
	go func() {
		log.Printf("Collector run loop starting...")
		if err := coll.Run(ctx); err != nil {
			// Send runtime errors to the system log view
			sysChan <- fmt.Sprintf("[ERROR] Collector run failed: %v", err)
		}
		log.Printf("Collector run loop finished.")
	}()

	// Start the UI application event loop
	log.Printf("Starting UI...")
	if err := app.SetRoot(layout, true).SetFocus(input).Run(); err != nil {
		log.Fatalf("Failed to start UI: %v", err)
	}

	log.Printf("Application exiting.")
}
