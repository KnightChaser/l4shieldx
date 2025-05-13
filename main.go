// main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"l4shieldx/ui"
	"l4shieldx/xdpcollector"
	"l4shieldx/xdpcollector/utility"

	"github.com/cilium/ebpf/rlimit"
	"github.com/gdamore/tcell/v2"
)

func main() {
	// Select network interface
	var iface string
	iface = ui.SelectNetworkInterface()

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
	coll, err := xdpcollector.New(iface, sysChan, netChan, allowChan, denyChan)

	if err != nil {
		log.Fatalf("Collector initialization failed: %v", err)
	}
	log.Printf("Starting XDP collector on interface %s", iface)

	// Setup UI
	app, layout, sysView, netView, allowedView, deniedView, input := ui.SetupUI(sysChan)

	// Handle text input for deny/allow commands
	input.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}
		cmd, err := utility.ParseCommand(input.GetText())
		if err != nil {
			sysChan <- "[ERROR] " + err.Error()
		} else {
			switch cmd.Op {
			case utility.OpDeny:
				// "deny" is followed by an IP address
				err = coll.Block(cmd.IP)
				msg := "[SYS] deny " + cmd.IP.String()
				if err != nil {
					msg += " failed: " + err.Error()
				}
				sysChan <- msg

			case utility.OpAllow:
				// "allow" is followed by an IP address
				err = coll.Unblock(cmd.IP)
				msg := "[SYS] allow " + cmd.IP.String()
				if err != nil {
					msg += " failed: " + err.Error()
				}
				sysChan <- msg

			case utility.OpProtect:
				// "protect" is followed by a PID
				err = coll.Protect(cmd.PID)
				msg := fmt.Sprintf("[SYS] protect %d", cmd.PID)
				if err != nil {
					msg += " failed: " + err.Error()
				}
				sysChan <- msg

			case utility.OpUnprotect:
				// "unprotect" is followed by a PID
				err = coll.Unprotect(cmd.PID)
				msg := fmt.Sprintf("[SYS] unprotect %d", cmd.PID)
				if err != nil {
					msg += " failed: " + err.Error()
				}
				sysChan <- msg

			case utility.OpShowProtected:
				// "showProtected" displays the protected PID and their ports
				protected := coll.ShowProtected()
				if len(protected) == 0 {
					sysChan <- "[SYS] No protected PIDs"
				} else {
					for pid, ports := range protected {
						sysChan <- fmt.Sprintf("[SYS] PID %d -> %v", pid, ports)
					}
				}

			case utility.OpSetThreshold:
				// "setThreshold" is followed by a number
				coll.SetThreshold(cmd.Value)
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
