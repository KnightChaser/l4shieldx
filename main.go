// main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os/signal"
	"strings"
	"syscall"

	"l4shieldx/ui"
	"l4shieldx/xdpcollector"
	"l4shieldx/xdpcollector/utility"

	"github.com/cilium/ebpf/rlimit"
	"github.com/gdamore/tcell/v2"
)

// selectInterface prompts the user to select a network interface from the available ones
func selectInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Failed to get network interfaces: %v", err)
	}

	fmt.Println("Select a network interface: ")
	valid := make([]string, 0)

	// Iterate over network interfaces and print their names and addresses
	for _, iface := range ifaces {
		// Skips ones that are down or have no addresses
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}

		addrs, _ := iface.Addrs()
		addrStrs := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				addrStrs = append(addrStrs, ipNet.IP.String())
			}
		}

		fmt.Printf("  [%d] %s (%s)\n", len(valid), iface.Name, strings.Join(addrStrs, ", "))
		valid = append(valid, iface.Name)
	}

	if len(valid) == 0 {
		log.Fatal("No valid network interfaces found")
	}

	// Prompt user for selection
	var choice int
	for {
		fmt.Print("Enter the number of the interface you want to use: ")
		_, err := fmt.Scanf("%d", &choice)
		if err == nil && choice >= 0 && choice < len(valid) {
			break
		}
		fmt.Println("Invalid input. Try again.")
	}

	return valid[choice]
}

func main() {
	// Set up command line flags
	var iface string
	flag.StringVar(&iface, "iface", "", "Network interface to use (default: prompt for selection)")
	flag.Parse()
	if iface == "" {
		iface = selectInterface()
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
				err = coll.Block(cmd.IP)
				msg := "[SYS] deny " + cmd.IP.String()
				if err != nil {
					msg += " failed: " + err.Error()
				}
				sysChan <- msg

			case utility.OpAllow:
				err = coll.Unblock(cmd.IP)
				msg := "[SYS] allow " + cmd.IP.String()
				if err != nil {
					msg += " failed: " + err.Error()
				}
				sysChan <- msg

			case utility.OpSetThreshold:
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
