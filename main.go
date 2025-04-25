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

	"l4shieldx/xdpcollector"

	"github.com/cilium/ebpf/rlimit"
	"github.com/rivo/tview"
)

// ChannelWriter funnels log.Printf calls into our System Log pane.
type ChannelWriter struct {
	Ch chan string
}

func (w ChannelWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	w.Ch <- msg
	return len(p), nil
}

func main() {
	iface := flag.String("iface", "", "network interface to attach XDP program to")
	flag.Parse()

	sysChan := make(chan string, 200)
	netChan := make(chan string, 200)
	countChan := make(chan int, 200)

	log.SetFlags(0) // drop default timestamps; UI will show them
	log.SetOutput(ChannelWriter{sysChan})

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	coll, err := xdpcollector.New(*iface, netChan, countChan)
	if err != nil {
		log.Fatalf("collector init: %v", err)
	}

	// Create an event loop to handle incoming events
	app := tview.NewApplication()
	sysView := tview.NewTextView()
	sysView.SetBorder(true).SetTitle("System Log")

	netView := tview.NewTextView()
	netView.SetBorder(true).SetTitle("Network Events")

	cntView := tview.NewTextView()
	cntView.SetBorder(true).SetTitle("Packet Count")

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(sysView, 0, 2, false).
		AddItem(netView, 0, 4, false).
		AddItem(cntView, 3, 1, false)

	go func() {
		for line := range sysChan {
			app.QueueUpdateDraw(func() {
				fmt.Fprintln(sysView, line)
			})
		}
	}()
	go func() {
		for line := range netChan {
			app.QueueUpdateDraw(func() {
				fmt.Fprintln(netView, line)
			})
		}
	}()
	go func() {
		for cnt := range countChan {
			app.QueueUpdateDraw(func() {
				cntView.Clear()
				fmt.Fprintf(cntView, "%d\n", cnt)
			})
		}
	}()

	// Handle shutdown signals
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run collector in background
	go func() {
		if err := coll.Run(ctx); err != nil {
			sysChan <- fmt.Sprintf("[ERROR] collector run: %v", err)
		}
	}()

	// Start the UI loop
	if err := app.SetRoot(layout, true).Run(); err != nil {
		log.Fatalf("failed to start UI: %v", err)
	}
}
