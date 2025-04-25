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

const maxLines = 100 // keep the last 100 entries

// ChannelWriter funnels log.Printf calls into our System Log pane.
type ChannelWriter struct{ Ch chan string }

func (w ChannelWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	w.Ch <- msg
	return len(p), nil
}

func main() {
	iface := flag.String("iface", "", "network interface to attach XDP program to")
	flag.Parse()

	// Create the channel
	sysChan := make(chan string, 200)
	netChan := make(chan string, 200)
	countChan := make(chan int, 200)

	log.SetFlags(0)
	log.SetOutput(ChannelWriter{sysChan})

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	coll, err := xdpcollector.New(*iface, netChan, countChan)
	if err != nil {
		log.Fatalf("collector init: %v", err)
	}
	log.Printf("Starting XDP collector on interface %s", *iface)

	// Set up the UI
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

	// buffers to hold last maxLines entries
	var sysLines, netLines []string

	// pump system log
	go func() {
		for line := range sysChan {
			sysLines = append(sysLines, line)
			if len(sysLines) > maxLines {
				sysLines = sysLines[1:]
			}
			app.QueueUpdateDraw(func() {
				sysView.SetText(strings.Join(sysLines, "\n"))
				sysView.ScrollToEnd()
			})
		}
	}()

	// pump network events
	go func() {
		for line := range netChan {
			netLines = append(netLines, line)
			if len(netLines) > maxLines {
				netLines = netLines[1:]
			}
			app.QueueUpdateDraw(func() {
				netView.SetText(strings.Join(netLines, "\n"))
				netView.ScrollToEnd()
			})
		}
	}()

	// pump packet count
	go func() {
		for cnt := range countChan {
			app.QueueUpdateDraw(func() {
				cntView.Clear()
				fmt.Fprintf(cntView, "%d", cnt)
			})
		}
	}()

	// Handle Ctrl+C and SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := coll.Run(ctx); err != nil {
			sysChan <- fmt.Sprintf("[ERROR] collector run: %v", err)
		}
	}()

	if err := app.SetRoot(layout, true).Run(); err != nil {
		log.Fatalf("failed to start UI: %v", err)
	}
}
