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
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const maxLines = 100 // keep the last 100 entries

// ChannelWriter funnels log.Printf calls into our System Log pane.
type ChannelWriter struct{ Ch chan string }

// Write implements the io.Writer interface for our channel.
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

	// -- Set up the UI --
	// (Basic UI setup code, using tview library)
	app := tview.NewApplication()
	sysView := tview.NewTextView()
	sysView.SetBorder(true).SetTitle("System Log")

	netView := tview.NewTextView()
	netView.SetBorder(true).SetTitle("Network Events")

	cntView := tview.NewTextView()
	cntView.SetBorder(true).SetTitle("Packet Count")

	// (Set up input field for user commands, splitting the bottom pane horizontally)
	input := tview.NewInputField().
		SetLabel("Command: ").
		SetFieldWidth(0) // expand to fill
	input.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			text := input.GetText()
			// If the user input is inserted,
			// show the text contents at the system log pane.
			if strings.TrimSpace(text) != "" {
				sysChan <- fmt.Sprintf("[INPUT] %s", text)
			}
			input.SetText("")   // clear
			app.SetFocus(input) // keep focus
		}
	})

	// Combine cntView + input into a horizontal Flex
	bottomFlex := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(cntView, 0, 1, false).
		AddItem(input, 0, 2, true)

	// Main layout: vertical split
	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(sysView, 0, 2, false).
		AddItem(netView, 0, 4, false).
		AddItem(bottomFlex, 3, 1, true)

	// Buffers to keep only the last maxLines entries
	var sysLines, netLines []string

	// Pump system log
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

	// Pump network events
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

	// Pump packet count
	go func() {
		for cnt := range countChan {
			app.QueueUpdateDraw(func() {
				cntView.Clear()
				fmt.Fprintf(cntView, "%d", cnt)
			})
		}
	}()

	// Handle shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run collector
	go func() {
		if err := coll.Run(ctx); err != nil {
			sysChan <- fmt.Sprintf("[ERROR] collector run: %v", err)
		}
	}()

	// Start UI
	if err := app.SetRoot(layout, true).SetFocus(input).Run(); err != nil {
		log.Fatalf("failed to start UI: %v", err)
	}
}
