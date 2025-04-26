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

// setupUI creates and configures the tview application, views, and layout.
// It returns the application, the root layout flexbox, and the input field.
func setupUI(sysChan chan string) (*tview.Application, *tview.Flex, *tview.TextView, *tview.TextView, *tview.TextView, *tview.InputField) {
	app := tview.NewApplication()

	sysView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetChangedFunc(func() { app.Draw() }) // Redraw on content change
	sysView.SetBorder(true).SetTitle("System Log")

	netView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetChangedFunc(func() { app.Draw() })
	netView.SetBorder(true).SetTitle("Network Events")

	cntView := tview.NewTextView().
		SetTextAlign(tview.AlignCenter). // Center the count
		SetChangedFunc(func() { app.Draw() })
	cntView.SetBorder(true).SetTitle("Packet Count")

	input := tview.NewInputField().
		SetLabel("Command: ").
		SetFieldWidth(0) // expand to fill

	input.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			text := input.GetText()
			// If the user input is inserted, show the text contents at the system log pane.
			if strings.TrimSpace(text) != "" {
				sysChan <- fmt.Sprintf("[INPUT] %s", text)
			}
			input.SetText("")   // clear input field
			app.SetFocus(input) // keep focus on input field
		} else if key == tcell.KeyEsc {
			app.SetFocus(input)
		}
	})

	// Combine cntView + input into a horizontal Flex
	bottomFlex := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(cntView, 0, 1, false). // Fixed width proportion for count
		AddItem(input, 0, 3, true)     // Input field takes more space and has focus

	// Main layout: vertical split
	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(sysView, 0, 2, false).  // System log proportion
		AddItem(netView, 0, 4, false).  // Network events proportion
		AddItem(bottomFlex, 3, 1, true) // Bottom row (count + input), has focus initially via input

	return app, layout, sysView, netView, cntView, input
}

// pumpTextview reads lines from a channel and updates a tview.TextView, keeping only maxLines.
func pumpTextview(app *tview.Application, view *tview.TextView, ch <-chan string, buffer *[]string) {
	for line := range ch {
		*buffer = append(*buffer, line)
		if len(*buffer) > maxLines {
			*buffer = (*buffer)[1:] // Keep buffer trimmed
		}
		// Use QueueUpdateDraw for thread-safe UI updates
		app.QueueUpdateDraw(func() {
			view.SetText(strings.Join(*buffer, "\n"))
			view.ScrollToEnd()
		})
	}
}

// pumpCounterView reads integers from a channel and updates the counter tview.TextView.
func pumpCounterView(app *tview.Application, view *tview.TextView, ch <-chan int) {
	for cnt := range ch {
		// Use QueueUpdateDraw for thread-safe UI updates
		app.QueueUpdateDraw(func() {
			view.SetText(fmt.Sprintf("%d", cnt)) // Update text directly
		})
	}
}

func main() {
	iface := flag.String("iface", "", "network interface to attach XDP program to")
	flag.Parse()

	if *iface == "" {
		log.Fatal("Error: -iface flag is required") // Added explicit check
	}

	// Create channels for communication
	sysChan := make(chan string, 200)
	netChan := make(chan string, 200)
	countChan := make(chan int, 200)

	// Configure standard logger to write to the system log channel
	log.SetFlags(0) // Keep flags minimal for clean output
	log.SetOutput(ChannelWriter{Ch: sysChan})

	// Remove memory lock limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Initialize XDP Collector
	coll, err := xdpcollector.New(*iface, netChan, countChan)
	if err != nil {
		log.Fatalf("Collector initialization failed: %v", err)
	}
	log.Printf("Starting XDP collector on interface %s", *iface) // Initial log message

	// Setup UI
	app, layout, sysView, netView, cntView, input := setupUI(sysChan)

	// Buffers to keep only the last maxLines entries for logs
	var sysLines, netLines []string

	// Start goroutines to pump data from channels to UI views
	go pumpTextview(app, sysView, sysChan, &sysLines)
	go pumpTextview(app, netView, netChan, &netLines)
	go pumpCounterView(app, cntView, countChan)

	// Handle graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run the XDP collector in a separate goroutine
	go func() {
		log.Printf("Collector run loop starting...") // Log collector start attempt
		if err := coll.Run(ctx); err != nil {
			// Send runtime errors to the system log view
			sysChan <- fmt.Sprintf("[ERROR] Collector run failed: %v", err)
		}
		log.Printf("Collector run loop finished.") // Log collector exit
		// Optionally close channels or signal UI shutdown here if needed
	}()

	// Start the UI application event loop
	log.Printf("Starting UI...")
	if err := app.SetRoot(layout, true).SetFocus(input).Run(); err != nil {
		// Use log.Fatalf which will send to sysChan before exiting if possible,
		// otherwise prints to stderr.
		log.Fatalf("Failed to start UI: %v", err)
	}

	log.Printf("Application exiting.") // This might not always be reached if UI exits abruptly
}
