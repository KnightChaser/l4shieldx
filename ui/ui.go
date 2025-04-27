// ui/ui.go
// Package ui provides a simple terminal user interface for displaying system logs,
// network events, and allowed/denied traffic counts using the tview library.
package ui

import (
	"fmt"
	"strings"

	"l4shieldx/xdpcollector/utility"

	"github.com/rivo/tview"
)

const MaxLines = 100 // keep the last 100 entries, exported

// ChannelWriter funnels log.Printf calls into our System Log pane.
type ChannelWriter struct{ Ch chan string }

// Write implements the io.Writer interface for our channel.
func (w ChannelWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	w.Ch <- msg
	return len(p), nil
}

// SetupUI creates and configures the tview application, views, and layout.
// It returns the application, the root layout flexbox, the system log view,
// the network log view, the allowed traffic view, the denied traffic view, and the input field.
func SetupUI(sysChan chan string) (
	*tview.Application,
	*tview.Flex,
	*tview.TextView,
	*tview.TextView,
	*tview.TextView,
	*tview.TextView,
	*tview.InputField,
) {
	app := tview.NewApplication()

	sysView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetChangedFunc(func() { app.Draw() })
	sysView.SetBorder(true).SetTitle(" System Log ")

	netView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetChangedFunc(func() { app.Draw() })
	netView.SetBorder(true).SetTitle(" Network Events ")

	allowedView := tview.NewTextView().
		SetTextAlign(tview.AlignCenter).
		SetChangedFunc(func() { app.Draw() })
	allowedView.SetBorder(true).SetTitle(" Allowed traffic ")

	deniedView := tview.NewTextView().
		SetTextAlign(tview.AlignCenter).
		SetChangedFunc(func() { app.Draw() })
	deniedView.SetBorder(true).SetTitle(" Denied traffic ")

	input := tview.NewInputField().
		SetLabel("Command: ").
		SetFieldWidth(0)

	// Bottom row: allowed, denied, then input
	bottomFlex := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(allowedView, 0, 1, false).
		AddItem(deniedView, 0, 1, false).
		AddItem(input, 0, 3, true)

	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(sysView, 0, 2, false).
		AddItem(netView, 0, 4, false).
		AddItem(bottomFlex, 4, 1, true) // increased height to show two lines in allowed/denied views

	return app, layout, sysView, netView, allowedView, deniedView, input
}

// PumpTextview reads lines from a channel and updates a tview.TextView, keeping only MaxLines.
func PumpTextview(app *tview.Application, view *tview.TextView, ch <-chan string, buffer *[]string) {
	for line := range ch {
		*buffer = append(*buffer, line)
		if len(*buffer) > MaxLines {
			*buffer = (*buffer)[1:]
		}
		app.QueueUpdateDraw(func() {
			view.SetText(strings.Join(*buffer, "\n"))
			view.ScrollToEnd()
		})
	}
}

// PumpCounterView reads TrafficStat from a channel and updates the given view.
func PumpCounterView(app *tview.Application, view *tview.TextView, ch <-chan utility.TrafficStat) {
	for stat := range ch {
		app.QueueUpdateDraw(func() {
			view.SetText(fmt.Sprintf("%d Pkts\n(%d B)", stat.Pkts, stat.Bytes))
		})
	}
}

