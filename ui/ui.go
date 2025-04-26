// ui/ui.go
// Package ui provides a simple terminal user interface for displaying system logs,
// network events, and packet counts using the tview library.
package ui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
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
// the network log view, the packet count view, and the input field.
func SetupUI(sysChan chan string) (
	*tview.Application,
	*tview.Flex,
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

	cntView := tview.NewTextView().
		SetTextAlign(tview.AlignCenter).
		SetChangedFunc(func() { app.Draw() })
	cntView.SetBorder(true).SetTitle(" Packet Count ")

	input := tview.NewInputField().
		SetLabel("Command: ").
		SetFieldWidth(0)

	input.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			text := input.GetText()
			if strings.TrimSpace(text) != "" {
				sysChan <- fmt.Sprintf("[INPUT] %s", text)
			}
			input.SetText("")
			app.SetFocus(input)
		} else if key == tcell.KeyEsc {
			app.SetFocus(input)
		}
	})

	bottomFlex := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(cntView, 0, 1, false).
		AddItem(input, 0, 3, true)

	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(sysView, 0, 2, false).
		AddItem(netView, 0, 4, false).
		AddItem(bottomFlex, 3, 1, true)

	return app, layout, sysView, netView, cntView, input
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

// PumpCounterView reads integers from a channel and updates the packet count view.
func PumpCounterView(app *tview.Application, view *tview.TextView, ch <-chan int) {
	for cnt := range ch {
		app.QueueUpdateDraw(func() {
			view.SetText(fmt.Sprintf("%d", cnt))
		})
	}
}
