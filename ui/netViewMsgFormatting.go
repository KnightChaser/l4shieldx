// ui/netViewMsgFormatting.go
package ui

import (
	"fmt"

	"l4shieldx/xdpcollector/utility"
)

// FormatNewViewMsg formats a new view message for the network view.
func FormatNewViewMsg(timestamp uint64,
	srcIP uint32, dstIP uint32,
	srcPort uint16, dstPort uint16) string {

	// Convert timestamp to human-readable format
	ts := utility.ConvertBpfNanotime(timestamp)

	// Format source and destination addresses
	src := fmt.Sprintf("%s:%d", utility.IntToIPv4(srcIP), dstIP)
	dst := fmt.Sprintf("%s:%d", utility.IntToIPv4(dstIP), dstPort)
	msg := fmt.Sprintf("%-25s %-21s → %-21s", ts, src, dst)

	return msg
}
