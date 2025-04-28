// ui/netViewMsgFormatting.go
package ui

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"sync"

	"l4shieldx/xdpcollector/utility"
)

const (
	timeColWidth     = 25 // width of the timestamp column
	endpointColWidth = 30 // width of each “IP:port (PROTO)” column
)

// pool holds reusable *bytes.Buffer instances
var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// services maps well-known ports → protocol name (e.g. 443 -> "HTTPS")
var services map[int]string

func init() {
	services = make(map[int]string)
	f, err := os.Open("/etc/services")
	if err != nil {
		return // skip protocol lookup if we can’t read file
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.ToUpper(fields[0])
		parts := strings.Split(fields[1], "/")
		if len(parts) != 2 {
			continue
		}
		port, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		services[port] = name
	}
}

func getService(port uint16) string {
	return services[int(port)]
}

// FormatNewViewMsg builds a fixed-width, CSV-like line with minimal allocations.
func FormatNewViewMsg(
	timestamp uint64,
	srcIP uint32, dstIP uint32,
	srcPort uint16, dstPort uint16,
) string {
	// Grab a buffer from the pool and reset it
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()

	// Convert timestamp
	ts := utility.ConvertBpfNanotime(timestamp)
	writePadded(buf, ts, timeColWidth)

	buf.WriteByte(' ') // column separator

	// Build src endpoint
	buf.WriteString(utility.IntToIPv4(srcIP))
	buf.WriteByte(':')
	buf.WriteString(strconv.Itoa(int(srcPort)))
	if svc := getService(srcPort); svc != "" {
		buf.WriteString(" (")
		buf.WriteString(svc)
		buf.WriteByte(')')
	}
	writePadding(buf, endpointColWidth-len(buf.Bytes())+len(ts)+1) // pad to endpointColWidth

	buf.WriteString("->")

	// Build dst endpoint
	buf.WriteString(utility.IntToIPv4(dstIP))
	buf.WriteByte(':')
	buf.WriteString(strconv.Itoa(int(dstPort)))
	if svc := getService(dstPort); svc != "" {
		buf.WriteString(" (")
		buf.WriteString(svc)
		buf.WriteByte(')')
	}
	writePadding(buf, endpointColWidth-buf.Len()+timeColWidth+1) // pad last column

	// Extract result string (copies once) and return buffer to pool
	result := buf.String()
	bufPool.Put(buf)
	return result
}

// writePadded writes s left-aligned in a field of width w
func writePadded(buf *bytes.Buffer, s string, w int) {
	buf.WriteString(s)
	writePadding(buf, w-len(s))
}

// writePadding writes n spaces (n ≤ 0 → no op)
func writePadding(buf *bytes.Buffer, n int) {
	for n > 0 {
		const chunk = "          " // 10 spaces
		if n >= len(chunk) {
			buf.WriteString(chunk)
			n -= len(chunk)
		} else {
			buf.WriteString(chunk[:n])
			return
		}
	}
}
