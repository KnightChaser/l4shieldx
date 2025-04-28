// ui/netViewMsgFormatting.go
package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"l4shieldx/xdpcollector/utility"
)

const (
	// Column widths for fixed-width alignment
	timeColWidth     = 25
	endpointColWidth = 30
)

// services maps well-known ports to their protocol names (e.g. 443→“HTTPS”).
var services map[int]string

func init() {
	// One-time startup cost: parse /etc/services into a map.
	services = make(map[int]string)
	f, err := os.Open("/etc/services")
	if err != nil {
		// If it fails, we skip protocol names but keep logging.
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		svcName := strings.ToUpper(parts[0])
		pp := strings.Split(parts[1], "/")
		if len(pp) != 2 {
			continue
		}
		port, err := strconv.Atoi(pp[0])
		if err != nil {
			continue
		}
		services[port] = svcName
	}
}

// getService returns the uppercase service name for a port, or "".
func getService(port uint16) string {
	return services[int(port)]
}

// FormatNewViewMsg builds a fixed-width log line:
// [timestamp] [srcIP:port (PROTO)] → [dstIP:port (PROTO)]
func FormatNewViewMsg(
	timestamp uint64,
	srcIP uint32, dstIP uint32,
	srcPort uint16, dstPort uint16,
) string {
	ts := utility.ConvertBpfNanotime(timestamp)

	// Base “IP:port” strings
	src := fmt.Sprintf("%s:%d", utility.IntToIPv4(srcIP), srcPort)
	dst := fmt.Sprintf("%s:%d", utility.IntToIPv4(dstIP), dstPort)

	// Append protocol name if known
	if svc := getService(srcPort); svc != "" {
		src = fmt.Sprintf("%s (%s)", src, svc)
	}
	if svc := getService(dstPort); svc != "" {
		dst = fmt.Sprintf("%s (%s)", dst, svc)
	}

	// Fixed-width, left-aligned columns for neat CSV-like logs
	return fmt.Sprintf(
		"%-*s %-*s → %-*s",
		timeColWidth, ts,
		endpointColWidth, src,
		endpointColWidth, dst,
	)
}
