// xdpcollector/utility/time.go
package utility

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// bootTime holds the system boot time, computed once at startup.
var bootTime time.Time

// init computes the boot time when the package is initialized.
// Example: If /proc/uptime returns "12345.67 54321.21" and the current time is T,
// then bootTime = T - 12345.67 seconds.
func init() {
	var err error
	bootTime, err = getBootTime()
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize bootTime: %v", err))
	}
}

// getBootTime reads the uptime from /proc/uptime and computes the boot time.
func getBootTime() (time.Time, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}, err
	}
	parts := strings.Fields(string(data))
	if len(parts) < 1 {
		return time.Time{}, fmt.Errorf("unexpected /proc/uptime format")
	}
	uptimeSeconds, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return time.Time{}, err
	}
	now := time.Now()     // Gets the local time along with the timezone
	loc := now.Location() // Captures the current timezone
	bootTime := now.Add(-time.Duration(uptimeSeconds * float64(time.Second))).In(loc)

	log.Printf("Current time zone: %s", loc)
	log.Printf("Current time: %s", now.Format(time.RFC3339))
	log.Printf("Boot time calculated as: %s", bootTime.Format(time.RFC3339))
	return bootTime, nil
}

// ConvertBpfNanotime converts a boot-relative nanosecond timestamp (from eBPF)
// to a formatted absolute time string with nanosecond precision.
// Example: Given an eBPF timestamp value of 1638472263123456789,
// the absolute time is bootTime + 1638472263123456789 ns.
func ConvertBpfNanotime(bpfNs uint64) string {
	absoluteTime := bootTime.Add(time.Duration(bpfNs))
	return absoluteTime.Format("2006-01-02T15:04:05.000000000Z07:00")
}
