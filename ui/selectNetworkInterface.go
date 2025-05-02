// ui/selectNetworkInterface.go
package ui

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/charmbracelet/huh"
)

// SelectNetworkInterface prompts the user to select a network interface from the available ones.
func SelectNetworkInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Failed to get network interfaces: %v", err)
	}

	// Filter out interfaces that are down or loopback
	choices := []huh.Option[string]{}
	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		addrStrs := []string{}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				addrStrs = append(addrStrs, ipNet.IP.String())
			}
		}
		pretty := fmt.Sprintf("%s (%s)", iface.Name, strings.Join(addrStrs, ", "))
		choices = append(choices, huh.NewOption(pretty, iface.Name))
	}

	if len(choices) == 0 {
		log.Fatal("No valid network interfaces found.")
	}

	// Create a selection form using the huh package
	var selected string
	form := huh.NewSelect[string]().
		Title("Select a network interface").
		Options(choices...).
		Value(&selected)

	if err := form.Run(); err != nil {
		log.Fatalf("Interface selection failed: %v", err)
	}

	return selected
}
