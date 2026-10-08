//go:build linux

package main

import (
	"encoding/hex"
	"os/exec"
	"slices"
	"strings"
)

// arpMACs returns the MAC addresses in the ARP cache of the device.
func arpMACs(device string) ([]string, error) {
	out, err := exec.Command("ip", "neigh", "show", "dev", device).Output()
	if err != nil {
		return nil, err
	}
	return parseARP(string(out)), nil
}

// parseARP extracts the MAC addresses from "ip neigh show" output such as
// "192.0.2.1 lladdr 02:00:00:00:00:01 REACHABLE". Entries without a link layer
// address, and broadcast and multicast addresses are skipped.
func parseARP(output string) []string {
	var macs []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		i := slices.Index(fields, "lladdr")
		if i < 0 || i+1 >= len(fields) {
			continue
		}

		addr, err := parseMAC(fields[i+1])
		if err != nil || addr[0]&1 == 1 {
			continue
		}
		macs = append(macs, hex.EncodeToString(addr[:]))
	}
	return macs
}
