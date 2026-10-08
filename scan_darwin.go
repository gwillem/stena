//go:build darwin

package main

import (
	"encoding/hex"
	"os/exec"
	"slices"
	"strings"
)

// arpMACs returns the MAC addresses in the ARP cache of the device.
func arpMACs(device string) ([]string, error) {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil, err
	}
	return parseARP(string(out), device), nil
}

// parseARP extracts the MAC addresses from "arp -a" output such as
// "? (192.0.2.1) at 2:0:0:0:0:1 on en0 ifscope [ethernet]". Entries on
// other interfaces, and broadcast and multicast addresses are skipped.
func parseARP(output, device string) []string {
	var macs []string
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		at := slices.Index(fields, "at")
		on := slices.Index(fields, "on")
		if at < 0 || on < 0 || at+1 >= len(fields) || on+1 >= len(fields) {
			continue
		}
		if fields[on+1] != device {
			continue
		}

		addr, err := parseMAC(fields[at+1])
		if err != nil || addr[0]&1 == 1 {
			continue
		}
		macs = append(macs, hex.EncodeToString(addr[:]))
	}
	return macs
}
