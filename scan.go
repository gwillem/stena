package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

type scanCommand struct{}

// Execute prints sessions for unique MAC addresses in the active device's ARP
// cache, followed by total active clients and traffic. Sessions are saved to
// <mac>.json in the working directory. Empty files mark missing sessions.
func (*scanCommand) Execute([]string) error {
	device, gateway, err := Device()
	if err != nil {
		return err
	}
	log.Printf("scanning device %s via gateway %s", device, gateway)

	info, err := Detect(gateway)
	if err != nil {
		return err
	}

	macs, err := arpMACs(device)
	if err != nil {
		return err
	}

	var clients int
	var used int64
	seen := make(map[string]bool)
	for _, mac := range macs {
		if seen[mac] {
			continue
		}
		seen[mac] = true
		if s := lookup(mac, info.ZoneID, mac == info.Mac); s != nil {
			clients += s.ConnectedClients
			if s.BytesUsed != nil {
				used += *s.BytesUsed
			}
		}
	}

	fmt.Printf("%d active clients, %.2fGB traffic\n", clients, float64(used)/1e9)
	return nil
}

// parseMAC converts an arp-style MAC address such as "2:0:0:0:0:1",
// whose octets are not zero-padded, to its six address bytes.
func parseMAC(s string) ([6]byte, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return [6]byte{}, fmt.Errorf("invalid MAC address %q", s)
	}

	var addr [6]byte
	for i, part := range parts {
		v, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return [6]byte{}, err
		}
		addr[i] = byte(v)
	}
	return addr, nil
}

// lookup fetches the session of a MAC address, prints it, saves it to
// <mac>.json and returns it. A MAC whose existing <mac>.json file is empty is
// known to have no session and is skipped; a MAC without a session only gets
// such an empty marker file and prints nothing. Both return nil.
func lookup(mac, zoneID string, me bool) *Session {
	if info, err := os.Stat(mac + ".json"); err == nil && info.Size() == 0 {
		return nil
	}

	body, err := FetchSession(mac, zoneID)
	if errors.Is(err, ErrNoSession) {
		if err := os.WriteFile(mac+".json", nil, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", mac, err)
		}
		return nil
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", mac, err)
		return nil
	}

	if err := os.WriteFile(mac+".json", indentedJSON(body), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", mac, err)
		return nil
	}
	return printSession(mac, me, body)
}

// printSession prints the session line for a session JSON document, with a
// "<=== ME" column when the MAC address is ours, and returns the session. It
// returns nil if the document is not valid session JSON.
func printSession(mac string, me bool, body []byte) *Session {
	var s Session
	if err := json.Unmarshal(body, &s); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", mac, err)
		return nil
	}

	line := s.Line(mac)
	if me {
		line += " <=== ME"
	}
	fmt.Println(line)
	return &s
}

func indentedJSON(body []byte) []byte {
	var buf bytes.Buffer
	if json.Indent(&buf, body, "", "  ") != nil {
		return append(body, '\n')
	}
	buf.WriteByte('\n')
	return buf.Bytes()
}
