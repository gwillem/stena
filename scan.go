package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type scanCommand struct {
	Positional struct {
		MACs []scanMAC `positional-arg-name:"mac" description:"scan only these MAC addresses (12 hexadecimal digits each)"`
	} `positional-args:"yes"`
}

type scanMAC string

// UnmarshalFlag parses a compact six-byte MAC address.
func (m *scanMAC) UnmarshalFlag(value string) error {
	var address [6]byte
	if len(value) != 12 {
		return fmt.Errorf("invalid MAC address %q: expected 12 hexadecimal digits", value)
	}
	if _, err := hex.Decode(address[:], []byte(value)); err != nil {
		return fmt.Errorf("invalid MAC address %q: %w", value, err)
	}
	*m = scanMAC(strings.ToLower(value))
	return nil
}

// Execute discovers the portal and prints sessions for the requested MACs or
// unique MAC addresses in the active device's ARP cache. Sessions are saved to
// <mac>.json in the working directory. Progress is written to stderr.
func (c *scanCommand) Execute([]string) error {
	fmt.Fprintln(os.Stderr, "Finding default gateway...")
	device, gateway, err := Device()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Finding own MAC via gateway %s on %s...\n", gateway, device)

	info, err := Detect(gateway)
	if err != nil {
		return err
	}

	return c.scanSessions(device, info)
}

func (c *scanCommand) scanSessions(device string, info Info) error {
	if len(c.Positional.MACs) != 0 {
		for _, address := range c.Positional.MACs {
			mac := string(address)
			lookup(mac, info.ZoneID, mac == info.Mac)
		}
		return nil
	}

	fmt.Fprintf(os.Stderr, "Checking ARP cache on %s (own MAC %s)...\n", device, info.Mac)
	macs, err := arpMACs(device)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Checking portal sessions (ARP entries: %d)...\n", len(macs))
	var clients int
	var used int64
	seen := make(map[string]bool)
	for _, mac := range macs {
		if seen[mac] {
			continue
		}
		seen[mac] = true
		if cached, err := os.Stat(mac + ".json"); err == nil && cached.Size() == 0 {
			continue
		}
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
// <mac>.json and returns it. A MAC without a session gets an empty marker file
// and prints nothing.
func lookup(mac, zoneID string, me bool) *Session {
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
