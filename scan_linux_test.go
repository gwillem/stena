//go:build linux

package main

import (
	"slices"
	"testing"
)

func TestParseARP(t *testing.T) {
	output := `192.0.2.1 lladdr 02:00:00:00:00:01 router REACHABLE
192.0.2.2 lladdr 02:00:00:00:00:02 STALE
192.0.2.3 lladdr 02:00:00:00:00:03 REACHABLE
192.0.2.4 lladdr 02:00:00:00:00:04 PERMANENT
192.0.2.5 FAILED
224.0.0.251 lladdr 01:00:5e:00:00:fb REACHABLE
192.0.2.255 lladdr 01:00:5e:00:00:01 REACHABLE
fe80::1 lladdr 02:00:00:00:00:01 router STALE
`

	want := []string{"020000000001", "020000000002", "020000000003", "020000000004", "020000000001"}
	if got := parseARP(output); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
