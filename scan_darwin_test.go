//go:build darwin

package main

import (
	"slices"
	"testing"
)

func TestParseARP(t *testing.T) {
	output := `? (192.0.2.1) at 2:0:0:0:0:1 on en0 ifscope [ethernet]
? (192.0.2.2) at 2:0:0:0:0:2 on en0 ifscope [ethernet]
? (192.0.2.3) at 2:0:0:0:0:3 on en0 ifscope permanent [ethernet]
? (192.0.2.4) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (192.0.2.255) at 1:0:5e:0:0:1 on en0 ifscope [ethernet]
? (198.51.100.1) at 2:0:0:0:1:1 on bridge100 ifscope permanent [bridge]
? (198.51.100.2) at 2:0:0:0:1:2 on bridge100 ifscope [bridge]
`

	want := []string{"020000000001", "020000000002", "020000000003"}
	if got := parseARP(output, "en0"); !slices.Equal(got, want) {
		t.Errorf("en0: got %v, want %v", got, want)
	}

	bridge := []string{"020000000101", "020000000102"}
	if got := parseARP(output, "bridge100"); !slices.Equal(got, bridge) {
		t.Errorf("bridge100: got %v, want %v", got, bridge)
	}
}
