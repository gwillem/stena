package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"
)

func TestParseMAC(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"2:0:0:0:0:1", "020000000001", true},
		{"02:00:00:00:00:02", "020000000002", true},
		{"2:0:0:0:0:a", "02000000000a", true},
		{"(incomplete)", "", false},
		{"02:00:00:00:00", "", false},
		{"02:00:00:00:00:zz", "", false},
	}

	for _, tt := range tests {
		addr, err := parseMAC(tt.in)
		got := hex.EncodeToString(addr[:])
		if tt.ok && (err != nil || got != tt.want) {
			t.Errorf("parseMAC(%q): got %q, err %v; want %q", tt.in, got, err, tt.want)
		}
		if !tt.ok && err == nil {
			t.Errorf("parseMAC(%q): got %q, want error", tt.in, got)
		}
	}
}

func TestPrintSession(t *testing.T) {
	online := []byte(`{"bytesUsed":250000000,"endTime":"2030-01-02T03:04:05Z","connectedClients":1,"maxSimultaneousClients":1,"isAuthVoucher":true,"authVoucherCode":"TEST-VOUCHER"}`)
	offline := []byte(`{"bytesUsed":50000000,"endTime":"2030-02-01T00:00:00Z","connectedClients":0,"maxSimultaneousClients":1,"isAuthOpen":true,"authOpenKeyword":"free"}`)

	var sessions []*Session
	out := captureStdout(t, func() {
		sessions = append(sessions, printSession("020000000001", false, online))
		sessions = append(sessions, printSession("020000000002", true, offline))
	})

	want := fmt.Sprintf("020000000001 TEST-VOUCHER 0.25GB %s\n020000000002 free 0.05GB %s OFFLINE <=== ME\n",
		formatLocal(t, "2030-01-02T03:04:05Z"),
		formatLocal(t, "2030-02-01T00:00:00Z"))
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}

	var clients, used int64
	for _, s := range sessions {
		if s == nil {
			t.Fatal("printSession returned nil session")
		}
		clients += int64(s.ConnectedClients)
		if s.BytesUsed != nil {
			used += *s.BytesUsed
		}
	}
	if clients != 1 {
		t.Errorf("total clients: got %d, want 1", clients)
	}
	if used != 300000000 {
		t.Errorf("total bytes: got %d, want %d", used, 300000000)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck
	os.Stdout = w
	fn()
	os.Stdout = old
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
