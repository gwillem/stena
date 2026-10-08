package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	flags "github.com/jessevdk/go-flags"
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

	want := fmt.Sprintf("020000000001 TEST-VOUCHER 0.25GB %s\n020000000002 free     0.05GB %s OFFLINE <=== ME\n",
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

func TestScanSingleMAC(t *testing.T) {
	const mac = "02000000000a"
	const zoneID = "00000000-0000-4000-8000-000000000001"
	const body = `{"bytesUsed":250000000,"connectedClients":1,"maxSimultaneousClients":1,"isAuthVoucher":true,"authVoucherCode":"TEST-VOUCHER"}`
	for _, tt := range []struct {
		name     string
		args     []string
		statuses map[string]int
		marker   bool
		want     string
	}{
		{"registered", []string{"02000000000A"}, map[string]int{mac: http.StatusOK}, false, mac + " TEST-VOUCHER 0.25GB -\n"},
		{"unregistered", []string{mac}, map[string]int{mac: http.StatusNotFound}, false, ""},
		{"registered after negative cache", []string{mac}, map[string]int{mac: http.StatusOK}, true, mac + " TEST-VOUCHER 0.25GB -\n"},
		{
			"multiple addresses",
			[]string{"02000000000A", "02000000000b", "02000000000c"},
			map[string]int{mac: http.StatusOK, "02000000000b": http.StatusNotFound, "02000000000c": http.StatusOK},
			false, mac + " TEST-VOUCHER 0.25GB -\n02000000000c TEST-VOUCHER 0.25GB -\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if tt.marker {
				if err := os.WriteFile(mac+".json", nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			requests := make(map[string]int)
			var requestsMu sync.Mutex
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				address := strings.TrimPrefix(r.URL.Path, "/api/v1/session/")
				requestsMu.Lock()
				requests[address]++
				requestsMu.Unlock()
				status, ok := tt.statuses[address]
				if r.Method != http.MethodGet || !ok {
					t.Errorf("unexpected session request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if got := r.Header.Get("X-NWN-ZONE-PUBLIC-ID"); got != zoneID {
					t.Errorf("zone ID: got %q, want %q", got, zoneID)
				}
				w.WriteHeader(status)
				if status == http.StatusOK {
					if _, err := io.WriteString(w, body); err != nil {
						t.Error(err)
					}
				}
			}))
			defer server.Close()
			oldClient := httpClient
			httpClient = server.Client()
			httpClient.Transport = sessionTestTransport{server.URL, httpClient.Transport}
			t.Cleanup(func() { httpClient = oldClient })

			var command scanCommand
			parser := flags.NewParser(&command, flags.None)
			parser.CommandHandler = func(flags.Commander, []string) error {
				return command.scanSessions("no-such-device", Info{Mac: "020000000001", ZoneID: zoneID})
			}
			var parseErr error
			out := captureStdout(t, func() {
				_, parseErr = parser.ParseArgs(tt.args)
			})
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			gotLines, wantLines := strings.Split(out, "\n"), strings.Split(tt.want, "\n")
			slices.Sort(gotLines)
			slices.Sort(wantLines)
			if !slices.Equal(gotLines, wantLines) {
				t.Errorf("stdout rows: got %q, want %q", gotLines, wantLines)
			}
			requestsMu.Lock()
			if len(requests) != len(tt.statuses) {
				t.Errorf("queried addresses: got %v, want %v", requests, tt.statuses)
			}
			for address := range tt.statuses {
				if requests[address] != 1 {
					t.Errorf("session requests for %s: got %d, want 1", address, requests[address])
				}
			}
			requestsMu.Unlock()
		})
	}
}

func TestScanWorkerPool(t *testing.T) {
	t.Chdir(t.TempDir())
	var command scanCommand
	var want strings.Builder
	for i := range 23 {
		mac := fmt.Sprintf("0200000000%02x", i)
		command.Positional.MACs = append(command.Positional.MACs, scanMAC(mac))
		if i != 5 && i != 6 && i != 7 {
			fmt.Fprintf(&want, "%s TEST-VOUCHER 0.25GB -\n", mac)
		}
	}
	command.Positional.MACs = append(command.Positional.MACs, command.Positional.MACs[0])
	want.WriteString("020000000000 TEST-VOUCHER 0.25GB -\n")
	started := make(chan struct{}, 24)
	release := make(chan struct{})
	laterResponse := make(chan struct{})
	var active, peak, requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for previous := peak.Load(); current > previous; previous = peak.Load() {
			if peak.CompareAndSwap(previous, current) {
				break
			}
		}
		started <- struct{}{}
		<-release
		if r.URL.Path == "/api/v1/session/020000000000" {
			select {
			case <-laterResponse:
			case <-r.Context().Done():
				return
			}
		}
		if r.URL.Path == "/api/v1/session/020000000014" {
			defer close(laterResponse)
		}
		switch r.URL.Path {
		case "/api/v1/session/020000000005":
			w.WriteHeader(http.StatusNotFound)
		case "/api/v1/session/020000000006":
			w.WriteHeader(http.StatusInternalServerError)
		case "/api/v1/session/020000000007":
			if _, err := io.WriteString(w, "invalid JSON"); err != nil {
				t.Error(err)
			}
		default:
			if _, err := io.WriteString(w, `{"bytesUsed":250000000,"connectedClients":1,"maxSimultaneousClients":1,"isAuthVoucher":true,"authVoucherCode":"TEST-VOUCHER"}`); err != nil {
				t.Error(err)
			}
		}
	}))
	defer server.Close()
	oldClient := httpClient
	httpClient = server.Client()
	httpClient.Timeout = 5 * time.Second
	httpClient.Transport = sessionTestTransport{server.URL, httpClient.Transport}
	t.Cleanup(func() { httpClient = oldClient })

	barrierDone := make(chan struct{})
	go func() {
		defer close(barrierDone)
		defer close(release)
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		for i := range 20 {
			select {
			case <-started:
			case <-timer.C:
				t.Errorf("only %d requests started while responses were blocked; want 20", i)
				return
			}
		}
	}()
	var scanErr error
	out := captureStdout(t, func() {
		scanErr = command.scanSessions("no-such-device", Info{Mac: "0200000000ff", ZoneID: "00000000-0000-4000-8000-000000000001"})
	})
	<-barrierDone
	if scanErr != nil {
		t.Fatal(scanErr)
	}
	if got := peak.Load(); got != 20 {
		t.Errorf("peak concurrent requests: got %d, want 20", got)
	}
	if got := requests.Load(); got != 24 {
		t.Errorf("session requests: got %d, want 24", got)
	}
	if strings.HasPrefix(out, "020000000000 ") {
		t.Error("slow first request blocked completed sessions")
	}
	gotLines, wantLines := strings.Split(out, "\n"), strings.Split(want.String(), "\n")
	slices.Sort(gotLines)
	slices.Sort(wantLines)
	if !slices.Equal(gotLines, wantLines) {
		t.Errorf("stdout rows: got %q, want %q", gotLines, wantLines)
	}
	if marker, err := os.Stat("020000000005.json"); err != nil || marker.Size() != 0 {
		t.Errorf("missing session marker: stat=%v, err=%v", marker, err)
	}
	if _, err := os.Stat("020000000006.json"); !os.IsNotExist(err) {
		t.Errorf("failed request should not create a cache file: %v", err)
	}
}

type sessionTestTransport struct {
	serverURL string
	transport http.RoundTripper
}

func (s sessionTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	target := *r.URL
	serverRequest := r.Clone(r.Context())
	serverRequest.URL = &target
	serverURL, err := url.Parse(s.serverURL)
	if err != nil {
		return nil, err
	}
	target.Scheme, target.Host = serverURL.Scheme, serverURL.Host
	return s.transport.RoundTrip(serverRequest)
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
