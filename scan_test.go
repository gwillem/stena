package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

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
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				address := strings.TrimPrefix(r.URL.Path, "/api/v1/session/")
				requests[address]++
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
			if out != tt.want {
				t.Errorf("stdout: got %q, want %q", out, tt.want)
			}
			if len(requests) != len(tt.statuses) {
				t.Errorf("queried addresses: got %v, want %v", requests, tt.statuses)
			}
			for address := range tt.statuses {
				if requests[address] != 1 {
					t.Errorf("session requests for %s: got %d, want 1", address, requests[address])
				}
			}
		})
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
