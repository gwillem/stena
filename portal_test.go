package main

import (
	"testing"
	"time"
)

func TestParseRedirect(t *testing.T) {
	location := "https://captive.nowherenetworks.net/?mac=020000000001&zoneId=00000000-0000-4000-8000-000000000001&accessControllerIp=192.0.2.1"

	want := Info{Mac: "020000000001", ZoneID: "00000000-0000-4000-8000-000000000001", AccessControllerIP: "192.0.2.1"}
	info, err := parseRedirect(location)
	if err != nil {
		t.Fatal(err)
	}
	if info != want {
		t.Errorf("got %v, want %v", info, want)
	}

	if _, err := parseRedirect("https://captive.nowherenetworks.net/"); err == nil {
		t.Error("want error for missing parameters")
	}
	if _, err := parseRedirect(":not a url"); err == nil {
		t.Error("want error for invalid URL")
	}
}

func TestSessionVoucher(t *testing.T) {
	tests := []struct {
		name string
		s    Session
		want string
	}{
		{"voucher", Session{IsAuthVoucher: true, AuthVoucherCode: "TEST-VOUCHER"}, "TEST-VOUCHER"},
		{"open", Session{IsAuthOpen: true, AuthOpenKeyword: "free"}, "free"},
		{"none", Session{}, "-"},
	}

	for _, tt := range tests {
		if got := tt.s.Voucher(); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestSessionDataUsed(t *testing.T) {
	used := int64(250000000)
	s := Session{BytesUsed: &used}
	if got := s.DataUsed(); got != "0.25GB" {
		t.Errorf("got %q, want 0.25GB", got)
	}
	empty := Session{}
	if got := empty.DataUsed(); got != "-" {
		t.Errorf("got %q, want -", got)
	}
}

func TestSessionExpiry(t *testing.T) {
	tests := []struct {
		name string
		s    Session
		want string
	}{
		{"endTime", Session{EndTime: new("2030-01-02T03:04:05Z")}, formatLocal(t, "2030-01-02T03:04:05Z")},
		{"endTimePermanent", Session{EndTimePermanent: new("2030-01-01T00:00:00Z")}, formatLocal(t, "2030-01-01T00:00:00Z")},
		{"invalid", Session{EndTime: new("not a time")}, "not a time"},
		{"none", Session{}, "-"},
	}

	for _, tt := range tests {
		if got := tt.s.Expiry(); got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestSessionLine(t *testing.T) {
	online := Session{
		BytesUsed:              new(int64(250000000)),
		EndTime:                new("2030-01-02T03:04:05Z"),
		ConnectedClients:       1,
		MaxSimultaneousClients: 1,
		IsAuthVoucher:          true,
		AuthVoucherCode:        "TEST-VOUCHER",
	}
	want := "020000000001 TEST-VOUCHER 0.25GB " + formatLocal(t, "2030-01-02T03:04:05Z")
	if got := online.Line("020000000001"); got != want {
		t.Errorf("online: got %q, want %q", got, want)
	}

	offline := Session{
		BytesUsed:              new(int64(50000000)),
		EndTime:                new("2030-02-01T00:00:00Z"),
		ConnectedClients:       0,
		MaxSimultaneousClients: 1,
		IsAuthOpen:             true,
		AuthOpenKeyword:        "free",
	}
	want = "020000000002 free     0.05GB " + formatLocal(t, "2030-02-01T00:00:00Z") + " OFFLINE"
	if got := offline.Line("020000000002"); got != want {
		t.Errorf("offline: got %q, want %q", got, want)
	}
}

func TestSessionLineVoucherWidth(t *testing.T) {
	for _, tt := range []struct {
		name string
		s    Session
		want string
	}{
		{"short code", Session{IsAuthVoucher: true, AuthVoucherCode: "TEST"}, "020000000001 TEST     - -"},
		{"eight characters", Session{IsAuthVoucher: true, AuthVoucherCode: "TEST0001"}, "020000000001 TEST0001 - -"},
		{"absent", Session{}, "020000000001 -        - -"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.Line("020000000001"); got != tt.want {
				t.Errorf("session line: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSessionOffline(t *testing.T) {
	tests := []struct {
		name string
		s    Session
		want bool
	}{
		{"connected", Session{ConnectedClients: 1, MaxSimultaneousClients: 1}, false},
		{"disconnected", Session{ConnectedClients: 0, MaxSimultaneousClients: 1}, true},
		{"unknown", Session{}, false},
	}

	for _, tt := range tests {
		if got := tt.s.Offline(); got != tt.want {
			t.Errorf("%s: got %t, want %t", tt.name, got, tt.want)
		}
	}
}

func formatLocal(t *testing.T, value string) string {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed.Local().Format("2006-01-02 15:04")
}
