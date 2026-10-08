package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libp2p/go-netroute"
)

const (
	baseURL   = "https://captive.nowherenetworks.net"
	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// redirectClient does not follow redirects; the Location header of the first
// response is the interesting part.
var redirectClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Timeout: 15 * time.Second,
}

// probeIP is the destination of the routing table lookups; no traffic is ever
// sent to it.
var probeIP = net.IPv4(8, 8, 8, 8)

// Device returns the network device that carries the default route and that
// route's gateway, e.g. en0 for Wi-Fi or an Ethernet adapter. A point-to-point
// default route, such as a VPN tunnel, has no gateway; the first interface
// whose own default route has a gateway is used instead.
func Device() (string, net.IP, error) {
	router, err := netroute.New()
	if err != nil {
		return "", nil, err
	}

	iface, gateway, _, err := router.Route(probeIP)
	if err == nil && gateway != nil && iface != nil {
		return iface.Name, gateway, nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", nil, err
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}

		src := interfaceIPv4(ifi)
		if src == nil {
			continue
		}

		iface, gateway, _, err := router.RouteWithSrc(nil, src, probeIP)
		if err != nil || gateway == nil || iface == nil {
			continue
		}
		return iface.Name, gateway, nil
	}
	return "", nil, errors.New("no network device with a default gateway found")
}

// interfaceIPv4 returns the first IPv4 address of the interface.
func interfaceIPv4(ifi net.Interface) net.IP {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip := ipnet.IP.To4(); ip != nil {
				return ip
			}
		}
	}
	return nil
}

// Info describes the captive portal that a CoovaChilli gateway redirects to.
type Info struct {
	Mac                string
	ZoneID             string
	AccessControllerIP string
}

// Detect requests http://<gateway> and extracts the portal info from the
// redirect Location header that a CoovaChilli gateway answers with.
func Detect(gateway net.IP) (Info, error) {
	resp, err := redirectClient.Get("http://" + gateway.String())
	if err != nil {
		return Info{}, fmt.Errorf("query gateway %s: %w", gateway, err)
	}
	resp.Body.Close() //nolint:errcheck

	info, err := parseRedirect(resp.Header.Get("Location"))
	if err != nil {
		return Info{}, fmt.Errorf("gateway %s does not seem to be a CoovaChilli captive portal: %w", gateway, err)
	}
	return info, nil
}

// parseRedirect extracts the portal info from a chilli redirect Location
// header such as
// "https://captive.nowherenetworks.net/?mac=<mac>&zoneId=<uuid>&accessControllerIp=<ip>".
func parseRedirect(location string) (Info, error) {
	u, err := url.Parse(location)
	if err != nil {
		return Info{}, err
	}

	query := u.Query()
	info := Info{
		Mac:                query.Get("mac"),
		ZoneID:             query.Get("zoneId"),
		AccessControllerIP: query.Get("accessControllerIp"),
	}
	if info.Mac == "" || info.ZoneID == "" || info.AccessControllerIP == "" {
		return Info{}, errors.New("missing mac, zoneId or accessControllerIp parameter")
	}
	return info, nil
}

// ErrNoSession reports that a MAC address has no portal session.
var ErrNoSession = errors.New("no session")

// FetchSession returns the session JSON document of a MAC address.
func FetchSession(mac, zoneID string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/session/"+mac, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-NWN-ZONE-PUBLIC-ID", zoneID)
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusNotFound:
		return nil, ErrNoSession
	default:
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
}

// Session is a captive portal session.
type Session struct {
	BytesUsed              *int64  `json:"bytesUsed"`
	EndTime                *string `json:"endTime"`
	EndTimePermanent       *string `json:"endTimePermanent"`
	ConnectedClients       int     `json:"connectedClients"`
	MaxSimultaneousClients int     `json:"maxSimultaneousClients"`
	IsAuthVoucher          bool    `json:"isAuthVoucher"`
	AuthVoucherCode        string  `json:"authVoucherCode"`
	IsAuthOpen             bool    `json:"isAuthOpen"`
	AuthOpenKeyword        string  `json:"authOpenKeyword"`
}

// Offline reports whether fewer clients are connected than the session
// allows.
func (s *Session) Offline() bool {
	return s.ConnectedClients < s.MaxSimultaneousClients
}

// Voucher returns the voucher code or open-access keyword, or "-" if absent.
func (s *Session) Voucher() string {
	switch {
	case s.IsAuthVoucher:
		return s.AuthVoucherCode
	case s.IsAuthOpen:
		return s.AuthOpenKeyword
	}
	return "-"
}

// DataUsed formats usage in decimal gigabytes, or "-" if unavailable.
func (s *Session) DataUsed() string {
	if s.BytesUsed == nil {
		return "-"
	}
	return fmt.Sprintf("%.2fGB", float64(*s.BytesUsed)/1e9)
}

// Expiry formats the session end time in local time, or "-" if unavailable.
func (s *Session) Expiry() string {
	end := s.EndTime
	if end == nil {
		end = s.EndTimePermanent
	}
	if end == nil {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, *end)
	if err != nil {
		return *end
	}
	return t.Local().Format("2006-01-02 15:04")
}

// Line returns a one-line summary of the session for a MAC address, with an
// "OFFLINE" marker when fewer clients are connected than the session allows.
func (s *Session) Line(mac string) string {
	line := fmt.Sprintf("%s %s %s %s", mac, s.Voucher(), s.DataUsed(), s.Expiry())
	if s.Offline() {
		line += " OFFLINE"
	}
	return line
}

// ErrVoucherInUse reports that the voucher is already active on another
// client.
var ErrVoucherInUse = errors.New("voucher is in use on another client")

type voucherAuth struct {
	Mac          string `json:"mac"`
	Voucher      string `json:"voucher"`
	LogoutOldest bool   `json:"logoutOldest"`
}

// Login authenticates the MAC address with a voucher code on the portal.
// When the voucher is already active on another client, ErrVoucherInUse is
// returned unless logoutOldest is set.
func Login(mac, zoneID, code string, logoutOldest bool) error {
	body, err := json.Marshal(voucherAuth{Mac: mac, Voucher: strings.ToUpper(code), LogoutOldest: logoutOldest})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/voucher/auth", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NWN-ZONE-PUBLIC-ID", zoneID)
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusMultipleChoices:
		return ErrVoucherInUse
	case resp.StatusCode == http.StatusNotFound:
		return errors.New("voucher not found")
	default:
		return responseError(resp)
	}
}

// responseError returns an error with the status code and body of a response.
func responseError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

// TriggerAuth asks the access controller to re-check the auth state of this
// client, which completes the login.
func TriggerAuth(accessControllerIP string) error {
	resp, err := httpClient.Get("http://" + accessControllerIP + "/auth?captiveStep=3&retryCount=0")
	if err != nil {
		return err
	}
	resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return nil
	}
	return fmt.Errorf("access controller returned HTTP %d", resp.StatusCode)
}
