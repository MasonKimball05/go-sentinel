// Package safenet makes outbound HTTP requests on behalf of untrusted users
// without letting them reach anything but the public internet (SSRF protection).
//
// The address check runs inside the dialer's Control hook, which sees the IP
// actually being connected to, after DNS resolution. Validating only the URL
// is not enough: a hostname can resolve to a public IP when checked and to
// 127.0.0.1 or the cloud metadata service a moment later (DNS rebinding), and
// redirects can point anywhere. Checking at connect time covers all of it.
package safenet

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrBlocked is returned when a request would reach a non-public address or port.
// The two errors below wrap it, so errors.Is(err, ErrBlocked) matches either.
var ErrBlocked = errors.New("destination not allowed")

var (
	// ErrPrivateAddress: the host resolved to (or was) a non-public IP.
	ErrPrivateAddress = fmt.Errorf("%w: not a public address", ErrBlocked)
	// ErrPort: the connection was to a port other than 80 or 443.
	ErrPort = fmt.Errorf("%w: port not allowed", ErrBlocked)
)

// Only the standard web ports: anything else would turn the checker into a port scanner.
var allowedPorts = map[string]bool{"80": true, "443": true}

// Ranges that are not the public internet. netip's IsPrivate / IsLoopback /
// IsLinkLocal* cover the common ones; these are the rest.
var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8",       // "this network"
	"100.64.0.0/10",   // carrier-grade NAT, including Tailscale
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation
	"203.0.113.0/24",  // documentation
	"240.0.0.0/4",     // reserved, including broadcast
	"64:ff9b::/96",    // NAT64: can embed any IPv4, including private ones
	"64:ff9b:1::/48",  // local-use NAT64
	"2001:db8::/32",   // documentation
	"2002::/16",       // 6to4: embeds an IPv4 address
	"100::/64",        // discard
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// IsPublic reports whether ip is a globally routable unicast address.
func IsPublic(ip netip.Addr) bool {
	ip = ip.Unmap() // ::ffff:10.0.0.1 is 10.0.0.1
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || !ip.IsGlobalUnicast() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// control runs after DNS resolution, just before each connection attempt.
func control(network, address string, _ syscall.RawConn) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return ErrBlocked
	}
	if !allowedPorts[port] {
		return fmt.Errorf("%w (%s)", ErrPort, port)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !IsPublic(ip) {
		return fmt.Errorf("%w (%s)", ErrPrivateAddress, host)
	}
	return nil
}

// Transport returns an http.Transport that can only connect to public addresses
// on ports 80 and 443. It ignores proxy environment variables on purpose.
func Transport(timeout time.Duration) *http.Transport {
	dialer := &net.Dialer{Timeout: timeout, Control: control}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		ForceAttemptHTTP2:     true,
	}
}

// CheckRedirect limits redirect chains and keeps them on http(s).
// (Where each hop connects is still enforced by the dialer.)
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return fmt.Errorf("%w: redirect to %s", ErrBlocked, req.URL.Scheme)
	}
	return nil
}

// NormalizeURL validates user input and returns a canonical URL to check.
// A bare hostname ("example.com") becomes https://example.com.
func NormalizeURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("enter a website address")
	}
	if len(raw) > 2048 {
		return nil, errors.New("that address is too long")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("that doesn't look like a website address")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("only http and https addresses can be checked")
	}
	if u.User != nil {
		return nil, errors.New("addresses with a username or password can't be checked")
	}
	host := u.Hostname()
	if host == "" || (!strings.Contains(host, ".") && !strings.Contains(host, ":")) {
		return nil, errors.New("enter a full domain, like example.com")
	}
	if p := u.Port(); p != "" && !allowedPorts[p] {
		return nil, errors.New("only the standard web ports (80 and 443) can be checked")
	}
	// Reject literal non-public IPs up front for a clear message. The dialer
	// still enforces this for hostnames and redirects.
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && !IsPublic(ip) {
		return nil, errors.New("private and internal addresses can't be checked")
	}
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}
