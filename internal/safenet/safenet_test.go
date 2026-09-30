package safenet

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestIsPublic(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", // loopback and private
		"169.254.169.254", // cloud metadata service
		"100.101.102.103", // Tailscale / CGNAT
		"0.0.0.0", "255.255.255.255", "224.0.0.1", "240.0.0.1",
		"192.0.2.1", "198.18.0.1",
		"::1", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", // IPv4-mapped private addresses
		"64:ff9b::a00:1", // NAT64 wrapping 10.0.0.1
		"2002:a00:1::1",  // 6to4 wrapping 10.0.0.1
		"2001:db8::1",
	}
	for _, s := range blocked {
		if IsPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "104.21.92.105", "2606:4700::6810:84e5"} {
		if !IsPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	good := map[string]string{
		"example.com":              "https://example.com/",
		"  https://Example.com/a ": "https://example.com/a",
		"http://example.com:80/":   "http://example.com:80/",
		"https://example.com#frag": "https://example.com/",
	}
	for in, want := range good {
		u, err := NormalizeURL(in)
		if err != nil || u.String() != want {
			t.Errorf("NormalizeURL(%q) = %v, %v; want %s", in, u, err, want)
		}
	}
	for _, in := range []string{
		"", "localhost", "ftp://example.com", "file:///etc/passwd", "javascript:alert(1)",
		"https://user:pass@example.com", "https://example.com:22", "https://example.com:8080",
		"http://127.0.0.1", "http://169.254.169.254/latest/meta-data", "http://[::1]/", "http://10.0.0.5",
	} {
		if _, err := NormalizeURL(in); err == nil {
			t.Errorf("NormalizeURL(%q) should be rejected", in)
		}
	}
}

// The dialer must refuse loopback even though the URL looked fine: this is the
// DNS-rebinding and redirect case, where only the connect-time check can help.
func TestTransportRefusesLoopbackAtConnectTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	client := &http.Client{Transport: Transport(2 * time.Second)}
	_, err := client.Get(srv.URL) // 127.0.0.1:<random port>
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("got %v, want ErrBlocked", err)
	}
}

func TestControlBlocksPortsAndPrivateIPs(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:443", "10.0.0.1:443", "8.8.8.8:22", "8.8.8.8:8080", "[::1]:443"} {
		if err := control("tcp", addr, nil); !errors.Is(err, ErrBlocked) {
			t.Errorf("control(%s) = %v, want ErrBlocked", addr, err)
		}
	}
	if err := control("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("public 443 should be allowed: %v", err)
	}
}

func TestRedirectLimits(t *testing.T) {
	req, _ := http.NewRequest("GET", "gopher://example.com/", nil)
	if err := CheckRedirect(req, nil); !errors.Is(err, ErrBlocked) {
		t.Errorf("non-http redirect allowed: %v", err)
	}
	ok, _ := http.NewRequest("GET", "https://example.com/", nil)
	if err := CheckRedirect(ok, make([]*http.Request, 5)); err == nil {
		t.Error("sixth redirect allowed")
	}
}

// Sanity check that the dialer really is the one doing the blocking.
func TestDialerDirectly(t *testing.T) {
	d := &net.Dialer{Timeout: time.Second, Control: control}
	if _, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:443"); !errors.Is(err, ErrBlocked) {
		t.Errorf("got %v, want ErrBlocked", err)
	}
}
