package check

import (
	"fmt"
	"net/http"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/config"
)

// checkStatus verifies the final status code and flags slow responses.
func checkStatus(site config.Site, resp *http.Response, elapsed, slow time.Duration) Result {
	ms := elapsed.Milliseconds()
	switch {
	case resp.StatusCode != site.ExpectStatus:
		return Result{site.Name, "status", Fail,
			fmt.Sprintf("got %d, want %d (%dms)", resp.StatusCode, site.ExpectStatus, ms), nil}
	case elapsed > slow:
		return Result{site.Name, "status", Warn,
			fmt.Sprintf("%d but slow: %dms (limit %dms)", resp.StatusCode, ms, slow.Milliseconds()), &ms}
	default:
		return Result{site.Name, "status", OK, fmt.Sprintf("%d in %dms", resp.StatusCode, ms), &ms}
	}
}

// checkTLS reads the certificate straight off the response; no extra
// connection is needed because net/http keeps the TLS handshake state.
func checkTLS(site config.Site, resp *http.Response, warnDays int, now time.Time) Result {
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return Result{site.Name, "tls", Fail, "not served over HTTPS", nil}
	}
	cert := resp.TLS.PeerCertificates[0] // [0] is the leaf; the rest is the chain
	days := int64(cert.NotAfter.Sub(now).Hours() / 24)
	expiry := cert.NotAfter.Format("2006-01-02") // Go's reference-date layout

	switch {
	case days < 0:
		return Result{site.Name, "tls", Fail, fmt.Sprintf("certificate EXPIRED on %s", expiry), &days}
	case days < int64(warnDays):
		return Result{site.Name, "tls", Warn, fmt.Sprintf("certificate expires in %d days (%s)", days, expiry), &days}
	default:
		return Result{site.Name, "tls", OK, fmt.Sprintf("expires in %d days (%s)", days, expiry), &days}
	}
}
