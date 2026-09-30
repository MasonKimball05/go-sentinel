package check

import (
	"crypto/tls"
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

// checkPQ reports whether the TLS handshake used a post-quantum key exchange.
//
// A "harvest now, decrypt later" attacker can record today's traffic and
// decrypt it once large quantum computers exist; a hybrid key exchange such
// as X25519MLKEM768 (X25519 combined with the NIST-standardized ML-KEM) keeps
// recorded sessions safe even then. Go's client offers these by default, so
// the negotiated group shows what the server supports.
func checkPQ(site config.Site, resp *http.Response) Result {
	if resp.TLS == nil {
		return Result{site.Name, "pq-tls", Warn, "not served over HTTPS", nil}
	}
	group := resp.TLS.CurveID
	if IsPostQuantum(group) {
		return Result{site.Name, "pq-tls", OK, fmt.Sprintf("post-quantum key exchange (%s)", group), nil}
	}
	return Result{site.Name, "pq-tls", Warn, fmt.Sprintf("classical key exchange only (%s)", group), nil}
}

// IsPostQuantum mirrors crypto/tls's unexported isPQKeyExchange.
func IsPostQuantum(group tls.CurveID) bool {
	switch group {
	case tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024, tls.MLKEM1024:
		return true
	default:
		return false
	}
}
