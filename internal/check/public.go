package check

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/config"
)

// RunPublic runs the checks for the public site checkup against a site the
// requester may not own. It is deliberately passive: it fetches the page a
// browser would and inspects the response, and never probes for sensitive
// files the way RunSite does. Probing strangers' servers for /.env is what
// attack scanners do, and it trips honeypots.
//
// The clients must come from a caller that enforces SSRF protection
// (see internal/safenet); this function trusts them.
func RunPublic(ctx context.Context, c Clients, u *url.URL, slow time.Duration, tlsWarnDays int) []Result {
	site := config.Site{Name: u.Hostname(), URL: u.String()}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, site.URL, nil)
	if err != nil {
		return []Result{{site.Name, "status", Fail, "invalid address", nil}}
	}
	req.Header.Set("User-Agent", userAgent)

	start := time.Now()
	resp, err := c.Follow.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return []Result{{site.Name, "status", Fail, "couldn't connect: " + unwrap(err), nil}}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	return append([]Result{
		publicStatus(site, resp, elapsed, slow),
		checkTLS(site, resp, tlsWarnDays, time.Now()),
		checkPQ(site, resp),
	}, checkHeaders(site, resp)...)
}

// publicStatus is lenient about the status code: an unknown site's homepage
// may legitimately answer 403 to automated clients, and that says nothing
// about its security configuration.
func publicStatus(site config.Site, resp *http.Response, elapsed, slow time.Duration) Result {
	ms := elapsed.Milliseconds()
	switch {
	case resp.StatusCode >= 400:
		return Result{site.Name, "status", Warn,
			fmt.Sprintf("HTTP %d: the site may block automated checks, so results can be partial", resp.StatusCode), &ms}
	case elapsed > slow:
		return Result{site.Name, "status", Warn, fmt.Sprintf("responded in %dms (slow)", ms), &ms}
	default:
		return Result{site.Name, "status", OK, fmt.Sprintf("HTTP %d in %dms", resp.StatusCode, ms), &ms}
	}
}

// unwrap keeps the useful tail of a *url.Error ("dial tcp ...: destination not allowed").
func unwrap(err error) string {
	if ue, ok := err.(*url.Error); ok {
		return ue.Err.Error()
	}
	return err.Error()
}
