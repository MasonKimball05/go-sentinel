// Package check runs the health and security checks against each site.
package check

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/config"
)

// Status is how bad a result is. Go has no enums; a typed int plus
// iota constants is the idiomatic stand-in.
type Status int

const (
	OK Status = iota
	Warn
	Fail
)

func (s Status) String() string {
	switch s {
	case OK:
		return "ok"
	case Warn:
		return "warn"
	default:
		return "fail"
	}
}

// MarshalText makes Status serialize as "ok"/"warn"/"fail" in -json output.
func (s Status) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText is the reverse, so JSON results can be read back in.
func (s *Status) UnmarshalText(b []byte) error {
	switch string(b) {
	case "ok":
		*s = OK
	case "warn":
		*s = Warn
	case "fail":
		*s = Fail
	default:
		return fmt.Errorf("unknown status %q", b)
	}
	return nil
}

// Result is a single check outcome for a single site.
type Result struct {
	Site   string `json:"site"`
	Check  string `json:"check"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	// Metric is the check's key number, when it has one: response time in
	// milliseconds for "status", days until certificate expiry for "tls".
	Metric *int64 `json:"metric,omitempty"`
}

// Clients holds the two HTTP clients the checks need.
type Clients struct {
	// Follow follows redirects: used for the homepage (http -> https, / -> /login).
	Follow *http.Client
	// NoFollow stops at the first response: a probe for /.env that redirects
	// to a login page must not be mistaken for a 200.
	NoFollow *http.Client
}

// NewClients builds both clients with the given timeout.
func NewClients(timeout time.Duration) Clients {
	return Clients{
		Follow: &http.Client{Timeout: timeout},
		NoFollow: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

const userAgent = "sentinel/0.1 (+https://github.com/MasonKimball05/go-sentinel)"

// RunAll checks every site concurrently and returns results in config order.
func RunAll(ctx context.Context, cfg config.Config, c Clients) []Result {
	perSite := make([][]Result, len(cfg.Sites))

	// One goroutine per site. Each writes only to its own slot in perSite,
	// so no mutex is needed; the WaitGroup just waits for all of them.
	var wg sync.WaitGroup
	for i, site := range cfg.Sites {
		wg.Go(func() {
			perSite[i] = RunSite(ctx, cfg, c, site)
		})
	}
	wg.Wait()

	var all []Result
	for _, rs := range perSite {
		all = append(all, rs...)
	}
	return all
}

// RunSite fetches the homepage once and runs every check against it,
// then probes for exposed sensitive files.
func RunSite(ctx context.Context, cfg config.Config, c Clients, site config.Site) []Result {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, site.URL, nil)
	if err != nil {
		return []Result{{site.Name, "status", Fail, "unreachable: " + err.Error(), nil}}
	}
	req.Header.Set("User-Agent", userAgent)

	start := time.Now()
	resp, err := c.Follow.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return []Result{{site.Name, "status", Fail, "unreachable: " + err.Error(), nil}}
	}
	// defer runs when RunSite returns, whichever return path we take.
	defer resp.Body.Close()
	// Drain (capped at 1 MiB) so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	results := []Result{
		checkStatus(site, resp, elapsed, cfg.SlowThreshold()),
		checkTLS(site, resp, cfg.TLSWarnDays, time.Now()),
	}
	results = append(results, checkHeaders(site, resp)...)
	results = append(results, checkExposed(ctx, c.NoFollow, site)...)
	return results
}
