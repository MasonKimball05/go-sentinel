package check

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/MasonKimball05/go-sentinel/internal/config"
)

// probe is a path that should never be public, plus a test that tells a
// real leak apart from a "soft 404" (a 200 that renders an HTML error page).
type probe struct {
	path   string
	leaked func(body []byte) bool
}

var defaultProbes = []probe{
	{"/.env", func(b []byte) bool { return !looksLikeHTML(b) && bytes.Contains(b, []byte("=")) }},
	{"/.git/HEAD", func(b []byte) bool { return bytes.HasPrefix(b, []byte("ref: ")) }},
	{"/.git/config", func(b []byte) bool { return bytes.Contains(b, []byte("[core]")) }},
	// macOS Finder metadata: lists every filename in the directory.
	{"/.DS_Store", func(b []byte) bool { return bytes.HasPrefix(b, []byte("\x00\x00\x00\x01Bud1")) }},
}

func looksLikeHTML(b []byte) bool {
	head := strings.ToLower(string(bytes.TrimSpace(b[:min(len(b), 512)])))
	return strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html")
}

// checkExposed probes each sensitive path and returns one summary result.
func checkExposed(ctx context.Context, client *http.Client, site config.Site) []Result {
	base, err := url.Parse(site.URL)
	if err != nil {
		return []Result{{site.Name, "exposed-files", Fail, err.Error()}}
	}

	var probes []probe
	for _, p := range defaultProbes {
		if !slices.Contains(site.SkipPaths, p.path) {
			probes = append(probes, p)
		}
	}
	for _, p := range site.ExtraPaths {
		// Site-specific paths get a generic test: any non-HTML 200 is a leak.
		probes = append(probes, probe{p, func(b []byte) bool { return !looksLikeHTML(b) }})
	}
	if len(probes) == 0 {
		return []Result{{site.Name, "exposed-files", OK, "all probes skipped by config"}}
	}

	var leaks, errs []string
	for _, p := range probes {
		target := base.ResolveReference(&url.URL{Path: p.path}).String()
		leaked, err := probeOne(ctx, client, target, p)
		switch {
		case err != nil:
			errs = append(errs, fmt.Sprintf("%s: %v", p.path, err))
		case leaked:
			leaks = append(leaks, p.path)
		}
	}

	switch {
	case len(leaks) > 0:
		return []Result{{site.Name, "exposed-files", Fail, "publicly readable: " + strings.Join(leaks, ", ")}}
	case len(errs) > 0:
		return []Result{{site.Name, "exposed-files", Warn, "could not probe " + strings.Join(errs, "; ")}}
	default:
		return []Result{{site.Name, "exposed-files", OK, fmt.Sprintf("%d sensitive path(s) not exposed", len(probes))}}
	}
}

func probeOne(ctx context.Context, client *http.Client, target string, p probe) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return false, err
	}
	return p.leaked(body), nil
}
