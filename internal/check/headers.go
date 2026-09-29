package check

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/MasonKimball05/go-sentinel/internal/config"
)

// minHSTSAge is 180 days, the lowest max-age most scanners accept.
const minHSTSAge = 180 * 24 * 60 * 60

var (
	maxAgeRe  = regexp.MustCompile(`(?i)max-age=(\d+)`)
	versionRe = regexp.MustCompile(`\d+\.\d+`)
)

// checkHeaders returns one result for required security headers and one
// for headers that leak server details.
func checkHeaders(site config.Site, resp *http.Response) []Result {
	h := resp.Header
	ignored := func(name string) bool {
		return slices.ContainsFunc(site.IgnoreHeaders, func(s string) bool {
			return strings.EqualFold(s, name)
		})
	}

	var problems []string
	need := func(name, why string) {
		if !ignored(name) {
			problems = append(problems, fmt.Sprintf("%s (%s)", name, why))
		}
	}

	if hsts := h.Get("Strict-Transport-Security"); hsts == "" {
		need("Strict-Transport-Security", "missing")
	} else if m := maxAgeRe.FindStringSubmatch(hsts); m == nil {
		need("Strict-Transport-Security", "no max-age")
	} else if age, _ := strconv.Atoi(m[1]); age < minHSTSAge {
		need("Strict-Transport-Security", fmt.Sprintf("max-age %d < 180 days", age))
	}

	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		need("Content-Security-Policy", "missing")
	}
	if !strings.EqualFold(h.Get("X-Content-Type-Options"), "nosniff") {
		need("X-Content-Type-Options", "should be nosniff")
	}
	// Clickjacking protection can come from either header.
	if h.Get("X-Frame-Options") == "" && !strings.Contains(csp, "frame-ancestors") {
		need("X-Frame-Options", "missing, and CSP has no frame-ancestors")
	}
	if h.Get("Referrer-Policy") == "" {
		need("Referrer-Policy", "missing")
	}

	results := make([]Result, 0, 2)
	if len(problems) == 0 {
		results = append(results, Result{site.Name, "headers", OK, "all security headers present", nil})
	} else {
		results = append(results, Result{site.Name, "headers", Warn, strings.Join(problems, "; "), nil})
	}

	// Leaky headers hand attackers your exact software versions.
	var leaks []string
	if s := h.Get("Server"); versionRe.MatchString(s) && !ignored("Server") {
		leaks = append(leaks, "Server: "+s)
	}
	if p := h.Get("X-Powered-By"); p != "" && !ignored("X-Powered-By") {
		leaks = append(leaks, "X-Powered-By: "+p)
	}
	if len(leaks) > 0 {
		results = append(results, Result{site.Name, "info-leak", Warn, strings.Join(leaks, "; "), nil})
	}
	return results
}
