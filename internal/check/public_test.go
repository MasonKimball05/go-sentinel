package check

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func runPublic(t *testing.T, handler http.HandlerFunc) Report {
	t.Helper()
	cfg, c := newSite(t, handler)
	u, err := url.Parse(cfg.Sites[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	return Grade(RunPublic(context.Background(), c, u, 2*time.Second, 14))
}

func TestPublicHardenedSiteGetsA(t *testing.T) {
	rep := runPublic(t, func(w http.ResponseWriter, r *http.Request) { secureHeaders(w) })
	if rep.Grade != "A" || rep.Score != 100 {
		t.Errorf("got %s (%d): %+v", rep.Grade, rep.Score, rep.Results)
	}
}

func TestPublicMissingHeadersLoseEightEach(t *testing.T) {
	// No security headers at all: 5 problems x 8 points.
	rep := runPublic(t, func(w http.ResponseWriter, r *http.Request) {})
	if rep.Score != 60 || rep.Grade != "D" {
		t.Errorf("got %s (%d), want D (60)", rep.Grade, rep.Score)
	}
	var tip string
	for _, f := range rep.Results {
		if f.Check == "headers" {
			tip = f.Tip
		}
	}
	if !strings.Contains(tip, "Cloudflare") {
		t.Errorf("headers finding should carry a fix tip, got %q", tip)
	}
}

// The public checkup must never probe for sensitive files on someone else's site.
func TestPublicIsPassive(t *testing.T) {
	runPublic(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("public checkup requested %s", r.URL.Path)
		}
	})
}

func TestPublicBlockedSiteIsPartialNotFailed(t *testing.T) {
	rep := runPublic(t, func(w http.ResponseWriter, r *http.Request) {
		secureHeaders(w)
		w.WriteHeader(http.StatusForbidden)
	})
	if rep.Grade == "?" {
		t.Error("a 403 is still a reachable site")
	}
}

func TestPublicUnreachableHasNoGrade(t *testing.T) {
	rep := Grade([]Result{{"x", "status", Fail, "couldn't connect", nil}})
	if rep.Grade != "?" || rep.Score != 0 {
		t.Errorf("got %s (%d)", rep.Grade, rep.Score)
	}
}

func TestScoreNeverNegative(t *testing.T) {
	rep := Grade([]Result{
		{"x", "status", OK, "", nil},
		{"x", "tls", Fail, "not served over HTTPS", nil},
		{"x", "pq-tls", Warn, "", nil},
		{"x", "headers", Warn, "a; b; c; d; e; f; g; h", nil},
		{"x", "info-leak", Warn, "", nil},
	})
	if rep.Score != 0 || rep.Grade != "F" {
		t.Errorf("got %s (%d), want F (0)", rep.Grade, rep.Score)
	}
}
