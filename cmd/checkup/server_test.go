package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/check"
)

// newTestServer uses a fake checker that counts calls instead of fetching.
func newTestServer(perIP int) (*server, *int) {
	calls := 0
	s := &server{
		check: func(ctx context.Context, u *url.URL) check.Report {
			calls++
			return check.Report{Grade: "A", Score: 100}
		},
		perIP:       newLimiter(perIP, time.Minute),
		global:      newLimiter(1000, time.Minute),
		cache:       newCache(10*time.Minute, 100),
		trustProxy:  true,
		corsOrigins: []string{"https://masonkimball.dev"},
	}
	return s, &calls
}

func get(t *testing.T, h http.Handler, target string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCheckReturnsGrade(t *testing.T) {
	s, _ := newTestServer(10)
	rec := get(t, s.routes(), "/api/check?url=example.com", nil)
	var resp response
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil || rec.Code != 200 {
		t.Fatalf("code %d, err %v", rec.Code, err)
	}
	if resp.Grade != "A" || resp.URL != "https://example.com/" {
		t.Errorf("got %+v", resp)
	}
}

func TestRejectsInternalTargetsBeforeChecking(t *testing.T) {
	s, calls := newTestServer(10)
	for _, target := range []string{"http://169.254.169.254/", "http://localhost", "https://10.0.0.1", "ftp://example.com"} {
		rec := get(t, s.routes(), "/api/check?url="+url.QueryEscape(target), nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", target, rec.Code)
		}
	}
	if *calls != 0 {
		t.Errorf("checker ran %d times for rejected input", *calls)
	}
}

func TestRateLimitPerIP(t *testing.T) {
	s, _ := newTestServer(2)
	h := s.routes()
	for i, site := range []string{"a.com", "b.com", "c.com"} {
		rec := get(t, h, "/api/check?url="+site, map[string]string{"X-Forwarded-For": "203.0.113.9"})
		want := 200
		if i == 2 {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Errorf("request %d: got %d, want %d", i+1, rec.Code, want)
		}
	}
	// A different client is unaffected.
	if rec := get(t, h, "/api/check?url=d.com", map[string]string{"X-Forwarded-For": "198.51.100.7"}); rec.Code != 200 {
		t.Errorf("second client got %d", rec.Code)
	}
}

// A client can't dodge the limit by adding its own X-Forwarded-For entries:
// only the last one (appended by Cloud Run) counts.
func TestForgedForwardedForIsIgnored(t *testing.T) {
	s, _ := newTestServer(1)
	h := s.routes()
	get(t, h, "/api/check?url=a.com", map[string]string{"X-Forwarded-For": "1.1.1.1, 203.0.113.9"})
	rec := get(t, h, "/api/check?url=b.com", map[string]string{"X-Forwarded-For": "8.8.8.8, 203.0.113.9"})
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("forged prefix bypassed the limit: got %d", rec.Code)
	}
}

func TestCacheAvoidsRecheckingAndIsFree(t *testing.T) {
	s, calls := newTestServer(1)
	h := s.routes()
	hdr := map[string]string{"X-Forwarded-For": "203.0.113.9"}
	get(t, h, "/api/check?url=example.com", hdr)
	rec := get(t, h, "/api/check?url=https://EXAMPLE.com", hdr) // same site, normalized
	var resp response
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if rec.Code != 200 || !resp.Cached || *calls != 1 {
		t.Errorf("code %d cached %v calls %d", rec.Code, resp.Cached, *calls)
	}
}

func TestSecurityHeadersAndCORS(t *testing.T) {
	s, _ := newTestServer(10)
	h := s.routes()
	rec := get(t, h, "/api/check?url=example.com", map[string]string{"Origin": "https://masonkimball.dev"})
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://masonkimball.dev" {
		t.Error("allowed origin didn't get CORS")
	}
	if rec.Header().Get("Content-Security-Policy") == "" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing security headers")
	}
	rec = get(t, h, "/api/check?url=example.org", map[string]string{"Origin": "https://evil.example"})
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("unknown origin got CORS")
	}
}

func TestLimiterResetsEachWindow(t *testing.T) {
	l := newLimiter(1, time.Minute)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	if !l.allow("k") || l.allow("k") {
		t.Fatal("limit of 1 not enforced")
	}
	now = now.Add(61 * time.Second)
	if !l.allow("k") {
		t.Error("limit didn't reset after the window")
	}
}
