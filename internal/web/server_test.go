package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/config"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	// A site nothing listens on: runs finish fast with a single failure.
	cfg, err := config.Parse([]byte(`{"timeout_seconds":1,"sites":[{"name":"dead","url":"https://127.0.0.1:1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, time.Minute)
}

func TestIndexServedWithSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer(t).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>Sentinel</title>") {
		t.Fatalf("got %d, body %.80q", rec.Code, rec.Body.String())
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP = %q", csp)
	}
}

func TestRunThenStatus(t *testing.T) {
	h := newTestServer(t).Handler()

	req := httptest.NewRequest("POST", "/api/run", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("run: got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/status", nil))
	var v statusView
	if err := json.NewDecoder(rec.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if len(v.Sites) != 1 || v.Sites[0].Status.String() != "fail" || v.LastRun.IsZero() {
		t.Errorf("unexpected status: %+v", v)
	}
}

func TestCrossSiteRunRefused(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/run", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	newTestServer(t).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("got %d, want 403", rec.Code)
	}
}

// A GET (e.g. an <img src> on some other site) must never trigger a run.
func TestGetDoesNotRun(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/run", nil))
	if rec.Code == http.StatusOK || !s.snapshot().LastRun.IsZero() {
		t.Errorf("GET /api/run ran checks (status %d)", rec.Code)
	}
}
