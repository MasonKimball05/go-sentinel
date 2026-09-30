package check

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/config"
)

// newSite spins up a local HTTPS server running handler and returns a
// config + clients pointed at it. t.Cleanup shuts it down after the test.
func newSite(t *testing.T, handler http.HandlerFunc) (config.Config, Clients) {
	t.Helper()
	return newSiteTLS(t, handler, nil)
}

// newSiteTLS is newSite with control over the server's TLS settings.
func newSiteTLS(t *testing.T, handler http.HandlerFunc, serverTLS *tls.Config) (config.Config, Clients) {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = serverTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)

	cfg, err := config.Parse([]byte(`{"sites":[{"name":"test","url":"` + srv.URL + `"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	// srv.Client() trusts the test server's self-signed cert.
	follow := srv.Client()
	noFollow := *follow
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return cfg, Clients{Follow: follow, NoFollow: &noFollow}
}

// find returns the result for a named check, failing the test if absent.
func find(t *testing.T, results []Result, name string) Result {
	t.Helper()
	for _, r := range results {
		if r.Check == name {
			return r
		}
	}
	t.Fatalf("no %q result in %+v", name, results)
	return Result{}
}

func secureHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
}

func TestHardenedSitePasses(t *testing.T) {
	cfg, c := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		secureHeaders(w)
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("<!doctype html><p>hi</p>"))
	})

	for _, r := range RunAll(context.Background(), cfg, c) {
		if r.Status != OK {
			t.Errorf("%s: got %s (%s), want ok", r.Check, r.Status, r.Detail)
		}
	}
}

func TestMissingHeadersWarn(t *testing.T) {
	cfg, c := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=300") // too short
		w.Header().Set("Server", "nginx/1.18.0")
		w.Write([]byte("ok"))
	})

	results := RunAll(context.Background(), cfg, c)
	h := find(t, results, "headers")
	if h.Status != Warn {
		t.Fatalf("headers: got %s, want warn", h.Status)
	}
	for _, want := range []string{"max-age 300", "Content-Security-Policy", "X-Frame-Options", "Referrer-Policy"} {
		if !strings.Contains(h.Detail, want) {
			t.Errorf("headers detail %q should mention %q", h.Detail, want)
		}
	}
	if leak := find(t, results, "info-leak"); !strings.Contains(leak.Detail, "nginx/1.18.0") {
		t.Errorf("info-leak detail %q should mention the nginx version", leak.Detail)
	}
}

func TestIgnoreHeaders(t *testing.T) {
	cfg, c := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		secureHeaders(w)
		w.Header().Del("Content-Security-Policy")
		w.Header().Set("X-Frame-Options", "DENY") // CSP was covering frame-ancestors
	})
	cfg.Sites[0].IgnoreHeaders = []string{"content-security-policy"} // case-insensitive

	if h := find(t, RunAll(context.Background(), cfg, c), "headers"); h.Status != OK {
		t.Errorf("headers: got %s (%s), want ok", h.Status, h.Detail)
	}
}

func TestExposedFiles(t *testing.T) {
	cfg, c := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.Write([]byte("SECRET_KEY=hunter2\n"))
		case "/.git/HEAD":
			// Soft 404: a 200 that is really an HTML error page. Must NOT be flagged.
			w.Write([]byte("<!DOCTYPE html><h1>Not found</h1>"))
		case "/.git/config":
			// Redirect to login. The no-follow client must not treat this as a leak.
			http.Redirect(w, r, "/login", http.StatusFound)
		case "/backup.sql":
			w.Write([]byte("CREATE TABLE users"))
		default:
			w.Write([]byte("<!doctype html>login page"))
		}
	})
	cfg.Sites[0].ExtraPaths = []string{"/backup.sql"}

	r := find(t, RunAll(context.Background(), cfg, c), "exposed-files")
	if r.Status != Fail {
		t.Fatalf("got %s, want fail", r.Status)
	}
	if r.Detail != "publicly readable: /.env, /backup.sql" {
		t.Errorf("unexpected detail %q", r.Detail)
	}
}

func TestSkipPathsAreNeverRequested(t *testing.T) {
	cfg, c := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			t.Error("skipped path /.env was requested")
		}
	})
	cfg.Sites[0].SkipPaths = []string{"/.env"}

	if r := find(t, RunAll(context.Background(), cfg, c), "exposed-files"); r.Status != OK {
		t.Errorf("got %s (%s), want ok", r.Status, r.Detail)
	}
}

func TestPostQuantumKeyExchangePasses(t *testing.T) {
	// Go's TLS server supports X25519MLKEM768 by default, like Cloudflare.
	cfg, c := newSite(t, func(w http.ResponseWriter, r *http.Request) {})
	r := find(t, RunAll(context.Background(), cfg, c), "pq-tls")
	if r.Status != OK || !strings.Contains(r.Detail, "MLKEM") {
		t.Errorf("got %s (%s), want ok with an ML-KEM group", r.Status, r.Detail)
	}
}

func TestClassicalKeyExchangeWarns(t *testing.T) {
	// A server that only offers X25519, like most sites today.
	cfg, c := newSiteTLS(t, func(w http.ResponseWriter, r *http.Request) {},
		&tls.Config{CurvePreferences: []tls.CurveID{tls.X25519}})
	r := find(t, RunAll(context.Background(), cfg, c), "pq-tls")
	if r.Status != Warn || !strings.Contains(r.Detail, "X25519") {
		t.Errorf("got %s (%s), want warn naming X25519", r.Status, r.Detail)
	}
}

func TestIsPostQuantum(t *testing.T) {
	for _, g := range []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024, tls.MLKEM1024} {
		if !IsPostQuantum(g) {
			t.Errorf("%s should count as post-quantum", g)
		}
	}
	for _, g := range []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384} {
		if IsPostQuantum(g) {
			t.Errorf("%s should not count as post-quantum", g)
		}
	}
}

func TestWrongStatusFails(t *testing.T) {
	cfg, c := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	if r := find(t, RunAll(context.Background(), cfg, c), "status"); r.Status != Fail {
		t.Errorf("got %s, want fail", r.Status)
	}
}

func TestSlowWarns(t *testing.T) {
	cfg, c := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			time.Sleep(30 * time.Millisecond)
		}
	})
	cfg.SlowMs = 10
	if r := find(t, RunAll(context.Background(), cfg, c), "status"); r.Status != Warn {
		t.Errorf("got %s (%s), want warn", r.Status, r.Detail)
	}
}

func TestUnreachable(t *testing.T) {
	cfg, err := config.Parse([]byte(`{"sites":[{"name":"dead","url":"https://127.0.0.1:1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	results := RunAll(context.Background(), cfg, NewClients(time.Second))
	if len(results) != 1 || results[0].Check != "status" || results[0].Status != Fail {
		t.Errorf("got %+v, want a single status/fail", results)
	}
}
