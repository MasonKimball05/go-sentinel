// Package web serves a local dashboard for sentinel's results.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"sync"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/check"
	"github.com/MasonKimball05/go-sentinel/internal/config"
)

// The //go:embed directive compiles the static/ folder into the binary,
// so the dashboard ships as one file with nothing to install alongside it.
//
//go:embed static
var staticFiles embed.FS

// Server holds the latest results and re-checks on an interval.
type Server struct {
	cfg      config.Config
	clients  check.Clients
	interval time.Duration

	// OnResults, if set, is called after every run (sentinel uses it to send alerts).
	OnResults func(context.Context, []check.Result)
	// AlertDestinations is shown in the dashboard header, e.g. ["ntfy"].
	AlertDestinations []string

	runMu sync.Mutex // serializes runs so two never overlap

	mu      sync.RWMutex // guards the fields below
	results []check.Result
	lastRun time.Time
	running bool
}

// New builds a Server. Call Loop to start background checks.
func New(cfg config.Config, interval time.Duration) *Server {
	return &Server{cfg: cfg, clients: check.NewClients(cfg.Timeout()), interval: interval}
}

// Loop runs a check immediately, then every interval until ctx is cancelled.
func (s *Server) Loop(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		s.run(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) run(ctx context.Context) {
	s.runMu.Lock()
	defer s.runMu.Unlock()

	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	results := check.RunAll(ctx, s.cfg, s.clients)

	s.mu.Lock()
	s.results, s.lastRun, s.running = results, time.Now(), false
	s.mu.Unlock()

	if s.OnResults != nil {
		s.OnResults(ctx, results)
	}
}

// Handler returns the HTTP routes. Go 1.22+ patterns can include the method.
func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(staticFiles, "static")

	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("POST /api/run", s.handleRun)
	return securityHeaders(mux)
}

// siteView is one card on the dashboard.
type siteView struct {
	Name    string         `json:"name"`
	URL     string         `json:"url"`
	Status  check.Status   `json:"status"` // worst status across its checks
	Results []check.Result `json:"results"`
}

type statusView struct {
	Sites           []siteView `json:"sites"`
	LastRun         time.Time  `json:"last_run"`
	Running         bool       `json:"running"`
	IntervalSeconds int        `json:"interval_seconds"`
	Alerts          []string   `json:"alerts"`
}

func (s *Server) snapshot() statusView {
	s.mu.RLock()
	defer s.mu.RUnlock()

	v := statusView{
		LastRun:         s.lastRun,
		Running:         s.running,
		IntervalSeconds: int(s.interval.Seconds()),
		Alerts:          append([]string{}, s.AlertDestinations...), // never null in JSON
	}
	for _, site := range s.cfg.Sites {
		sv := siteView{Name: site.Name, URL: site.URL, Results: []check.Result{}}
		for _, r := range s.results {
			if r.Site == site.Name {
				sv.Results = append(sv.Results, r)
				sv.Status = max(sv.Status, r.Status) // OK < Warn < Fail
			}
		}
		v.Sites = append(v.Sites, sv)
	}
	return v
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.snapshot())
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	// The server only listens on localhost, but any website you visit could
	// still POST here from your browser. Browsers stamp Sec-Fetch-Site on
	// every request, so reject anything that didn't come from this page.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	s.run(r.Context())
	writeJSON(w, s.snapshot())
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// securityHeaders gives the dashboard the same headers sentinel checks for.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
