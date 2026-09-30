package main

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/check"
	"github.com/MasonKimball05/go-sentinel/internal/safenet"
)

//go:embed static
var staticFiles embed.FS

// Checker grades one normalized URL. Injected so tests don't hit the network.
type Checker func(ctx context.Context, u *url.URL) check.Report

type server struct {
	check       Checker
	perIP       *limiter // per client IP
	global      *limiter // across everyone: caps outbound traffic we generate
	cache       *cache
	trustProxy  bool     // true on Cloud Run: read the client IP from X-Forwarded-For
	corsOrigins []string // sites allowed to call the API from a browser
}

type response struct {
	URL       string    `json:"url"`
	CheckedAt time.Time `json:"checked_at"`
	Cached    bool      `json:"cached"`
	check.Report
}

type apiError struct {
	Error string `json:"error"`
}

func (s *server) routes() http.Handler {
	static, _ := fs.Sub(staticFiles, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/check", s.handleCheck)
	// Cloud Run's front end reserves some paths ending in "z", /healthz among
	// them, so it never reaches the app there. /health works everywhere.
	health := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }
	mux.HandleFunc("GET /health", health)
	mux.HandleFunc("GET /healthz", health)
	return s.securityHeaders(mux)
}

func (s *server) handleCheck(w http.ResponseWriter, r *http.Request) {
	u, err := safenet.NormalizeURL(r.URL.Query().Get("url"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{err.Error()})
		return
	}
	key := u.String()

	// Cached results are free, so they don't count against the rate limit.
	if rep, at, ok := s.cache.get(key); ok {
		writeJSON(w, http.StatusOK, response{URL: key, CheckedAt: at, Cached: true, Report: rep})
		return
	}
	ip := s.clientIP(r)
	if !s.perIP.allow(ip) || !s.global.allow("*") {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, apiError{"too many checks, try again in a minute"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rep := s.check(ctx, u)
	now := time.Now().UTC()
	s.cache.put(key, rep, now)
	// Hostname only: enough to spot abuse without logging full URLs.
	log.Printf("check host=%s grade=%s ip=%s", u.Hostname(), rep.Grade, ip)
	writeJSON(w, http.StatusOK, response{URL: key, CheckedAt: now, Report: rep})
}

// clientIP returns the requester's address. Behind Cloud Run's front end the
// real client is the LAST X-Forwarded-For entry (anything earlier was supplied
// by the client and can be forged); without a proxy it's RemoteAddr.
func (s *server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// securityHeaders applies the headers this tool grades other sites on, plus
// CORS for the allowed origins (so the portfolio can call the API).
func (s *server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if origin := r.Header.Get("Origin"); origin != "" && strings.HasPrefix(r.URL.Path, "/api/") {
			for _, o := range s.corsOrigins {
				if origin == o {
					h.Set("Access-Control-Allow-Origin", origin)
					h.Set("Vary", "Origin")
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// limiter allows n events per key per window (a fixed window: simple, and
// precise enough for abuse prevention).
type limiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	counts map[string]int
	start  time.Time
	now    func() time.Time
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, counts: map[string]int{}, now: time.Now}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := l.now(); now.Sub(l.start) >= l.window {
		l.start, l.counts = now, map[string]int{} // new window; also bounds memory
	}
	if l.counts[key] >= l.n {
		return false
	}
	l.counts[key]++
	return true
}

// cache holds recent reports so repeated checks of the same site don't send
// it more traffic. Bounded: when full, it's cleared.
type cache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[string]cacheEntry
	now     func() time.Time
}

type cacheEntry struct {
	rep check.Report
	at  time.Time
}

func newCache(ttl time.Duration, max int) *cache {
	return &cache{ttl: ttl, max: max, entries: map[string]cacheEntry{}, now: time.Now}
}

func (c *cache) get(key string) (check.Report, time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || c.now().Sub(e.at) > c.ttl {
		return check.Report{}, time.Time{}, false
	}
	return e.rep, e.at, true
}

func (c *cache) put(key string, rep check.Report, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		c.entries = map[string]cacheEntry{}
	}
	c.entries[key] = cacheEntry{rep, at}
}
