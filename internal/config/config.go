// Package config loads and validates sentinel's JSON config file.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"
)

// Config is the top-level shape of sentinel.json.
// The `json:"..."` struct tags map JSON keys onto Go fields.
type Config struct {
	TimeoutSeconds int `json:"timeout_seconds"`
	SlowMs         int `json:"slow_ms"`
	TLSWarnDays    int `json:"tls_warn_days"`
	// StateFile remembers each check's last status between runs, so alerts
	// fire on changes rather than on every run.
	StateFile string `json:"state_file"`
	Alerts    Alerts `json:"alerts"`
	Sites     []Site `json:"sites"`
}

// Alerts configures where state-change notifications go. Both URLs act as
// passwords (anyone holding one can post, and an ntfy topic can be read),
// so prefer the SENTINEL_NTFY_URL / SENTINEL_DISCORD_WEBHOOK env vars over
// committing them here.
type Alerts struct {
	NtfyURL        string `json:"ntfy_url"`
	DiscordWebhook string `json:"discord_webhook"`
	// ConfirmRuns is how many consecutive runs a new status must hold before
	// alerting. 2 filters out one-off network blips at the cost of one interval.
	ConfirmRuns int `json:"confirm_runs"`
}

// Site is one deployed app to watch.
type Site struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	ExpectStatus int    `json:"expect_status"`
	// IgnoreHeaders silences header checks the host can't satisfy
	// (e.g. GitHub Pages doesn't let you set a CSP).
	IgnoreHeaders []string `json:"ignore_headers"`
	// ExtraPaths are site-specific paths that should never be publicly readable.
	ExtraPaths []string `json:"extra_paths"`
	// SkipPaths are probes to never send, e.g. paths that are honeypots on
	// this site. Probing a honeypot gets the machine running sentinel banned.
	SkipPaths []string `json:"skip_paths"`
}

// Timeout converts the configured seconds into a time.Duration.
func (c Config) Timeout() time.Duration {
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// SlowThreshold converts the configured millisecond limit into a time.Duration.
func (c Config) SlowThreshold() time.Duration {
	return time.Duration(c.SlowMs) * time.Millisecond
}

// Load reads path, fills in defaults, and validates every site.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return Parse(data)
}

// Parse is Load without the file read, so tests can feed it bytes directly.
func Parse(data []byte) (Config, error) {
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() // a typo'd key is an error, not a silent no-op
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 10
	}
	if cfg.SlowMs <= 0 {
		cfg.SlowMs = 1500
	}
	if cfg.TLSWarnDays <= 0 {
		cfg.TLSWarnDays = 14
	}
	if cfg.StateFile == "" {
		cfg.StateFile = "sentinel-state.json"
	}
	if cfg.Alerts.ConfirmRuns <= 0 {
		cfg.Alerts.ConfirmRuns = 1
	}
	// Env vars win over the file, so CI secrets never touch the repo.
	if v := os.Getenv("SENTINEL_NTFY_URL"); v != "" {
		cfg.Alerts.NtfyURL = v
	}
	if v := os.Getenv("SENTINEL_DISCORD_WEBHOOK"); v != "" {
		cfg.Alerts.DiscordWebhook = v
	}
	for name, raw := range map[string]string{"ntfy_url": cfg.Alerts.NtfyURL, "discord_webhook": cfg.Alerts.DiscordWebhook} {
		if raw == "" {
			continue
		}
		// Don't echo the value in the error: it's a secret.
		if u, err := url.Parse(raw); err != nil || u.Scheme != "https" || u.Host == "" {
			return Config{}, fmt.Errorf("alerts.%s must be an https URL", name)
		}
	}

	if len(cfg.Sites) == 0 {
		return Config{}, fmt.Errorf("config has no sites")
	}

	// Ranging with an index (not a copy) lets us write defaults back into the slice.
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		if s.Name == "" {
			return Config{}, fmt.Errorf("site #%d is missing a name", i+1)
		}
		u, err := url.Parse(s.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return Config{}, fmt.Errorf("site %q: url must be an absolute http(s) URL, got %q", s.Name, s.URL)
		}
		if s.ExpectStatus == 0 {
			s.ExpectStatus = 200
		}
	}
	return cfg, nil
}
