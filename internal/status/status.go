// Package status builds the public summary the portfolio shows.
//
// It deliberately publishes only availability facts (up/down, response time,
// certificate expiry). Security findings such as missing headers or exposed
// files stay private: a public list of a site's weaknesses is a map for attackers.
package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/check"
	"github.com/MasonKimball05/go-sentinel/internal/config"
)

// Summary is the whole published document.
type Summary struct {
	GeneratedAt time.Time `json:"generated_at"`
	Sites       []Site    `json:"sites"`
}

// Site is one site's public status.
type Site struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Up         bool   `json:"up"`
	ResponseMs *int64 `json:"response_ms,omitempty"`
	TLSDays    *int64 `json:"tls_days_left,omitempty"`
}

// Build turns a run's results into a Summary, in config order.
func Build(cfg config.Config, results []check.Result, now time.Time) Summary {
	s := Summary{GeneratedAt: now.UTC().Truncate(time.Second), Sites: []Site{}}
	for _, site := range cfg.Sites {
		out := Site{Name: site.Name, URL: site.URL}
		for _, r := range results {
			if r.Site != site.Name {
				continue
			}
			switch r.Check {
			case "status":
				// Slow (Warn) still counts as up; only a Fail is down.
				out.Up = r.Status != check.Fail
				out.ResponseMs = r.Metric
			case "tls":
				out.TLSDays = r.Metric
			}
		}
		s.Sites = append(s.Sites, out)
	}
	return s
}

// Write saves the summary as JSON, atomically (temp file + rename).
func Write(path string, s Summary) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".status-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename succeeds
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
