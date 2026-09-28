// Package alert turns check results into notifications, but only when a
// check's status actually changes.
package alert

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/check"
)

// entry is what we remember about one site+check between runs.
type entry struct {
	Status  check.Status `json:"status"`  // most recent observed status
	Streak  int          `json:"streak"`  // consecutive runs at Status
	Alerted check.Status `json:"alerted"` // last status we told the user about
	Detail  string       `json:"detail"`
	Since   time.Time    `json:"since"` // when Status began
}

// Change is a transition worth notifying about.
type Change struct {
	Site, Check string
	From, To    check.Status
	Detail      string
}

// Tracker holds per-check state. It is not safe for concurrent use; the
// Alerter wraps it in a mutex.
type Tracker struct {
	path    string
	confirm int
	entries map[string]*entry // key: "site/check"
}

// LoadTracker reads state from path. A missing file is a fresh start, not an error.
func LoadTracker(path string, confirmRuns int) (*Tracker, error) {
	t := &Tracker{path: path, confirm: max(confirmRuns, 1), entries: map[string]*entry{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &t.entries); err != nil {
		return nil, err
	}
	return t, nil
}

func key(site, name string) string { return site + "/" + name }

// Observe records a run and returns the changes that crossed the
// confirmation threshold.
//
// A check never seen before is treated as having been OK, so a brand-new
// problem alerts once and a healthy new site stays quiet.
func (t *Tracker) Observe(results []check.Result, now time.Time) []Change {
	var changes []Change
	for _, r := range results {
		k := key(r.Site, r.Check)
		e, seen := t.entries[k]
		switch {
		case !seen:
			e = &entry{Status: r.Status, Streak: 1, Alerted: check.OK, Since: now}
			t.entries[k] = e
		case e.Status == r.Status:
			e.Streak++
		default:
			e.Status, e.Streak, e.Since = r.Status, 1, now
		}
		e.Detail = r.Detail

		if e.Streak >= t.confirm && e.Status != e.Alerted {
			changes = append(changes, Change{r.Site, r.Check, e.Alerted, e.Status, r.Detail})
			e.Alerted = e.Status
		}
	}
	return changes
}

// Rollback marks changes as not yet delivered, so the next run retries them.
func (t *Tracker) Rollback(changes []Change) {
	for _, c := range changes {
		if e, ok := t.entries[key(c.Site, c.Check)]; ok {
			e.Alerted = c.From
		}
	}
}

// Prune drops state for sites no longer in the config.
func (t *Tracker) Prune(sites map[string]bool) {
	for k := range t.entries { // deleting while ranging over a map is safe in Go
		site := k[:max(strings.LastIndex(k, "/"), 0)]
		if !sites[site] {
			delete(t.entries, k)
		}
	}
}

// Save writes state atomically: write a temp file, then rename over the
// old one, so a crash mid-write can't leave half a JSON file behind.
func (t *Tracker) Save() error {
	data, err := json.MarshalIndent(t.entries, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(t.path), ".sentinel-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), t.path)
}
