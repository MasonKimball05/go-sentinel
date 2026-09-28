package alert

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/check"
	"github.com/MasonKimball05/go-sentinel/internal/config"
)

// Alerter ties state tracking to delivery. Safe for concurrent use: the
// dashboard's background loop and its Run button can both call Process.
type Alerter struct {
	mu        sync.Mutex
	tracker   *Tracker
	notifiers []Notifier
	sites     map[string]bool
	log       io.Writer
}

// New loads saved state and sets up whichever notifiers are configured.
func New(cfg config.Config, log io.Writer) (*Alerter, error) {
	t, err := LoadTracker(cfg.StateFile, cfg.Alerts.ConfirmRuns)
	if err != nil {
		return nil, fmt.Errorf("load state %s: %w", cfg.StateFile, err)
	}
	a := &Alerter{tracker: t, sites: map[string]bool{}, log: log}
	for _, s := range cfg.Sites {
		a.sites[s.Name] = true
	}
	if cfg.Alerts.NtfyURL != "" {
		a.notifiers = append(a.notifiers, Ntfy{cfg.Alerts.NtfyURL})
	}
	if cfg.Alerts.DiscordWebhook != "" {
		a.notifiers = append(a.notifiers, Discord{cfg.Alerts.DiscordWebhook})
	}
	return a, nil
}

// Destinations names the configured notifiers, for display.
func (a *Alerter) Destinations() []string {
	names := make([]string, len(a.notifiers))
	for i, n := range a.notifiers {
		names[i] = n.Name()
	}
	return names
}

// Process records a run, sends one message for any changes, and saves state.
// If every notifier fails, the changes are rolled back so the next run retries.
func (a *Alerter) Process(ctx context.Context, results []check.Result) []Change {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.tracker.Prune(a.sites)
	changes := a.tracker.Observe(results, time.Now())

	if len(changes) > 0 {
		msg := Format(changes)
		fmt.Fprintf(a.log, "sentinel: %s\n%s\n", msg.Title, msg.Body)
		if len(a.notifiers) > 0 && !a.deliver(ctx, msg) {
			a.tracker.Rollback(changes)
			changes = nil
		}
	}
	if err := a.tracker.Save(); err != nil {
		fmt.Fprintln(a.log, "sentinel: save state:", err)
	}
	return changes
}

// Test sends a sample message to every notifier and reports the first error.
func (a *Alerter) Test(ctx context.Context) error {
	if len(a.notifiers) == 0 {
		return errors.New("no alert destinations configured (set alerts.ntfy_url or SENTINEL_NTFY_URL)")
	}
	msg := Message{Title: "sentinel test alert", Body: "If you can read this, alerts are working.", Good: true}
	var errs []error
	for _, n := range a.notifiers {
		if err := n.Notify(ctx, msg); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n.Name(), err))
		} else {
			fmt.Fprintf(a.log, "sentinel: test alert sent via %s\n", n.Name())
		}
	}
	return errors.Join(errs...)
}

// deliver reports whether at least one notifier succeeded.
func (a *Alerter) deliver(ctx context.Context, msg Message) bool {
	delivered := false
	for _, n := range a.notifiers {
		if err := n.Notify(ctx, msg); err != nil {
			fmt.Fprintf(a.log, "sentinel: %s alert failed: %v\n", n.Name(), err)
		} else {
			delivered = true
		}
	}
	return delivered
}

// unwrapURLError strips the URL (a secret here) from an http client error.
func unwrapURLError(err error) error {
	if ue, ok := errors.AsType[*url.Error](err); ok {
		return ue.Err
	}
	return err
}
