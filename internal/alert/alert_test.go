package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/check"
	"github.com/MasonKimball05/go-sentinel/internal/config"
)

func res(st check.Status) []check.Result {
	return []check.Result{{Site: "site", Check: "status", Status: st, Detail: "d"}}
}

func newTracker(t *testing.T, confirm int) *Tracker {
	t.Helper()
	tr, err := LoadTracker(filepath.Join(t.TempDir(), "state.json"), confirm)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestObserveTransitions(t *testing.T) {
	tr := newTracker(t, 1)
	now := time.Now()

	// Each step: the status observed, and the change we expect (or none).
	steps := []struct {
		in   check.Status
		want string // "from->to", or "" for no alert
	}{
		{check.OK, ""},             // healthy new check: quiet
		{check.OK, ""},             // unchanged
		{check.Fail, "ok->fail"},   // goes down
		{check.Fail, ""},           // still down: don't nag
		{check.Warn, "fail->warn"}, // partially recovers
		{check.OK, "warn->ok"},     // fully recovers
	}
	for i, s := range steps {
		changes := tr.Observe(res(s.in), now)
		got := ""
		if len(changes) == 1 {
			got = changes[0].From.String() + "->" + changes[0].To.String()
		}
		if got != s.want || len(changes) > 1 {
			t.Errorf("step %d (%s): got %q, want %q", i, s.in, got, s.want)
		}
	}
}

func TestNewProblemAlertsOnFirstSight(t *testing.T) {
	if c := newTracker(t, 1).Observe(res(check.Warn), time.Now()); len(c) != 1 || c[0].From != check.OK {
		t.Errorf("got %+v, want one ok->warn change", c)
	}
}

func TestConfirmRunsFiltersBlips(t *testing.T) {
	tr := newTracker(t, 2)
	now := time.Now()
	tr.Observe(res(check.OK), now)

	if c := tr.Observe(res(check.Fail), now); len(c) != 0 {
		t.Fatalf("alerted after 1 failing run with confirm_runs=2: %+v", c)
	}
	if c := tr.Observe(res(check.OK), now); len(c) != 0 {
		t.Fatalf("a blip that recovered should never alert: %+v", c)
	}
	tr.Observe(res(check.Fail), now)
	if c := tr.Observe(res(check.Fail), now); len(c) != 1 {
		t.Fatalf("want an alert after 2 failing runs, got %+v", c)
	}
}

func TestRollbackRetriesNextRun(t *testing.T) {
	tr := newTracker(t, 1)
	c := tr.Observe(res(check.Fail), time.Now())
	tr.Rollback(c)
	if again := tr.Observe(res(check.Fail), time.Now()); len(again) != 1 {
		t.Errorf("rolled-back change should re-alert, got %+v", again)
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	tr, _ := LoadTracker(path, 1)
	tr.Observe(res(check.Fail), time.Now())
	if err := tr.Save(); err != nil {
		t.Fatal(err)
	}

	// A new process (e.g. the next cron run) must not re-alert the same failure.
	tr2, err := LoadTracker(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	if c := tr2.Observe(res(check.Fail), time.Now()); len(c) != 0 {
		t.Errorf("re-alerted after restart: %+v", c)
	}
}

func TestPruneRemovedSites(t *testing.T) {
	tr := newTracker(t, 1)
	tr.Observe([]check.Result{
		{Site: "keep", Check: "status"},
		{Site: "gone", Check: "status"},
	}, time.Now())
	tr.Prune(map[string]bool{"keep": true})
	if _, ok := tr.entries["gone/status"]; ok {
		t.Error("state for removed site was kept")
	}
	if _, ok := tr.entries["keep/status"]; !ok {
		t.Error("state for configured site was dropped")
	}
}

func TestFormat(t *testing.T) {
	m := Format([]Change{{"parliament", "status", check.OK, check.Fail, "got 502"}})
	if m.Title != "parliament status is now FAIL" || !m.Urgent || m.Good {
		t.Errorf("single change: %+v", m)
	}
	m = Format([]Change{
		{"a", "status", check.Fail, check.OK, "200"},
		{"a", "tls", check.Warn, check.OK, "fine"},
	})
	if !m.Good || m.Urgent || !strings.Contains(m.Title, "2 checks") {
		t.Errorf("recovery batch: %+v", m)
	}
}

// capture is a fake webhook endpoint that records what it receives.
func capture(t *testing.T, status int) (*httptest.Server, *http.Request, *[]byte) {
	t.Helper()
	var got http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &got, &body
}

func TestNtfyRequest(t *testing.T) {
	srv, req, body := capture(t, 200)
	err := Ntfy{srv.URL + "/topic"}.Notify(context.Background(), Message{Title: "T", Body: "B", Urgent: true})
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Title") != "T" || req.Header.Get("Priority") != "high" || string(*body) != "B" {
		t.Errorf("headers %v body %q", req.Header, *body)
	}
}

func TestDiscordBlocksMentions(t *testing.T) {
	srv, _, body := capture(t, 204)
	err := Discord{srv.URL}.Notify(context.Background(), Message{Title: "T", Body: "@everyone"})
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		AllowedMentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
	}
	if err := json.Unmarshal(*body, &p); err != nil || p.AllowedMentions.Parse == nil || len(p.AllowedMentions.Parse) != 0 {
		t.Errorf("allowed_mentions not locked down: %s", *body)
	}
}

func TestErrorsDoNotLeakURL(t *testing.T) {
	secret := "https://127.0.0.1:1/super-secret-topic"
	err := Ntfy{secret}.Notify(context.Background(), Message{})
	if err == nil || strings.Contains(err.Error(), "super-secret-topic") {
		t.Errorf("error leaks the URL: %v", err)
	}
}

func TestProcessRollsBackWhenDeliveryFails(t *testing.T) {
	srv, _, _ := capture(t, 500)
	cfg := config.Config{StateFile: filepath.Join(t.TempDir(), "s.json"), Sites: []config.Site{{Name: "site"}}}
	a, err := New(cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	a.notifiers = []Notifier{Ntfy{srv.URL}}

	if c := a.Process(context.Background(), res(check.Fail)); len(c) != 0 {
		t.Errorf("reported %d delivered changes despite a 500", len(c))
	}
	a.notifiers = nil // "delivery" now trivially succeeds
	if c := a.Process(context.Background(), res(check.Fail)); len(c) != 1 {
		t.Errorf("undelivered failure was not retried: %+v", c)
	}
}
