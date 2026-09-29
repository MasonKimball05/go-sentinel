package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/check"
	"github.com/MasonKimball05/go-sentinel/internal/config"
)

func ptr(v int64) *int64 { return &v }

var cfg = config.Config{Sites: []config.Site{
	{Name: "parliament", URL: "https://am-parliament.org"},
	{Name: "portfolio", URL: "https://masonkimball.dev"},
}}

func TestBuild(t *testing.T) {
	results := []check.Result{
		{Site: "parliament", Check: "status", Status: check.OK, Metric: ptr(251)},
		{Site: "parliament", Check: "tls", Status: check.OK, Metric: ptr(45)},
		{Site: "portfolio", Check: "status", Status: check.Fail, Detail: "unreachable"},
	}
	s := Build(cfg, results, time.Date(2026, 9, 29, 18, 0, 0, 0, time.UTC))

	if len(s.Sites) != 2 {
		t.Fatalf("got %d sites", len(s.Sites))
	}
	p := s.Sites[0]
	if !p.Up || *p.ResponseMs != 251 || *p.TLSDays != 45 {
		t.Errorf("parliament: %+v", p)
	}
	if s.Sites[1].Up || s.Sites[1].ResponseMs != nil {
		t.Errorf("portfolio should be down with no response time: %+v", s.Sites[1])
	}
}

func TestSlowIsStillUp(t *testing.T) {
	s := Build(cfg, []check.Result{{Site: "parliament", Check: "status", Status: check.Warn, Metric: ptr(4000)}}, time.Now())
	if !s.Sites[0].Up {
		t.Error("a slow site was reported as down")
	}
}

// The public summary must never carry security findings.
func TestSecurityFindingsAreNotPublished(t *testing.T) {
	results := []check.Result{
		{Site: "parliament", Check: "status", Status: check.OK, Metric: ptr(200)},
		{Site: "parliament", Check: "headers", Status: check.Warn, Detail: "Content-Security-Policy (missing)"},
		{Site: "parliament", Check: "exposed-files", Status: check.Fail, Detail: "publicly readable: /.env"},
	}
	data, err := json.Marshal(Build(cfg, results, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"Content-Security-Policy", ".env", "headers", "exposed"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("summary leaks %q: %s", leak, data)
		}
	}
}

func TestWriteRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	want := Build(cfg, nil, time.Date(2026, 9, 29, 18, 0, 0, 0, time.UTC))
	if err := Write(path, want); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var got Summary
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !got.GeneratedAt.Equal(want.GeneratedAt) || len(got.Sites) != 2 {
		t.Errorf("round trip: %+v", got)
	}
}
