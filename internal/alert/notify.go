package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/check"
)

// Message is one notification, already worded.
type Message struct {
	Title  string
	Body   string
	Urgent bool // something newly failing
	Good   bool // everything in it is a recovery
}

// Notifier delivers a Message somewhere. Anything with this method
// satisfies the interface; Go interfaces are implemented implicitly.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, m Message) error
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Ntfy posts to an ntfy.sh topic URL (https://ntfy.sh/<topic>), which
// pushes to the ntfy phone app.
type Ntfy struct{ URL string }

func (Ntfy) Name() string { return "ntfy" }

func (n Ntfy) Notify(ctx context.Context, m Message) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, strings.NewReader(m.Body))
	if err != nil {
		return err
	}
	// ntfy reads metadata from headers. Header values should be ASCII, so
	// emoji go through Tags, which ntfy renders as emoji.
	req.Header.Set("Title", m.Title)
	switch {
	case m.Urgent:
		req.Header.Set("Priority", "high")
		req.Header.Set("Tags", "rotating_light")
	case m.Good:
		req.Header.Set("Tags", "white_check_mark")
	default:
		req.Header.Set("Tags", "warning")
	}
	return send(req)
}

// Discord posts to a channel webhook URL.
type Discord struct{ URL string }

func (Discord) Name() string { return "discord" }

func (d Discord) Notify(ctx context.Context, m Message) error {
	payload, err := json.Marshal(map[string]any{
		"content": fmt.Sprintf("**%s**\n%s", m.Title, m.Body),
		// Site text can contain "@everyone"; never let it ping anyone.
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return send(req)
}

func send(req *http.Request) error {
	resp, err := httpClient.Do(req)
	if err != nil {
		// The error text includes the URL, which is a secret. Keep only the cause.
		return fmt.Errorf("request failed: %w", unwrapURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("got HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

// Format words a batch of changes as one message, so a site going down
// (several checks at once) is one buzz, not five.
func Format(changes []Change) Message {
	var m Message
	m.Good = true
	lines := make([]string, 0, len(changes))
	for _, c := range changes {
		if c.To == check.Fail {
			m.Urgent = true
		}
		if c.To != check.OK {
			m.Good = false
		}
		lines = append(lines, fmt.Sprintf("%s %s %s: %s (was %s)", symbol(c.To), c.Site, c.Check, c.Detail, c.From))
	}
	m.Body = strings.Join(lines, "\n")

	if len(changes) == 1 {
		c := changes[0]
		m.Title = fmt.Sprintf("%s %s is now %s", c.Site, c.Check, strings.ToUpper(c.To.String()))
	} else {
		m.Title = fmt.Sprintf("sentinel: %d checks changed", len(changes))
	}
	return m
}

func symbol(s check.Status) string {
	switch s {
	case check.OK:
		return "✓"
	case check.Warn:
		return "!"
	default:
		return "✗"
	}
}
