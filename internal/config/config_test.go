package config

import (
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`{"sites":[{"name":"a","url":"https://example.com"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TimeoutSeconds != 10 || cfg.SlowMs != 1500 || cfg.TLSWarnDays != 14 {
		t.Errorf("defaults not applied: %+v", cfg)
	}
	if cfg.Sites[0].ExpectStatus != 200 {
		t.Errorf("expect_status default: got %d", cfg.Sites[0].ExpectStatus)
	}
}

// Table-driven tests are the standard Go pattern: one loop, many cases.
func TestInvalid(t *testing.T) {
	cases := map[string]string{
		"no sites":       `{"sites":[]}`,
		"missing name":   `{"sites":[{"url":"https://example.com"}]}`,
		"relative url":   `{"sites":[{"name":"a","url":"example.com"}]}`,
		"ftp url":        `{"sites":[{"name":"a","url":"ftp://example.com"}]}`,
		"typo'd key":     `{"sites":[{"name":"a","url":"https://example.com","expect_stauts":200}]}`,
		"malformed json": `{"sites":`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestAlertEnvOverridesFile(t *testing.T) {
	t.Setenv("SENTINEL_NTFY_URL", "https://ntfy.sh/from-env")
	cfg, err := Parse([]byte(`{"alerts":{"ntfy_url":"https://ntfy.sh/from-file"},"sites":[{"name":"a","url":"https://example.com"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Alerts.NtfyURL != "https://ntfy.sh/from-env" {
		t.Errorf("got %q", cfg.Alerts.NtfyURL)
	}
}

func TestAlertURLMustBeHTTPSAndIsNotEchoed(t *testing.T) {
	_, err := Parse([]byte(`{"alerts":{"discord_webhook":"http://discord.com/api/webhooks/secret-token"},"sites":[{"name":"a","url":"https://example.com"}]}`))
	if err == nil {
		t.Fatal("plain http webhook accepted")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Errorf("error echoes the secret: %v", err)
	}
}
