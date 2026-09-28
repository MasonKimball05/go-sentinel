// Command sentinel checks your deployed sites for uptime, TLS expiry,
// missing security headers, and publicly exposed sensitive files.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/alert"
	"github.com/MasonKimball05/go-sentinel/internal/check"
	"github.com/MasonKimball05/go-sentinel/internal/config"
)

func main() {
	configPath := flag.String("config", "sentinel.json", "path to config file")
	watch := flag.Duration("watch", 0, "re-run on this interval (e.g. 5m); 0 runs once")
	asJSON := flag.Bool("json", false, "print results as JSON")
	serve := flag.Bool("serve", false, "run the web dashboard instead of printing to the terminal")
	addr := flag.String("addr", "127.0.0.1:8484", "dashboard listen address (with -serve)")
	noOpen := flag.Bool("no-open", false, "don't open the dashboard in a browser (with -serve)")
	testAlert := flag.Bool("test-alert", false, "send a test notification to every alert destination and exit")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sentinel:", err)
		os.Exit(2)
	}
	alerter, err := alert.New(cfg, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sentinel:", err)
		os.Exit(2)
	}

	// ctx is cancelled on Ctrl+C (or SIGTERM from a service manager), which
	// aborts in-flight requests cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *testAlert {
		if err := alerter.Test(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "sentinel:", err)
			os.Exit(1)
		}
		return
	}

	if *serve {
		interval := *watch
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		if err := serveDashboard(ctx, cfg, alerter, *addr, interval, !*noOpen); err != nil {
			fmt.Fprintln(os.Stderr, "sentinel:", err)
			os.Exit(1)
		}
		return
	}

	clients := check.NewClients(cfg.Timeout())
	run := func() bool {
		results := check.RunAll(ctx, cfg, clients)
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(results)
		} else {
			printTable(results)
		}
		alerter.Process(ctx, results)
		for _, r := range results {
			if r.Status == check.Fail {
				return false
			}
		}
		return true
	}

	if *watch <= 0 {
		// Non-zero exit on any failure, so cron or CI can alert on it.
		if !run() {
			os.Exit(1)
		}
		return
	}

	ticker := time.NewTicker(*watch)
	defer ticker.Stop()
	for {
		fmt.Printf("\n── %s ──\n", time.Now().Format("2006-01-02 15:04:05"))
		run()
		// select waits on whichever channel is ready first.
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func printTable(results []check.Result) {
	// Align the columns without the badges, then prefix each line with its
	// badge. tabwriter counts ANSI color codes as visible width, so feeding
	// it colored badges would push the header out of line.
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SITE\tCHECK\tDETAIL")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.Site, r.Check, r.Detail)
	}
	_ = w.Flush()

	color := useColor()
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	fmt.Println("   " + lines[0])
	for i, r := range results {
		fmt.Printf("%s  %s\n", badge(r.Status, color), lines[i+1])
	}
}

func badge(s check.Status, color bool) string {
	sym, code := "✓", "32" // green
	switch s {
	case check.Warn:
		sym, code = "!", "33" // yellow
	case check.Fail:
		sym, code = "✗", "31" // red
	}
	if !color {
		return sym
	}
	return "\x1b[" + code + "m" + sym + "\x1b[0m"
}

// useColor is true only when writing to a real terminal and NO_COLOR is unset.
func useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
