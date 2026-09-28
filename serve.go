package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/alert"
	"github.com/MasonKimball05/go-sentinel/internal/check"
	"github.com/MasonKimball05/go-sentinel/internal/config"
	"github.com/MasonKimball05/go-sentinel/internal/web"
)

// serveDashboard runs the web UI until ctx is cancelled (Ctrl+C).
func serveDashboard(ctx context.Context, cfg config.Config, alerter *alert.Alerter, addr string, interval time.Duration, openBrowser bool) error {
	// Listen first so a port conflict fails fast, before any checks start.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	url := "http://" + ln.Addr().String()

	s := web.New(cfg, interval)
	s.AlertDestinations = alerter.Destinations()
	s.OnResults = func(ctx context.Context, results []check.Result) { alerter.Process(ctx, results) }
	go s.Loop(ctx) // background checks; `go` starts a goroutine and moves on

	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	fmt.Printf("Sentinel dashboard on %s (checking every %s). Ctrl+C to quit.\n", url, interval)
	if openBrowser {
		openURL(url)
	}

	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func openURL(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start() // best effort: the URL is printed either way
}
