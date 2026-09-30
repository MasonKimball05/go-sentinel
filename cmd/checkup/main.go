// Command checkup is the public site security checkup: enter a URL, get a
// graded report on HTTPS, post-quantum TLS, security headers and version leaks.
//
// It fetches arbitrary user-supplied URLs, so every request goes through
// internal/safenet (SSRF protection) and the checks are passive only.
//
//	PORT                 listen port (default 8080; Cloud Run sets it)
//	TRUST_PROXY_HEADERS  "1" behind Cloud Run, to rate-limit by real client IP
//	CORS_ORIGINS         comma-separated origins allowed to call /api/check
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MasonKimball05/go-sentinel/internal/check"
	"github.com/MasonKimball05/go-sentinel/internal/safenet"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	const timeout = 8 * time.Second
	client := &http.Client{
		Timeout:       timeout,
		Transport:     safenet.Transport(timeout),
		CheckRedirect: safenet.CheckRedirect,
	}
	clients := check.Clients{Follow: client, NoFollow: client}

	s := &server{
		check: func(ctx context.Context, u *url.URL) check.Report {
			return check.Grade(check.RunPublic(ctx, clients, u, 3*time.Second, 14))
		},
		perIP:       newLimiter(6, time.Minute),
		global:      newLimiter(60, time.Minute),
		cache:       newCache(10*time.Minute, 500),
		trustProxy:  os.Getenv("TRUST_PROXY_HEADERS") == "1",
		corsOrigins: splitList(os.Getenv("CORS_ORIGINS")),
	}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Printf("checkup listening on :%s", port)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
