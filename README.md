# sentinel

A small Go tool that watches my deployed sites from the outside, shows the
results on a local dashboard, and pings my phone when something changes.

| Check | What it looks for |
|---|---|
| `status` | Reachable, expected HTTP status (default 200); warns if slower than `slow_ms` |
| `tls` | Certificate expiry; warns inside `tls_warn_days` |
| `pq-tls` | Post-quantum key exchange: passes when the handshake negotiates a hybrid ML-KEM group such as `X25519MLKEM768`; warns on classical-only (e.g. plain `X25519`) |
| `headers` | HSTS (≥180 days), CSP, `X-Content-Type-Options`, clickjacking protection, `Referrer-Policy` |
| `info-leak` | Version numbers in `Server` / `X-Powered-By` |
| `exposed-files` | Public `/.env`, `/.git/HEAD`, `/.git/config`, `/.DS_Store`, plus any `extra_paths` |

Standard library only, with no third-party dependencies.

## Run

```bash
go run .                  # one pass; exits 1 if anything fails
go run . -serve           # web dashboard at http://127.0.0.1:8484 (opens your browser)
go run . -watch 5m        # terminal mode, re-check every 5 minutes
go run . -json            # machine-readable output
go run . -test-alert      # send a test notification and exit
go run . -status-file status.json   # also write the public status summary (below)
make test                 # vet + tests
make dist                 # static binaries for Linux (amd64/arm64) and macOS
```

## Alerts

sentinel remembers each check's last status in `sentinel-state.json` and only
notifies on a **change**: a site going down, a certificate entering the warning
window, and the recovery afterwards. A failure that lasts all day is one alert,
not 48. Several checks changing in the same run arrive as one message.

**Phone push via [ntfy](https://ntfy.sh)** (free, no account):
1. Install the ntfy app and subscribe to a topic with a long random name,
   e.g. `sentinel-` followed by the output of `openssl rand -hex 12`.
   Anyone who guesses the topic can read it, so don't use a short one.
2. `export SENTINEL_NTFY_URL=https://ntfy.sh/<your-topic>`
3. `go run . -test-alert`

**Discord:** set `SENTINEL_DISCORD_WEBHOOK` to a channel webhook URL.

Both can also go in `sentinel.json` under `alerts`, but the env vars keep them
out of git. Set `alerts.confirm_runs` to `2` if one-off network blips alert you.

## Deploy (GitHub Actions)

`.github/workflows/sentinel.yml` runs a check every 30 minutes from GitHub's
servers, a genuinely outside view that keeps working while your laptop sleeps.
State is carried between runs in the Actions cache.

1. Push this repo to GitHub.
2. **Settings → Secrets and variables → Actions:** add `SENTINEL_NTFY_URL`
   (and/or `SENTINEL_DISCORD_WEBHOOK`).
3. **Actions → sentinel → Run workflow** to try it.

Scheduled workflows are free on public repos. On a private repo each run uses
about a minute of the 2,000 free minutes/month, and every 30 minutes is about
1,440 runs, which fits. Every 15 minutes would not.

## Public status

`-status-file` writes a small summary that is safe to publish: per site, up or
down, response time, days until the TLS certificate expires, and whether the
handshake was post-quantum. **Security findings are never included**: a public
list of a site's weaknesses would be a map for attackers, and a test enforces this.

The workflow's *Publish status* step uploads it to a gist, which
[masonkimball.dev](https://masonkimball.dev) reads to show live status. It's
skipped unless both are set in the repo's Actions settings:
- secret `SENTINEL_GIST_TOKEN`: a fine-grained token with only *Gists: read and write*
- variable `SENTINEL_GIST_ID`: the gist's ID

## Public site checkup (`cmd/checkup`)

A web service anyone can use: enter a URL and get an A–F grade for HTTPS,
post-quantum key exchange, security headers and version leaks, with a fix for
each problem. Try locally with `PORT=8080 go run ./cmd/checkup`.

It fetches user-supplied URLs, so it's built defensively:
- **SSRF protection at connect time** (`internal/safenet`). The dialer checks
  the IP actually being connected to, after DNS, so hostnames that resolve to
  internal addresses (`127.0.0.1.nip.io`), DNS rebinding and redirects can't
  reach loopback, private networks, cloud metadata (169.254.169.254) or
  Tailscale. Only ports 80 and 443.
- **Passive only.** It never probes other people's sites for files like `.env`.
- **Rate limited** (6 checks/min per client IP, 60/min total) with a 10-minute
  result cache, so it can't be used to flood a site.

### Deploy to Cloud Run
```bash
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com
gcloud run deploy checkup --source . --region us-central1 --allow-unauthenticated \
  --max-instances=1 --concurrency=20 --memory=256Mi --timeout=30 \
  --set-env-vars=TRUST_PROXY_HEADERS=1,CORS_ORIGINS=https://masonkimball.dev
```
`--max-instances=1` caps cost; the free tier covers far more traffic than a
portfolio tool gets. Set a budget alert in the Cloud Console anyway.

On a new project the first deploy can fail with "the default service account is
missing required IAM permissions". Grant the build role to the project's
default compute service account (its number is in the error), then wait a
couple of minutes for it to take effect:

```bash
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/run.builder" --condition=None
```

The health check is at `/health`. Cloud Run's front end reserves `/healthz`,
so that path only works when running it elsewhere.

## Config (`sentinel.json`)

```jsonc
{
  "timeout_seconds": 10,               // defaults shown
  "slow_ms": 1500,
  "tls_warn_days": 14,
  "state_file": "sentinel-state.json",
  "alerts": { "confirm_runs": 1 },     // + ntfy_url / discord_webhook, or use env vars
  "sites": [{
    "name": "parliament",
    "url": "https://am-parliament.org",
    "expect_status": 200,
    "ignore_headers": [],   // headers your host can't set
    "extra_paths": [],      // more paths that must never be public
    "skip_paths": ["/.env"] // NEVER probe these (see below)
  }]
}
```

> ⚠️ **Honeypots:** if a site bans IPs that request trap paths (Parliament
> does for `/.env` and `/.git/*`), list those paths in `skip_paths`.
> Otherwise sentinel gets the machine it runs on banned.

## Layout

```
main.go                  flags, terminal output, watch loop
serve.go                 starts the dashboard server
internal/config/         JSON loading, defaults, env overrides, validation
internal/check/          one file per check; RunAll fans out one goroutine per site
internal/status/         the public status summary (-status-file)
internal/safenet/        SSRF-safe HTTP transport for the public checkup
cmd/checkup/             the public site checkup web service
internal/alert/          state tracking (state.go), ntfy/Discord (notify.go), glue (alerter.go)
internal/web/            dashboard HTTP handlers; static/ is embedded into the binary
.github/workflows/       scheduled run on GitHub Actions
```

## Roadmap

- [x] Web dashboard (`-serve`)
- [x] Alerts on state change (ntfy, Discord), persisted state, blip filtering
- [x] Scheduled outside-in checks on GitHub Actions
- [ ] Static asset fingerprinting: flag "Cloudflare purge needed" when a known CSS/JS hash changes
- [ ] Uptime % and history chart on the dashboard
- [ ] Package as a macOS menu-bar app
