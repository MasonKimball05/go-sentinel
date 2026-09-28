# sentinel

A small Go tool that watches my deployed sites from the outside, shows the
results on a local dashboard, and pings my phone when something changes.

| Check | What it looks for |
|---|---|
| `status` | Reachable, expected HTTP status (default 200); warns if slower than `slow_ms` |
| `tls` | Certificate expiry; warns inside `tls_warn_days` |
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
