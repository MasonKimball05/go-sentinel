package check

import "strings"

// Report is a graded checkup result.
type Report struct {
	Grade   string    `json:"grade"` // A–F, or "?" when the site couldn't be reached
	Score   int       `json:"score"` // 0–100
	Results []Finding `json:"results"`
}

// Finding is a Result plus advice on fixing it.
type Finding struct {
	Check  string `json:"check"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	Tip    string `json:"tip,omitempty"`
}

// Deductions per problem. Transport security weighs most; missing headers
// add up; post-quantum is new enough to cost little.
const (
	penaltyNoHTTPS      = 40
	penaltyTLSWarn      = 10
	penaltyPerHeader    = 8
	penaltyInfoLeak     = 5
	penaltyClassicalKEX = 5
)

var tips = map[string]string{
	"tls-fail":  "Serve the site over HTTPS. Let's Encrypt certificates are free, and most hosts and CDNs (including Cloudflare) turn it on in one click.",
	"tls-warn":  "Renew the TLS certificate soon, or turn on automatic renewal.",
	"pq-tls":    "Enable hybrid post-quantum key exchange (X25519MLKEM768). Cloudflare and recent versions of nginx/OpenSSL 3.5+, Caddy and Go support it; it protects today's traffic from future quantum decryption.",
	"headers":   "Add the missing response headers in your web server or app. If your host can't set headers (e.g. GitHub Pages), a CDN can: on Cloudflare, a Response Header Transform Rule sets them without code changes.",
	"info-leak": "Hide exact software versions (e.g. nginx `server_tokens off;`, or remove X-Powered-By) so attackers can't match you to known vulnerabilities.",
	"status":    "The site responded slowly or refused the automated check; the other results may be incomplete.",
}

// Grade scores results from RunPublic.
func Grade(results []Result) Report {
	rep := Report{Score: 100}
	reachable := true
	for _, r := range results {
		f := Finding{Check: r.Check, Status: r.Status, Detail: r.Detail}
		switch {
		case r.Check == "status" && r.Status == Fail:
			reachable = false
		case r.Check == "tls" && r.Status == Fail:
			rep.Score -= penaltyNoHTTPS
			f.Tip = tips["tls-fail"]
		case r.Check == "tls" && r.Status == Warn:
			rep.Score -= penaltyTLSWarn
			f.Tip = tips["tls-warn"]
		case r.Check == "pq-tls" && r.Status != OK:
			rep.Score -= penaltyClassicalKEX
			f.Tip = tips["pq-tls"]
		case r.Check == "headers" && r.Status != OK:
			// Detail lists problems separated by "; ".
			rep.Score -= penaltyPerHeader * (strings.Count(r.Detail, ";") + 1)
			f.Tip = tips["headers"]
		case r.Check == "info-leak":
			rep.Score -= penaltyInfoLeak
			f.Tip = tips["info-leak"]
		case r.Check == "status" && r.Status == Warn:
			f.Tip = tips["status"]
		}
		rep.Results = append(rep.Results, f)
	}
	if !reachable {
		rep.Grade, rep.Score = "?", 0
		return rep
	}
	rep.Score = max(rep.Score, 0)
	switch {
	case rep.Score >= 90:
		rep.Grade = "A"
	case rep.Score >= 80:
		rep.Grade = "B"
	case rep.Score >= 70:
		rep.Grade = "C"
	case rep.Score >= 60:
		rep.Grade = "D"
	default:
		rep.Grade = "F"
	}
	return rep
}
