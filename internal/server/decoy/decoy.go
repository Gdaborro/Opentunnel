// Package decoy serves the public-facing Aborro Systems website that fronts
// the relay. Every non-tunnel request lands here; the site is a plain,
// hand-maintained looking corporate page set so the host looks like an
// ordinary infrastructure company.
package decoy

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

//go:embed all:site
var siteFS embed.FS

// IndexPage returns the home-page body (used for kill-switch 503s so the
// outage reads like any other).
func IndexPage() []byte {
	data, _ := siteFS.ReadFile("site/index.html")
	return data
}

// NotFoundPage returns the catch-all 404 body.
func NotFoundPage() []byte {
	data, _ := siteFS.ReadFile("site/404.html")
	return data
}

// pages maps clean URLs to embedded files.
var pages = map[string]string{
	"/":         "site/index.html",
	"/about":    "site/about.html",
	"/services": "site/services.html",
	"/contact":  "site/contact.html",
	"/status":   "site/status.html",
}

// Handler serves the decoy site. If customHTML is non-nil it is served for
// every path (legacy single-page decoy behaviour used by tests).
//
// Realism (pentest 2026-10-25): every response carries a Server header
// (Go's http server emits none — no real nginx/Apache/IIS site is
// headerless), and static assets carry ETag/Last-Modified/Accept-Ranges
// like every origin in the world.
func Handler(customHTML []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		if customHTML != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(customHTML)
			return
		}
		p := r.URL.Path
		if p != "/" {
			p = strings.TrimSuffix(p, "/")
		}
		switch p {
		case "/favicon.ico", "/favicon.svg":
			serveAsset(w, "site/favicon.svg", "image/svg+xml", "public, max-age=86400")
			return
		case "/robots.txt":
			serveAsset(w, "site/robots.txt", "text/plain; charset=utf-8", "")
			return
		case "/style.css":
			serveAsset(w, "site/style.css", "text/css; charset=utf-8", "public, max-age=3600")
			return
		}
		if file, ok := pages[p]; ok {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			data, _ := siteFS.ReadFile(file)
			_, _ = w.Write(data)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		data, _ := siteFS.ReadFile("site/404.html")
		_, _ = w.Write(data)
	})
}

// siteEpoch is the plausible "last deploy" timestamp for static assets.
// Embedded files carry no modtime, so the decoy presents a consistent
// one instead of Go's omission.
var siteEpoch = time.Date(2026, 8, 27, 2, 5, 0, 0, time.UTC)

// serveAsset emits an embedded file with the header shape every real
// static origin sends: ETag (content hash), Last-Modified, Accept-Ranges.
func serveAsset(w http.ResponseWriter, name, ctype, cache string) {
	data, err := siteFS.ReadFile(name)
	if err != nil {
		// Same catch-all page as every other unknown path: Go's native
		// "404 page not found" text is exactly the fingerprint the decoy
		// exists to avoid.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		nf, _ := siteFS.ReadFile("site/404.html")
		_, _ = w.Write(nf)
		return
	}
	sum := sha256.Sum256(data)
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:8])+`"`)
	w.Header().Set("Last-Modified", siteEpoch.UTC().Format(http.TimeFormat))
	w.Header().Set("Accept-Ranges", "bytes")
	if cache != "" {
		w.Header().Set("Cache-Control", cache)
	}
	_, _ = w.Write(data)
}
