// Package decoy serves the public-facing Aborro Systems website that fronts
// the relay. Every non-tunnel request lands here; the site is a plain,
// hand-maintained looking corporate page set so the host looks like an
// ordinary infrastructure company.
package decoy

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed all:site
var siteFS embed.FS

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
func Handler(customHTML []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			data, _ := siteFS.ReadFile("site/favicon.svg")
			_, _ = w.Write(data)
			return
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			data, _ := siteFS.ReadFile("site/robots.txt")
			_, _ = w.Write(data)
			return
		case "/style.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			data, _ := siteFS.ReadFile("site/style.css")
			_, _ = w.Write(data)
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
