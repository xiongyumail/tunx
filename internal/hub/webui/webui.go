// Package webui serves the tunx-hub panel: a single-page app built from
// web/ (npm run build) into dist/ and embedded in the binary. Paths that are
// not files fall back to index.html so the client router handles them.
package webui

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed all:dist
var dist embed.FS

// CSP allows only same-origin scripts. Inline styles are needed by Ant
// Design's CSS-in-JS; images may be data: URIs.
const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; " +
	"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// Handler serves the panel. It never serves /api paths.
func Handler() http.Handler {
	root, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	index, err := fs.ReadFile(root, "index.html")
	if err != nil {
		index = []byte("<!doctype html><title>tunx hub</title><p>The panel is not built: run <code>make -C web</code> or <code>npm run build</code> in web/.</p>")
	}
	files := http.FileServerFS(root)
	start := time.Now()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", CSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := path.Clean("/" + r.URL.Path)
		if p == "/api" || strings.HasPrefix(p, "/api/") {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(p, "/")
		if name != "" && name != "index.html" {
			if st, err := fs.Stat(root, name); err == nil && !st.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					// Vite puts a content hash in every asset name.
					h.Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					h.Set("Cache-Control", "no-cache")
				}
				files.ServeHTTP(w, r)
				return
			}
			if name == "assets" || strings.HasPrefix(name, "assets/") || path.Ext(name) != "" {
				http.NotFound(w, r)
				return
			}
		}
		h.Set("Cache-Control", "no-cache")
		h.Set("Content-Type", "text/html; charset=utf-8")
		http.ServeContent(w, r, "index.html", start, bytes.NewReader(index))
	})
}

// Mount returns a handler that sends /api/ to api and everything else to
// the panel.
func Mount(api http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/", api)
	mux.Handle("/", Handler())
	return mux
}
