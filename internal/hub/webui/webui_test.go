package webui

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, h http.Handler, method, path string) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Result()
}

func body(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestIndexAndFallback(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "api:"+r.URL.Path) })
	h := Mount(api)
	for _, p := range []string{"/", "/overview", "/nodes", "/settings/tokens", "/index.html"} {
		r := get(t, h, "GET", p)
		b := body(t, r)
		if r.StatusCode != 200 || !strings.Contains(b, `<div id="app">`) {
			t.Errorf("%s: status %d, body %.80q", p, r.StatusCode, b)
		}
		if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: CSP %q", p, csp)
		}
		if r.Header.Get("Cache-Control") != "no-cache" || r.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: headers %v", p, r.Header)
		}
	}
	if b := body(t, get(t, h, "GET", "/api/nodes")); b != "api:/api/nodes" {
		t.Errorf("api not mounted: %q", b)
	}
	if r := get(t, h, "POST", "/overview"); r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", r.StatusCode)
	}
	for _, p := range []string{"/assets/missing.js", "/missing.png", "/assets/"} {
		if r := get(t, h, "GET", p); r.StatusCode != 404 {
			t.Errorf("%s: %d, want 404", p, r.StatusCode)
		}
	}
	if r := get(t, Handler(), "GET", "/api/whatever"); r.StatusCode != 404 {
		t.Errorf("Handler served /api: %d", r.StatusCode)
	}
}

func TestAssets(t *testing.T) {
	assets, err := fs.Glob(dist, "dist/assets/*.js")
	if err != nil || len(assets) == 0 {
		t.Fatalf("no built assets embedded (%v); run npm run build in web/", err)
	}
	p := strings.TrimPrefix(assets[0], "dist")
	r := get(t, Handler(), "GET", p)
	if r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Type"), "javascript") {
		t.Fatalf("%s: %d %q", p, r.StatusCode, r.Header.Get("Content-Type"))
	}
	if !strings.Contains(r.Header.Get("Cache-Control"), "immutable") {
		t.Errorf("%s: Cache-Control %q", p, r.Header.Get("Cache-Control"))
	}
	// The index must not carry inline scripts, which the CSP forbids.
	idx := body(t, get(t, Handler(), "GET", "/"))
	for _, tag := range strings.Split(idx, "<script")[1:] {
		if !strings.Contains(tag[:strings.Index(tag, ">")], "src=") {
			t.Errorf("inline script in index.html: %.80q", tag)
		}
	}
}
