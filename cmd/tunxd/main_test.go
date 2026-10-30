package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xiongyumail/tunx/internal/config"
)

func TestKeygen(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"keygen"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var k map[string]string
	if err := json.Unmarshal(out.Bytes(), &k); err != nil || k["private_key"] == "" || k["public_key"] == "" {
		t.Fatalf("output %q: %v", out.String(), err)
	}
}

func TestCheckExample(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"check", "-c", "../../examples/site-a.json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	for _, want := range []string{
		"config ok: node site-a",
		"public key: RC6GLc35UndsjWjZJlmzwS+XdFlfUCHPR1sslB0XWc4=",
		"ip addr add 10.200.0.2/24 dev tunx0",
		"ip -4 route replace 10.0.2.0/24 dev tunx0",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

func TestCheckInvalid(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(f, []byte(`{"node": "a"}`), 0o600)
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"check", "-c", f}, &out, &errb); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "private_key") {
		t.Fatalf("stderr %q", errb.String())
	}
	if code := run(context.Background(), []string{"bogus"}, &out, &errb); code != 2 {
		t.Fatalf("unknown command exit %d", code)
	}
}

func TestEnrollAndPull(t *testing.T) {
	priv, pub, err := config.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	revision := "r1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/enroll":
			var req map[string]string
			json.NewDecoder(r.Body).Decode(&req)
			if req["token"] != "once" {
				http.Error(w, "bad token", http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{
				"node": "site-a", "network": "test", "private_key": priv,
				"public_key": pub, "node_token": "tunx_nt_test",
				"config_path": "/api/nodes/site-a/config", "key_file": "node.key",
			})
		case "/api/nodes/site-a/config":
			if r.Header.Get("Authorization") != "Bearer tunx_nt_test" {
				http.Error(w, "bad auth", http.StatusUnauthorized)
				return
			}
			etag := `"` + revision + `"`
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"node": "site-a", "revision": revision,
				"tunxd": map[string]any{"node": "site-a", "network": "test", "private_key_file": "node.key", "listen": []map[string]string{{"address": "127.0.0.1:0"}}},
				"xray":  map[string]any{"log": map[string]string{"loglevel": revision}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("once\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"enroll", "-hub", srv.URL, "-token-file", token, "-dir", dir}, &out, &errb); code != 0 {
		t.Fatalf("enroll exit %d: %s", code, errb.String())
	}
	for _, name := range []string{hubStateFile, "node.key", tunxdFile, xrayFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode: %v %v", name, info, err)
		}
	}
	if strings.Contains(out.String(), priv) || strings.Contains(out.String(), "tunx_nt_test") {
		t.Fatal("secret printed")
	}
	out.Reset()
	if code := run(context.Background(), []string{"pull", "-dir", dir}, &out, &errb); code != 0 || !strings.Contains(out.String(), "unchanged") {
		t.Fatalf("unchanged pull exit %d: %s %s", code, out.String(), errb.String())
	}
	revision = "r2"
	out.Reset()
	if code := run(context.Background(), []string{"pull", "-dir", dir}, &out, &errb); code != 0 || !strings.Contains(out.String(), "r2") {
		t.Fatalf("updated pull exit %d: %s %s", code, out.String(), errb.String())
	}
	b, err := os.ReadFile(filepath.Join(dir, xrayFile))
	if err != nil || !strings.Contains(string(b), `"r2"`) {
		t.Fatalf("xray config: %s %v", b, err)
	}
}

func TestEnrollRejectsRemoteHTTP(t *testing.T) {
	var out, errb bytes.Buffer
	code := run(context.Background(), []string{"enroll", "-hub", "http://example.com", "-token-file", "none"}, &out, &errb)
	if code != 1 || !strings.Contains(errb.String(), "HTTPS") {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
}

// run starts a node without a TUN and stops cleanly when ctx ends.
func TestRunStops(t *testing.T) {
	var keys map[string]string
	var kb bytes.Buffer
	run(context.Background(), []string{"keygen"}, &kb, &kb)
	json.Unmarshal(kb.Bytes(), &keys)
	// The peer's key does not matter here; reuse the generated one.
	peerPub := keys["public_key"]
	f := filepath.Join(t.TempDir(), "node.json")
	os.WriteFile(f, []byte(`{
  "node": "solo", "network": "t", "private_key": "`+keys["private_key"]+`",
  "listen": [{"address": "127.0.0.1:0"}],
  "peers": [{"name": "other", "public_key": "`+peerPub+`"}],
  "status": "127.0.0.1:0"
}`), 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	var errb syncBuffer
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"run", "-c", f}, &errb, &errb) }()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(errb.String(), "node started") {
		if time.Now().After(deadline) {
			t.Fatalf("not started: %s", errb.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop")
	}
	if !strings.Contains(errb.String(), "node stopped") {
		t.Fatalf("log: %s", errb.String())
	}
}
