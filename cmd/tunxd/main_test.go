package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
