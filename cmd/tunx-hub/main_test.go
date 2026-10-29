package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongyumail/tunx/internal/hub/render"
)

func runCmd(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestCLI(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "hub.db")

	if code, _, _ := runCmd(t, "", "export", "-db", db, "-"); code != 1 {
		t.Fatal("export without a database should fail")
	}
	if code, _, _ := runCmd(t, "short\n", "init", "-db", db); code != 1 {
		t.Fatal("short password accepted")
	}
	code, out, errs := runCmd(t, "a-long-enough-password\n", "init", "-db", db, "-network", "example")
	if code != 0 || !strings.Contains(out, "TOTP secret (shown once): ") || !strings.Contains(out, "otpauth://totp/") {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	if code, _, _ := runCmd(t, "a-long-enough-password\n", "init", "-db", db); code != 1 {
		t.Fatal("second init accepted")
	}

	code, out, errs = runCmd(t, "", "import", "-db", db, "../../examples/network.yaml")
	if code != 0 || !strings.Contains(out, "create nodes hub") {
		t.Fatalf("import: %d %s %s", code, out, errs)
	}
	exported := filepath.Join(dir, "net.yaml")
	if code, _, errs := runCmd(t, "", "export", "-db", db, exported); code != 0 {
		t.Fatal(errs)
	}
	code, out, _ = runCmd(t, "", "import", "-db", db, exported)
	if code != 0 || !strings.Contains(out, "0 changes") {
		t.Fatalf("re-import: %s", out)
	}
	b, _ := os.ReadFile(exported)
	code, out, _ = runCmd(t, "", "export", "-db", db, "-")
	if code != 0 || out != string(b) {
		t.Fatal("export to stdout differs from file")
	}

	code, out, errs = runCmd(t, "", "render", "-db", db, "site-a")
	var bundle render.Bundle
	if code != 0 || json.Unmarshal([]byte(out), &bundle) != nil || bundle.Node != "site-a" {
		t.Fatalf("render: %d %s %s", code, out, errs)
	}
	if code, _, _ := runCmd(t, "", "render", "-db", db, "nope"); code != 1 {
		t.Fatal("render of an unknown node succeeded")
	}

	code, out, _ = runCmd(t, "", "token", "-db", db, "ci")
	if code != 0 || !strings.HasPrefix(out, "tunx_at_") {
		t.Fatalf("token: %s", out)
	}
	code, out, _ = runCmd(t, "", "enroll-token", "-db", db, "site-b")
	if code != 0 || !strings.HasPrefix(out, "tunx_et_") {
		t.Fatalf("enroll-token: %s", out)
	}
	if code, _, _ := runCmd(t, "", "enroll-token", "-db", db, "nope"); code != 1 {
		t.Fatal("enroll token for an unknown node")
	}
	if code, _, _ := runCmd(t, "", "bogus"); code != 2 {
		t.Fatal("unknown command accepted")
	}
}
