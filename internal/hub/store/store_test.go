package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xiongyumail/tunx/internal/hub/model"
)

var ctx = context.Background()

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hub.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func example(t *testing.T) *model.Spec {
	t.Helper()
	b, err := os.ReadFile("../../../examples/network.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s, err := model.ParseYAML(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMigrations(t *testing.T) {
	s, path := openTemp(t)
	v, err := s.Version(ctx)
	if err != nil || v != SchemaVersion {
		t.Fatalf("version %d, %v", v, err)
	}
	s.Close()
	// Reopening applies nothing new and keeps the data.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if v, _ := s2.Version(ctx); v != SchemaVersion {
		t.Fatalf("version after reopen %d", v)
	}
	var n int
	s2.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n)
	if n != SchemaVersion {
		t.Fatalf("%d migration rows", n)
	}
	// A database from a newer binary is refused.
	s2.db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, 'x')`, SchemaVersion+1)
	s2.Close()
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("newer schema accepted: %v", err)
	}
}

func TestImportIdempotentAndAudited(t *testing.T) {
	s, _ := openTemp(t)
	spec := example(t)
	changes, err := s.Import(ctx, "test", spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1+len(spec.Groups)+len(spec.Nodes)+len(spec.Links)+len(spec.Routes)+len(spec.Access)+len(spec.Egress)+len(spec.Clients) {
		t.Fatalf("%d changes", len(changes))
	}
	audit, _ := s.Audit(ctx, 1000)
	if len(audit) != len(changes) {
		t.Fatalf("%d audit rows for %d changes", len(audit), len(changes))
	}
	// Importing the same spec again changes nothing.
	changes, err = s.Import(ctx, "test", spec)
	if err != nil || len(changes) != 0 {
		t.Fatalf("second import: %v %v", changes, err)
	}
	got, err := s.Spec(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := model.MarshalYAML(spec)
	b, _ := model.MarshalYAML(got)
	if string(a) != string(b) {
		t.Fatalf("stored spec differs:\n%s\n---\n%s", a, b)
	}
}

func TestImportKeepsAndGeneratesSecrets(t *testing.T) {
	s, _ := openTemp(t)
	spec := example(t)
	// Strip secrets: the hub generates them on the first import.
	for i := range spec.Links {
		spec.Links[i].UUID, spec.Links[i].ShortID = "", ""
	}
	spec.Clients[0].UUID, spec.Clients[0].Password = "", ""
	spec.Node("hub").Endpoints[0].Reality.PrivateKey = ""
	if _, err := s.Import(ctx, "test", spec); err != nil {
		t.Fatal(err)
	}
	first, _ := s.Spec(ctx)
	if first.Links[0].UUID == "" || first.Clients[0].Password == "" || first.Node("hub").Endpoints[0].Reality.PrivateKey == "" {
		t.Fatal("secrets not generated")
	}
	// Importing the stripped spec again keeps them.
	changes, err := s.Import(ctx, "test", spec)
	if err != nil || len(changes) != 0 {
		t.Fatalf("re-import rotated secrets: %v %v", changes, err)
	}
	// Secrets never appear in the audit log.
	audit, _ := s.Audit(ctx, 1000)
	for _, e := range audit {
		if strings.Contains(string(e.Diff), first.Links[0].UUID) || strings.Contains(string(e.Diff), first.Clients[0].Password) {
			t.Fatalf("secret in audit: %s", e.Diff)
		}
	}
}

func TestInvalidChangeRollsBack(t *testing.T) {
	s, _ := openTemp(t)
	if _, err := s.Import(ctx, "test", example(t)); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Spec(ctx)
	nAudit, _ := s.Audit(ctx, 1000)

	// An import with a dangling reference is rejected as a whole.
	bad := example(t)
	bad.Nodes = bad.Nodes[:len(bad.Nodes)-1] // drops site-b, still linked
	bad.Network.DNSSuffix = "changed.internal"
	_, err := s.Import(ctx, "test", bad)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want a validation error, got %v", err)
	}
	after, _ := s.Spec(ctx)
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if string(a) != string(b) {
		t.Fatal("failed import changed the network")
	}
	if n, _ := s.Audit(ctx, 1000); len(n) != len(nAudit) {
		t.Fatal("failed import wrote audit rows")
	}
}

func TestUpdateDiffAndDelete(t *testing.T) {
	s, _ := openTemp(t)
	if _, err := s.Import(ctx, "test", example(t)); err != nil {
		t.Fatal(err)
	}
	changes, err := s.Update(ctx, "alice", func(sp *model.Spec) error {
		_, err := sp.Put("links", []byte(`{"name":"a-hub","dialer":"site-a","listener":"hub","endpoint":"reality","cost":7}`))
		return err
	})
	if err != nil || len(changes) != 1 || changes[0].Action != "update" {
		t.Fatalf("%v %v", changes, err)
	}
	sp, _ := s.Spec(ctx)
	if sp.Links[0].Cost != 7 || sp.Links[0].UUID != "d47897ee-b466-4238-8aa8-781608aa24c9" {
		t.Fatalf("link after put without uuid: %+v", sp.Links[0])
	}
	audit, _ := s.Audit(ctx, 1)
	if audit[0].Actor != "alice" || !strings.Contains(string(audit[0].Diff), `"cost":{"new":7,"old":null}`) {
		t.Fatalf("audit %+v %s", audit[0], audit[0].Diff)
	}

	// Deleting a node still referenced fails; deleting the client works.
	if _, err := s.Update(ctx, "alice", func(sp *model.Spec) error { return sp.Delete("nodes", "site-b") }); err == nil {
		t.Fatal("deleted a referenced node")
	}
	if _, err := s.Update(ctx, "alice", func(sp *model.Spec) error { return sp.Delete("clients", "phone") }); err == nil {
		t.Fatal("deleted a client still used by policies")
	}
}

func TestEnrollOnce(t *testing.T) {
	s, _ := openTemp(t)
	spec := example(t)
	spec.Node("site-b").PublicKey = ""
	if _, err := s.Import(ctx, "test", spec); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	s.SetClock(func() time.Time { return now })
	if err := s.CreateEnrollToken(ctx, "alice", "site-b", "h1", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateEnrollToken(ctx, "alice", "nope", "h2", now.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token for unknown node: %v", err)
	}
	const pub = "MCuN82pQdmcBcq56rRhxKdmRTvJoGQ+5+pttotl+GvU="
	node, err := s.Enroll(ctx, "h1", pub, "nt1")
	if err != nil || node != "site-b" {
		t.Fatalf("enroll: %v %v", node, err)
	}
	if _, err := s.Enroll(ctx, "h1", pub, "nt2"); !errors.Is(err, ErrBadEnrollToken) {
		t.Fatalf("token reused: %v", err)
	}
	if n, err := s.NodeByToken(ctx, "nt1"); err != nil || n != "site-b" {
		t.Fatalf("node token: %v %v", n, err)
	}
	sp, _ := s.Spec(ctx)
	if sp.Node("site-b").PublicKey != pub {
		t.Fatal("public key not stored")
	}
	// Expired tokens are refused.
	s.CreateEnrollToken(ctx, "alice", "site-b", "h3", now.Add(time.Minute))
	now = now.Add(2 * time.Minute)
	if _, err := s.Enroll(ctx, "h3", pub, "nt3"); !errors.Is(err, ErrBadEnrollToken) {
		t.Fatalf("expired token: %v", err)
	}
	// Deleting the node removes its config token.
	spec2 := example(t)
	spec2.Links = spec2.Links[:1]
	spec2.Nodes = []model.Node{*spec2.Node("hub"), *spec2.Node("site-a")}
	spec2.Access, spec2.Egress, spec2.Routes, spec2.Clients, spec2.Groups = nil, nil, nil, nil, nil
	if _, err := s.Import(ctx, "test", spec2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NodeByToken(ctx, "nt1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token of deleted node still valid: %v", err)
	}
}

func TestTOTPStepMonotonic(t *testing.T) {
	s, _ := openTemp(t)
	if err := s.CreateAdmin(ctx, Admin{Username: "admin", PasswordHash: "x", TOTPSecret: "y"}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.UseTOTPStep(ctx, "admin", 10); !ok {
		t.Fatal("first step refused")
	}
	if ok, _ := s.UseTOTPStep(ctx, "admin", 10); ok {
		t.Fatal("replayed step accepted")
	}
	if err := s.CreateAdmin(ctx, Admin{Username: "admin", PasswordHash: "x", TOTPSecret: "y"}); err == nil {
		t.Fatal("duplicate admin")
	}
}
