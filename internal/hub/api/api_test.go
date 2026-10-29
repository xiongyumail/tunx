package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xiongyumail/tunx/internal/hub/auth"
	"github.com/xiongyumail/tunx/internal/hub/model"
	"github.com/xiongyumail/tunx/internal/hub/render"
	"github.com/xiongyumail/tunx/internal/hub/store"
)

const (
	adminUser = "admin"
	adminPass = "s3cret-pass"
)

type env struct {
	t      *testing.T
	srv    *httptest.Server
	st     *store.Store
	secret string
	mu     sync.Mutex
	now    time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, now: time.Unix(1_800_000_000, 0)}
	st.SetClock(func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now })

	b, err := os.ReadFile("../../../examples/network.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := model.ParseYAML(b)
	if err != nil {
		t.Fatal(err)
	}
	spec.Node("site-b").PublicKey = "" // enrolled in the test
	if _, err := st.Import(t.Context(), "test", spec); err != nil {
		t.Fatal(err)
	}
	e.secret, _ = auth.NewTOTPSecret()
	hash, _ := auth.HashPassword(adminPass)
	if err := st.CreateAdmin(t.Context(), store.Admin{Username: adminUser, PasswordHash: hash, TOTPSecret: e.secret}); err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer((&Server{Store: st}).Handler())
	t.Cleanup(e.srv.Close)
	return e
}

// tick advances the clock by one TOTP step so a fresh code is valid.
func (e *env) tick() {
	e.mu.Lock()
	e.now = e.now.Add(30 * time.Second)
	e.mu.Unlock()
}

func (e *env) code() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, _ := auth.TOTPCode(e.secret, e.now)
	return c
}

type client struct {
	e      *env
	hc     *http.Client
	bearer string
	csrf   bool
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, hc: &http.Client{Jar: jar}}
}

func (c *client) do(method, path string, body any, hdr ...string) (int, []byte, http.Header) {
	c.e.t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		r = strings.NewReader(b)
	case []byte:
		r = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		r = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, c.e.srv.URL+path, r)
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.csrf {
		req.Header.Set(CSRFHeader, "1")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out, resp.Header
}

func (c *client) want(code int, method, path string, body any, hdr ...string) []byte {
	c.e.t.Helper()
	got, out, _ := c.do(method, path, body, hdr...)
	if got != code {
		c.e.t.Fatalf("%s %s: status %d, want %d: %s", method, path, got, code, out)
	}
	return out
}

func (e *env) login() *client {
	e.t.Helper()
	e.tick()
	c := e.client()
	c.want(200, "POST", "/api/login", map[string]string{"username": adminUser, "password": adminPass, "totp": e.code()})
	c.csrf = true
	return c
}

func TestLogin(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	e.tick()
	c.want(401, "GET", "/api/nodes", nil)
	c.want(401, "POST", "/api/login", map[string]string{"username": adminUser, "password": "wrong", "totp": e.code()})
	c.want(401, "POST", "/api/login", map[string]string{"username": adminUser, "password": adminPass, "totp": "000000"})
	c.want(401, "POST", "/api/login", map[string]string{"username": adminUser, "password": adminPass})
	c.want(401, "POST", "/api/login", map[string]string{"username": "nobody", "password": adminPass, "totp": e.code()})
	code := e.code()
	c.want(200, "POST", "/api/login", map[string]string{"username": adminUser, "password": adminPass, "totp": code})
	// The same code cannot be used twice.
	c2 := e.client()
	c2.want(401, "POST", "/api/login", map[string]string{"username": adminUser, "password": adminPass, "totp": code})

	c.want(200, "GET", "/api/me", nil)
	// Cookie sessions need the CSRF header to change state.
	c.want(403, "POST", "/api/tokens", map[string]string{"name": "ci"})
	c.csrf = true
	c.want(204, "POST", "/api/logout", nil)
	c.want(401, "GET", "/api/me", nil)

	// Sessions expire.
	c = e.login()
	e.mu.Lock()
	e.now = e.now.Add(13 * time.Hour)
	e.mu.Unlock()
	c.want(401, "GET", "/api/me", nil)
}

func TestLoginLockout(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	for range maxFailures {
		c.want(401, "POST", "/api/login", map[string]string{"username": adminUser, "password": "wrong", "totp": "123456"})
	}
	e.tick()
	c.want(429, "POST", "/api/login", map[string]string{"username": adminUser, "password": adminPass, "totp": e.code()})
	e.mu.Lock()
	e.now = e.now.Add(2 * time.Minute)
	e.mu.Unlock()
	c.want(200, "POST", "/api/login", map[string]string{"username": adminUser, "password": adminPass, "totp": e.code()})
}

func TestCRUD(t *testing.T) {
	e := newEnv(t)
	c := e.login()
	var nodes []model.Node
	json.Unmarshal(c.want(200, "GET", "/api/nodes", nil), &nodes)
	if len(nodes) != 4 {
		t.Fatalf("%d nodes", len(nodes))
	}
	c.want(404, "GET", "/api/widgets", nil)
	c.want(404, "GET", "/api/nodes/nope", nil)

	laptop := map[string]any{"name": "laptop", "node": "hub", "endpoint": "reality"}
	var res struct {
		Changes []store.Change `json:"changes"`
		Object  model.Client   `json:"object"`
	}
	json.Unmarshal(c.want(200, "POST", "/api/clients", laptop), &res)
	if len(res.Changes) != 1 || res.Object.UUID == "" || res.Object.Password == "" {
		t.Fatalf("create: %+v", res)
	}
	c.want(409, "POST", "/api/clients", laptop)
	c.want(400, "PUT", "/api/clients/other", laptop)
	c.want(400, "POST", "/api/clients", map[string]any{"name": "x", "node": "nope", "endpoint": "reality"})
	c.want(400, "POST", "/api/clients", map[string]any{"name": "y", "node": "hub", "endpoint": "reality", "bogus": 1})
	laptop["tags"] = []string{"mobile"}
	json.Unmarshal(c.want(200, "PUT", "/api/clients/laptop", laptop), &res)
	if res.Object.Tags[0] != "mobile" || res.Object.UUID == "" {
		t.Fatalf("put: %+v", res.Object)
	}
	share := c.want(200, "GET", "/api/clients/laptop/share", nil)
	if !strings.Contains(string(share), "vless://") {
		t.Fatalf("share %s", share)
	}
	c.want(200, "DELETE", "/api/clients/laptop", nil)
	c.want(404, "GET", "/api/clients/laptop", nil)
	c.want(404, "DELETE", "/api/clients/laptop", nil)

	// Access policies accept numeric ports.
	c.want(200, "POST", "/api/access", map[string]any{"name": "web", "priority": 65, "action": "allow", "destinations": []string{"10.0.2.0/24"}, "proto": []string{"tcp"}, "ports": []any{80, "8000-8080"}})
	var pol model.AccessPolicy
	json.Unmarshal(c.want(200, "GET", "/api/access/web", nil), &pol)
	if len(pol.Ports) != 2 || pol.Ports[0] != "80" {
		t.Fatalf("ports %v", pol.Ports)
	}

	var netw model.Network
	json.Unmarshal(c.want(200, "GET", "/api/network", nil), &netw)
	netw.DNSSuffix = "corp.internal"
	c.want(200, "PUT", "/api/network", netw)
	c.want(400, "PUT", "/api/network", map[string]any{"name": ""})

	var audit []store.AuditEntry
	json.Unmarshal(c.want(200, "GET", "/api/audit?limit=3", nil), &audit)
	if len(audit) != 3 || audit[0].Kind != "network" || audit[0].Actor != "admin:admin" {
		t.Fatalf("audit %+v", audit)
	}
}

func TestAPITokens(t *testing.T) {
	e := newEnv(t)
	c := e.login()
	var tok struct{ Name, Token string }
	json.Unmarshal(c.want(200, "POST", "/api/tokens", map[string]string{"name": "ci"}), &tok)
	if !strings.HasPrefix(tok.Token, APITokenPrefix) {
		t.Fatalf("token %+v", tok)
	}
	bot := e.client()
	bot.bearer = tok.Token
	bot.want(200, "GET", "/api/export", nil)
	// Bearer tokens do not need the CSRF header.
	bot.want(200, "POST", "/api/routes", map[string]any{"name": "extra", "prefix": "10.0.3.0/24", "advertisers": []any{map[string]any{"node": "site-b"}}})
	var audit []store.AuditEntry
	json.Unmarshal(c.want(200, "GET", "/api/audit?limit=1", nil), &audit)
	if audit[0].Actor != "token:ci" {
		t.Fatalf("audit actor %q", audit[0].Actor)
	}
	bad := e.client()
	bad.bearer = APITokenPrefix + "wrong"
	bad.want(401, "GET", "/api/export", nil)
	bad.bearer = "something-else"
	bad.want(401, "GET", "/api/export", nil)

	c.want(204, "DELETE", "/api/tokens/ci", nil)
	bot.want(401, "GET", "/api/export", nil)
	if strings.Contains(string(c.want(200, "GET", "/api/audit?limit=100", nil)), tok.Token) {
		t.Fatal("token value in audit log")
	}
}

func TestEnrollAndConfig(t *testing.T) {
	e := newEnv(t)
	c := e.login()
	var et struct{ Node, Token string }
	json.Unmarshal(c.want(200, "POST", "/api/nodes/site-b/enroll-token", nil), &et)
	c.want(404, "POST", "/api/nodes/nope/enroll-token", nil)

	anon := e.client()
	anon.want(401, "POST", "/api/enroll", map[string]string{"token": EnrollPrefix + "wrong"})
	var en EnrollResponse
	json.Unmarshal(anon.want(200, "POST", "/api/enroll", map[string]string{"token": et.Token}), &en)
	anon.want(401, "POST", "/api/enroll", map[string]string{"token": et.Token})
	if en.Node != "site-b" || en.Network != "example" || en.KeyFile != render.KeyFile {
		t.Fatalf("enroll %+v", en)
	}
	seed, _ := base64.StdEncoding.DecodeString(en.PrivateKey)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if base64.StdEncoding.EncodeToString(pub) != en.PublicKey {
		t.Fatal("private and public key do not match")
	}

	node := e.client()
	node.bearer = en.NodeToken
	code, body, hdr := node.do("GET", en.ConfigPath, nil)
	if code != 200 {
		t.Fatalf("config: %d %s", code, body)
	}
	var b render.Bundle
	if err := json.Unmarshal(body, &b); err != nil || b.Node != "site-b" || b.Tunxd.Peer("hub") == nil {
		t.Fatalf("bundle %v %s", err, body)
	}
	node.want(304, "GET", en.ConfigPath, nil, "If-None-Match", hdr.Get("ETag"))
	node.want(403, "GET", "/api/nodes/hub/config", nil)
	node.want(403, "GET", "/api/nodes", nil)
	node.want(403, "GET", "/api/export", nil)
	bad := e.client()
	bad.bearer = NodeTokenPrefix + "wrong"
	bad.want(401, "GET", en.ConfigPath, nil)

	// Other nodes now see site-b as a peer; the admin can read any config.
	var hub render.Bundle
	json.Unmarshal(c.want(200, "GET", "/api/nodes/hub/config", nil), &hub)
	if p := hub.Tunxd.Peer("site-b"); p == nil || base64.StdEncoding.EncodeToString(p.PublicKey) != en.PublicKey {
		t.Fatalf("hub peer site-b %+v", p)
	}
	// The private key is not stored anywhere the API can reach.
	exp := c.want(200, "GET", "/api/export", nil)
	if bytes.Contains(exp, []byte(en.PrivateKey)) {
		t.Fatal("private key exported")
	}
	// A change makes the old ETag stale.
	c.want(200, "PUT", "/api/links/b-hub", map[string]any{"name": "b-hub", "dialer": "site-b", "listener": "hub", "endpoint": "reality", "interface": "eth2"})
	node.want(200, "GET", en.ConfigPath, nil, "If-None-Match", hdr.Get("ETag"))

	// Re-enrolling rotates the key and the config token.
	json.Unmarshal(c.want(200, "POST", "/api/nodes/site-b/enroll-token", nil), &et)
	var en2 EnrollResponse
	json.Unmarshal(anon.want(200, "POST", "/api/enroll", map[string]string{"token": et.Token}), &en2)
	node.want(401, "GET", en.ConfigPath, nil)
	if en2.PublicKey == en.PublicKey {
		t.Fatal("key not rotated")
	}
}

func TestImportExport(t *testing.T) {
	e := newEnv(t)
	c := e.login()
	exp := c.want(200, "GET", "/api/export", nil)
	var res struct{ Changes []store.Change }
	json.Unmarshal(c.want(200, "POST", "/api/import", exp), &res)
	if len(res.Changes) != 0 {
		t.Fatalf("re-import changed %v", res.Changes)
	}
	// Invalid YAML and invalid networks are rejected without change.
	c.want(400, "POST", "/api/import", "network: [")
	c.want(400, "POST", "/api/import", "network: {name: example}\nbogus: 1\n")
	broken := strings.Replace(string(exp), "exit: exit", "exit: hub", 1)
	c.want(400, "POST", "/api/import", broken)
	if got := c.want(200, "GET", "/api/export", nil); !bytes.Equal(got, exp) {
		t.Fatal("failed import changed the network")
	}
	// A real change is applied and audited.
	changed := strings.Replace(string(exp), "dns_suffix: tunx.internal", "dns_suffix: other.internal", 1)
	json.Unmarshal(c.want(200, "POST", "/api/import", changed), &res)
	if len(res.Changes) != 1 || res.Changes[0].Kind != "network" {
		t.Fatalf("changes %v", res.Changes)
	}
}
