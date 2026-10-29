package render

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xiongyumail/tunx/internal/config"
	"github.com/xiongyumail/tunx/internal/hub/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

func loadExample(t *testing.T) *model.Spec {
	t.Helper()
	b, err := os.ReadFile("../../../examples/network.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s, err := model.ParseYAML(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// TestGolden renders every node of the example network and compares with
// testdata/<node>.json (go test -run Golden -update rewrites them).
func TestGolden(t *testing.T) {
	s := loadExample(t)
	for _, n := range s.Nodes {
		t.Run(n.Name, func(t *testing.T) {
			b, err := Node(s, n.Name)
			if err != nil {
				t.Fatal(err)
			}
			got := marshal(t, b)
			file := filepath.Join("testdata", n.Name+".json")
			if *update {
				if err := os.WriteFile(file, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("render differs from %s (rerun with -update after checking):\n%s", file, got)
			}
			checkTunxdConfig(t, b.Tunxd)
			checkXray(t, b.Xray)
		})
	}
}

// checkTunxdConfig loads the rendered config the way tunxd does, with the
// key file written next to it.
func checkTunxdConfig(t *testing.T, c *config.Config) {
	t.Helper()
	dir := t.TempDir()
	priv, _, err := config.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFile), []byte(priv), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "tunxd.json")
	if err := os.WriteFile(file, marshal(t, c), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(file); err != nil {
		t.Fatalf("tunxd config does not load: %v", err)
	}
}

// checkXray runs `xray run -test` on the config when xray is installed.
func checkXray(t *testing.T, x map[string]any) {
	t.Helper()
	bin, err := exec.LookPath("xray")
	if err != nil {
		t.Log("xray not on PATH; skipping xray run -test")
		return
	}
	file := filepath.Join(t.TempDir(), "xray.json")
	if err := os.WriteFile(file, marshal(t, x), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "run", "-test", "-c", file).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Configuration OK") {
		t.Fatalf("xray rejects the config: %v\n%s\n%s", err, out, marshal(t, x))
	}
}

func TestDeterministic(t *testing.T) {
	s := loadExample(t)
	a, err := Node(s, "hub")
	if err != nil {
		t.Fatal(err)
	}
	// Reverse every list: canonical order must restore the same output.
	r := s.Clone()
	slices.Reverse(r.Nodes)
	slices.Reverse(r.Links)
	slices.Reverse(r.Access)
	r.Canonicalize()
	for range 5 {
		b, err := Node(r, "hub")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(marshal(t, a), marshal(t, b)) {
			t.Fatal("rendering is not deterministic")
		}
	}
	// A change changes the revision.
	r.Links[0].Priority = 3
	c, _ := Node(r, "hub")
	if c.Revision == a.Revision {
		t.Fatal("revision unchanged after a link change")
	}
}

func TestExampleWiring(t *testing.T) {
	s := loadExample(t)
	hub, _ := Node(s, "hub")
	siteB, _ := Node(s, "site-b")

	// The UUID site-b dials with is a user of the hub's REALITY inbound,
	// routed to tunxd, and the short ID is accepted.
	out := findTag(t, siteB.Xray["outbounds"], "link-b-hub")
	user := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	if user["id"] != "28506096-9aed-4c94-8359-6cf0916d1cb6" {
		t.Fatalf("site-b dials with %v", user["id"])
	}
	ss := out["streamSettings"].(map[string]any)
	if ss["sockopt"].(map[string]any)["interface"] != "eth1" {
		t.Fatal("site-b link not bound to eth1")
	}
	pub := ss["realitySettings"].(map[string]any)["password"]
	if want, _ := model.RealityPublicKey(s.Node("hub").Endpoint("reality").Reality.PrivateKey); pub != want {
		t.Fatalf("reality public key %v, want %v", pub, want)
	}
	in := findTag(t, hub.Xray["inbounds"], "in-reality")
	clients := in["settings"].(map[string]any)["clients"].([]any)
	if !slices.ContainsFunc(clients, func(c any) bool {
		m := c.(map[string]any)
		return m["id"] == user["id"] && m["email"] == "link:b-hub"
	}) {
		t.Fatal("hub inbound lacks site-b's user")
	}
	sids := in["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)["shortIds"].([]any)
	if !slices.Contains(sids, any("fcf33702d1a427ef")) || !slices.Contains(sids, any("823a5f77f5284c15")) {
		t.Fatalf("short IDs %v", sids)
	}

	// The phone's traffic goes to tunxd's client SOCKS server with its own
	// account; the hub's peers trust the phone's identity from the hub.
	if hub.ClientSOCKS == nil || hub.ClientSOCKS.Users[0].Name != "phone" {
		t.Fatalf("client socks %+v", hub.ClientSOCKS)
	}
	findTag(t, hub.Xray["outbounds"], "client-phone")
	if p := siteB.Tunxd.Peer("hub"); !slices.Contains(p.RelayFor, "phone") || !slices.Contains(p.RelayFor, "site-a") {
		t.Fatalf("site-b relay_for %v", p.RelayFor)
	}
	// The hub dials the exit; the sites reach the exit and site A only via
	// the hub.
	if hub.Tunxd.Peer("exit").Dial == "" || hub.Tunxd.Peer("site-a").Dial != "" {
		t.Fatal("hub dial sides wrong")
	}
	for _, r := range siteB.Tunxd.Routes {
		if r.Prefix.String() == "0.0.0.0/0" && (r.Advertisers[0].Node != "exit" || !slices.Equal(r.Advertisers[0].Via, []string{"hub"})) {
			t.Fatalf("site-b default route %+v", r)
		}
	}
}

func findTag(t *testing.T, list any, tag string) map[string]any {
	t.Helper()
	for _, x := range list.([]any) {
		if m := x.(map[string]any); m["tag"] == tag {
			return m
		}
	}
	t.Fatalf("no %q in %v", tag, list)
	return nil
}

const testKey = "Tlsnm/UmIl4hNQhD2zypl+u/JdYC0RotgT7JvUKQxpc="

func pathSpec() *model.Spec {
	// a -1- r1 -1- b      a and b are sites; c advertises the same prefix
	// a -1- r2 -5- b      as b with a lower preference; r1 and r2 relay,
	//           r2 -1- c  n is not a relay.
	//   a -1- n -1- b
	s := &model.Spec{Network: model.Network{Name: "t", Prefixes: []string{"10.9.0.0/24"}}}
	addr := 1
	for _, n := range []struct {
		name string
		caps []string
	}{{"a", nil}, {"b", []string{"advertise"}}, {"c", []string{"advertise"}}, {"n", nil}, {"r1", []string{"listen", "relay"}}, {"r2", []string{"listen", "relay"}}} {
		node := model.Node{Name: n.name, PublicKey: testKey, Capabilities: append(n.caps, "listen"),
			Addresses: []string{"10.9.0." + string(rune('0'+addr))}}
		node.Endpoints = []model.Endpoint{{Name: "e", Transport: "vless", Address: n.name + ".lan", Port: 1000}}
		s.Nodes = append(s.Nodes, node)
		addr++
	}
	link := func(name, d, l string, cost int) model.Link {
		return model.Link{Name: name, Dialer: d, Listener: l, Endpoint: "e", Cost: cost}
	}
	s.Links = []model.Link{
		link("a-r1", "a", "r1", 1), link("r1-b", "r1", "b", 1),
		link("a-r2", "a", "r2", 1), link("r2-b", "r2", "b", 5), link("r2-c", "r2", "c", 1),
		link("a-n", "a", "n", 1), link("n-b", "n", "b", 1),
	}
	s.Routes = []model.Route{{Name: "lan", Prefix: "192.168.0.0/24", Advertisers: []model.RouteAdvertiser{
		{Node: "c", Priority: 20}, {Node: "b", Priority: 10},
	}}}
	s.Canonicalize()
	if err := s.FillGenerated(nil); err != nil {
		panic(err)
	}
	return s
}

func route(t *testing.T, c *config.Config, prefix string) config.Route {
	t.Helper()
	for _, r := range c.Routes {
		if r.Prefix.String() == prefix {
			return r
		}
	}
	t.Fatalf("no route %s in %+v", prefix, c.Routes)
	return config.Route{}
}

func TestPathsRelaysAndPriority(t *testing.T) {
	s := pathSpec()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := Node(s, "a")
	if err != nil {
		t.Fatal(err)
	}
	r := route(t, b.Tunxd, "192.168.0.0/24")
	if len(r.Advertisers) != 2 {
		t.Fatalf("advertisers %+v", r.Advertisers)
	}
	// b first by priority, via the cheaper relay first; n is not a relay.
	if a := r.Advertisers[0]; a.Node != "b" || a.Priority != 10 || !slices.Equal(a.Via, []string{"r1", "r2"}) {
		t.Fatalf("first advertiser %+v", a)
	}
	if a := r.Advertisers[1]; a.Node != "c" || !slices.Equal(a.Via, []string{"r2"}) {
		t.Fatalf("second advertiser %+v", a)
	}
	// r2 reaches b directly and also through... nothing else that avoids
	// r2 itself except r1 via a, which is not a relay.
	b2, _ := Node(s, "r2")
	if a := route(t, b2.Tunxd, "192.168.0.0/24").Advertisers[0]; a.Node != "b" || len(a.Via) != 0 {
		t.Fatalf("r2 advertiser %+v", a)
	}
	// b accepts a's identity from r1 and r2 but not from n.
	bb, _ := Node(s, "b")
	if p := bb.Tunxd.Peer("r1"); !slices.Contains(p.RelayFor, "a") {
		t.Fatalf("r1 relay_for %v", p.RelayFor)
	}
	if p := bb.Tunxd.Peer("n"); len(p.RelayFor) != 0 {
		t.Fatalf("non-relay n relay_for %v", p.RelayFor)
	}

	// Cutting a-r1 moves b behind r2; making r1 cheaper than r2 again
	// through cost keeps order by cost.
	s.Links[slices.IndexFunc(s.Links, func(l model.Link) bool { return l.Name == "a-r1" })].Disabled = true
	b, _ = Node(s, "a")
	if a := route(t, b.Tunxd, "192.168.0.0/24").Advertisers[0]; !slices.Equal(a.Via, []string{"r2"}) {
		t.Fatalf("after cut %+v", a)
	}
	// Equal priority: the closer advertiser comes first.
	s.Routes[0].Advertisers[0].Priority = 10
	b, _ = Node(s, "a")
	if a := route(t, b.Tunxd, "192.168.0.0/24").Advertisers[0]; a.Node != "c" {
		t.Fatalf("equal priority should prefer the closer c: %+v", a)
	}
}

func TestUnenrolledNodeSkipped(t *testing.T) {
	s := loadExample(t)
	s.Node("site-b").PublicKey = ""
	b, err := Node(s, "hub")
	if err != nil {
		t.Fatal(err)
	}
	if b.Tunxd.Peer("site-b") != nil {
		t.Fatal("unenrolled peer rendered")
	}
	if len(b.Warnings) == 0 {
		t.Fatal("no warning for the unenrolled peer")
	}
	for _, r := range b.Tunxd.Routes {
		if r.Prefix.String() == "10.0.2.0/24" {
			t.Fatal("route to an unenrolled advertiser rendered")
		}
	}
	// The unenrolled node itself still renders (links skipped).
	if _, err := Node(s, "site-b"); err != nil {
		t.Fatal(err)
	}
}

func TestEmptySelectorDropsRule(t *testing.T) {
	s := loadExample(t)
	s.Access = append(s.Access, model.AccessPolicy{Name: "nobody", Priority: 1, Action: "allow", Sources: []string{"tag:none"}})
	s.Access = append(s.Access, model.AccessPolicy{Name: "nowhere", Priority: 2, Action: "allow", Destinations: []string{"tag:none"}})
	s.Canonicalize()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	b, _ := Node(s, "site-a")
	for _, r := range b.Tunxd.Policy {
		if len(r.Identity) == 0 && len(r.Dst) == 0 && r.Action == "allow" {
			t.Fatalf("empty selector became match-any: %+v", r)
		}
	}
}

func TestShareLink(t *testing.T) {
	s := loadExample(t)
	u, err := ShareLink(s, "phone")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"vless://40163530-55b6-4c57-b282-96c34879f4c7@hub.example.com:443?", "security=reality", "pbk=q7SR35M689mcETdRz2dvCaIpzYHztzgObewyL9rJDiQ", "sid=823a5f77f5284c15", "flow=xtls-rprx-vision", "#phone"} {
		if !strings.Contains(u, want) {
			t.Errorf("share link %s lacks %s", u, want)
		}
	}
}

// TestTransports renders TLS, SOCKS and a chained link and checks them
// with xray.
func TestTransports(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeSelfSigned(t, cert, key)
	s := &model.Spec{Network: model.Network{Name: "t", Prefixes: []string{"10.9.0.0/24"}}}
	s.Nodes = []model.Node{
		{Name: "a", PublicKey: testKey, Addresses: []string{"10.9.0.1"},
			Proxies: []model.Proxy{{Name: "up", Outbound: map[string]any{"protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": 1081}}}}}}},
		{Name: "b", PublicKey: testKey, Addresses: []string{"10.9.0.2"}, Capabilities: []string{"listen", "relay"},
			Endpoints: []model.Endpoint{
				{Name: "tls", Transport: "tls", Address: "b.test", Port: 8443, TLS: &model.TLS{ServerName: "b.test", CertFile: cert, KeyFile: key}, Clients: true},
				{Name: "socks", Transport: "socks", Address: "b.test", Port: 1080},
			}},
	}
	s.Links = []model.Link{
		{Name: "a-b-tls", Dialer: "a", Listener: "b", Endpoint: "tls", DialerProxy: "up", Mark: 7},
		{Name: "a-b-socks", Dialer: "a", Listener: "b", Endpoint: "socks", Priority: 5},
	}
	s.Clients = []model.Client{{Name: "laptop", Node: "b", Endpoint: "tls"}}
	s.Canonicalize()
	if err := s.FillGenerated(nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a", "b"} {
		b, err := Node(s, n)
		if err != nil {
			t.Fatal(err)
		}
		checkXray(t, b.Xray)
		checkTunxdConfig(t, b.Tunxd)
		if n == "a" {
			if b.Tunxd.Peer("b").Dial != "127.0.0.1:10801" {
				t.Fatalf("a should dial the preferred tls link: %+v", b.Tunxd.Peer("b"))
			}
			if !slices.ContainsFunc(b.Warnings, func(w string) bool { return strings.Contains(w, "standby") }) {
				t.Fatalf("no standby warning: %v", b.Warnings)
			}
			so := findTag(t, b.Xray["outbounds"], "link-a-b-tls")["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
			if so["dialerProxy"] != "proxy-up" {
				t.Fatalf("sockopt %v", so)
			}
		}
	}
}

func writeSelfSigned(t *testing.T, certFile, keyFile string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "b.test"}, DNSNames: []string{"b.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600)
}
