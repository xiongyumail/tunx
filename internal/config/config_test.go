package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongyumail/tunx/internal/core"
)

func TestExamplesValid(t *testing.T) {
	files, _ := filepath.Glob("../../examples/*.json")
	if len(files) < 3 {
		t.Fatalf("found %d examples", len(files))
	}
	keys := map[string]string{}
	var cfgs []*Config
	for _, f := range files {
		c, err := Load(f)
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := PublicKey(c.PublicKey()).MarshalText()
		keys[c.Node] = string(pub)
		cfgs = append(cfgs, c)
	}
	// Every peer's key matches that node's own key.
	for _, c := range cfgs {
		for _, p := range c.Peers {
			got, _ := p.PublicKey.MarshalText()
			if want, ok := keys[p.Name]; ok && string(got) != want {
				t.Errorf("%s: key of peer %s does not match its config", c.Node, p.Name)
			}
		}
	}
}

func TestStripComments(t *testing.T) {
	in := `{
  // line comment with "quote"
  "a": "http://x/*not a comment*/", /* block
  comment */ "b": "\"//\"" // trailing
}`
	c, err := Parse([]byte(strings.Replace(in, `"a"`, `"node"`, 1)))
	if err == nil {
		t.Fatalf("unknown field b accepted: %+v", c)
	}
	out := string(StripComments([]byte(in)))
	if len(out) != len(in) {
		t.Fatal("offsets changed")
	}
	for _, want := range []string{`"http://x/*not a comment*/"`, `"\"//\""`} {
		if !strings.Contains(out, want) {
			t.Errorf("string %s damaged: %s", want, out)
		}
	}
	for _, gone := range []string{"line comment", "block", "trailing"} {
		if strings.Contains(out, gone) {
			t.Errorf("comment %q kept", gone)
		}
	}
}

func seed(t *testing.T) (string, string) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv.Seed()), base64.StdEncoding.EncodeToString(pub)
}

func TestValidateErrors(t *testing.T) {
	key, pub := seed(t)
	base := `"node": "a", "network": "n", "private_key": "` + key + `", "listen": [{"address": "127.0.0.1:7700"}]`
	peerB := `{"name": "b", "public_key": "` + pub + `"}`
	for _, tc := range []struct{ body, want string }{
		{`"network": "n", "private_key": "` + key + `"`, "node: must be"},
		{`"node": "a b", "private_key": "` + key + `"`, "contains whitespace"},
		{`"node": "a"`, "private_key or private_key_file is required"},
		{`"node": "a", "private_key": "nope!"`, "not base64"},
		{`"node": "a", "private_key": "` + pub[:20] + `"`, "private key"},
		{base + `, "hop_limit": 300`, "hop_limit"},
		{base + `, "status": "0.0.0.0:80"`, "loopback"},
		{base + `, "listen": [{"address": "nope"}]`, "listen[0]"},
		{base + `, "tun": {"name": ""}`, "tun.name"},
		{base + `, "tun": {"name": "t", "mtu": 100}`, "tun.mtu"},
		{base + `, "peers": [` + peerB + `, ` + peerB + `]`, "duplicate peer"},
		{base + `, "peers": [{"name": "a", "public_key": "` + pub + `"}]`, "is this node"},
		{base + `, "peers": [{"name": "b"}]`, "public_key missing"},
		{base + `, "peers": [{"name": "b", "public_key": "AAAA"}]`, "invalid public key"},
		{base + `, "peers": [{"name": "b", "public_key": "` + pub + `", "interface": "eth0"}]`, "need a dial address"},
		{base + `, "routes": [{"prefix": "10.0.0.1/8", "advertisers": [{"node": "a"}]}]`, "host bits"},
		{base + `, "routes": [{"prefix": "10.0.0.0/33", "advertisers": [{"node": "a"}]}]`, "10.0.0.0/33"},
		{base + `, "routes": [{"prefix": "10.0.0.0/8"}]`, "no advertisers"},
		{base + `, "routes": [{"prefix": "10.0.0.0/8", "advertisers": [{"node": "c"}]}]`, "not a peer; give a via"},
		{base + `, "peers": [` + peerB + `], "routes": [{"prefix": "10.0.0.0/8", "advertisers": [{"node": "c", "via": ["d"]}]}]`, `via "d" is not a peer`},
		{base + `, "peers": [` + peerB + `], "routes": [{"prefix": "10.0.0.0/8", "advertisers": [{"node": "b", "source": "preserve"}]}]`, "apply only to this node"},
		{base + `, "routes": [{"prefix": "10.0.0.0/8", "advertisers": [{"node": "a", "source": "nat"}]}]`, "want snat or preserve"},
		{base + `, "routes": [{"prefix": "10.0.0.0/8", "advertisers": [{"node": "a"}]}, {"prefix": "10.0.0.0/8", "advertisers": [{"node": "a"}]}]`, "duplicate prefix"},
		{base + `, "policy": [{"action": "maybe"}]`, "want allow or deny"},
		{base + `, "policy": [{"action": "allow", "proto": ["sctp"]}]`, "want tcp, udp"},
		{base + `, "policy": [{"action": "allow", "proto": ["icmp"], "ports": [80]}]`, "icmp-only"},
		{base + `, "policy": [{"action": "allow", "identity": ["@nogroup"]}]`, "unknown group"},
		{base + `, "policy": [{"action": "allow", "ports": ["9-1"]}]`, "invalid port range"},
		{base + `, "policy": [{"action": "allow", "dst": ["10.0.0.1/8"]}]`, "host bits"},
		{base + `, "link": {"keepalive_interval": "10s", "keepalive_timeout": "5s"}`, "keepalive_timeout must be longer"},
		{base + `, "link": {"keepalive_interval": "soon"}`, "invalid duration"},
		{base + `, "log_level": "loud"`, "log_level"},
		{base + `, "routs": []`, "unknown field"},
		{`"node": "a", "network": "n", "private_key": "` + key + `", "peers": [` + peerB + `]`, "never form a link"},
	} {
		c, err := Parse([]byte("{" + tc.body + "}"))
		if err == nil {
			err = c.Validate("")
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s\n  got error %v, want %q", tc.body, err, tc.want)
		}
	}
}

func TestValidConfig(t *testing.T) {
	key, pub := seed(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "node.key"), []byte(key+"\n"), 0o600)
	body := `{
  "node": "a", "network": "n",
  "private_key_file": "node.key",
  "addresses": ["10.200.0.1", "fd00::1"],
  "listen": [{"address": "127.0.0.1:7700"}],
  "peers": [{"name": "b", "public_key": "` + pub + `", "dial": "127.0.0.1:1", "priority": 2, "relay_for": ["@g"]},
            {"name": "c", "public_key": "` + pub + `", "priority": 1}],
  "groups": {"g": ["x-*"]},
  "routes": [
    {"prefix": "10.1.0.0/16", "advertisers": [{"node": "a", "source": "preserve", "interface": "eth1", "mark": 7}]},
    {"prefix": "10.2.0.0/16", "advertisers": [{"node": "d", "priority": 1, "via": ["*"]}, {"node": "b", "priority": 2}]}
  ],
  "policy": [{"action": "allow", "identity": ["@g", "b"], "proto": ["tcp"], "ports": [22, "80-90"]}],
  "link": {"keepalive_interval": "1s", "keepalive_timeout": "3s"}
}`
	f := filepath.Join(dir, "c.json")
	os.WriteFile(f, []byte(body), 0o600)
	c, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	if c.HopLimit != DefaultHopLimit || c.Key() == nil {
		t.Fatal("defaults not filled")
	}
	lc := c.LinkConfig("b")
	if len(lc.Peers) != 1 || lc.KeepaliveTimeout.Seconds() != 3 || lc.Name != "a" {
		t.Fatalf("link config %+v", lc)
	}
	if len(c.LinkConfig().Peers) != 2 {
		t.Fatal("listener config should accept all peers")
	}
	tb, err := c.Table()
	if err != nil {
		t.Fatal(err)
	}
	// Overlay addresses become local host routes.
	if e := tb.Lookup(c.Addresses[1]); e == nil || e.Advertisers[0].Node != "a" || e.Prefix.Bits() != 128 {
		t.Fatalf("overlay route %+v", e)
	}
	e := tb.Lookup(c.Addresses[0].Next())
	if e != nil {
		t.Fatalf("unexpected route %+v", e)
	}
	// via "*" follows peer priority: c (1) before b (2).
	_, next := tb.Resolve(netipMust("10.2.0.1"), func(p string) bool { return p == "b" || p == "c" })
	if len(next) < 2 || next[0].Peer != "c" || next[1].Peer != "b" {
		t.Fatalf("next %+v", next)
	}
	_, next = tb.Resolve(netipMust("10.1.0.1"), func(string) bool { return true })
	if !next[0].Local || next[0].Egress.Interface != "eth1" || next[0].Egress.Mark != 7 || next[0].Egress.Source.String() != "preserve" {
		t.Fatalf("local %+v", next)
	}
	pol, err := c.BuildPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !pol.MayCarry("b", "x-1") || pol.MayCarry("c", "x-1") {
		t.Fatal("relay_for not applied")
	}
	m := core.FlowMeta{Proto: core.ProtoTCP, Identity: "x-9", Dst: netipPortMust("10.1.0.1:85")}
	if !pol.Allow(m) {
		t.Fatal("rule not applied")
	}
	m.Dst = netipPortMust("10.1.0.1:91")
	if pol.Allow(m) {
		t.Fatal("port range not applied")
	}
}

func TestParsePrivateKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	full := base64.StdEncoding.EncodeToString(priv)
	k, err := ParsePrivateKey(full)
	if err != nil || !k.Equal(priv) {
		t.Fatalf("full key: %v", err)
	}
	bad := append([]byte(nil), priv...)
	bad[40] ^= 1
	if _, err := ParsePrivateKey(base64.StdEncoding.EncodeToString(bad)); err == nil {
		t.Fatal("mismatched public half accepted")
	}
	s, p, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	k, err = ParsePrivateKey(s)
	if err != nil || base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)) != p {
		t.Fatal("generated pair does not match")
	}
}

func netipMust(s string) netip.Addr         { return netip.MustParseAddr(s) }
func netipPortMust(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
