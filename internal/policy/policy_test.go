package policy

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/xiongyumail/tunx/internal/core"
)

func meta(id string, proto core.Proto, src, dst string) core.FlowMeta {
	return core.FlowMeta{Proto: proto, Identity: id, Src: netip.MustParseAddrPort(src), Dst: netip.MustParseAddrPort(dst)}
}

func TestDefaultDeny(t *testing.T) {
	p, err := New(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Allow(meta("a", core.ProtoTCP, "10.0.0.1:1", "10.0.0.2:80")) {
		t.Fatal("empty policy allowed")
	}
	var nilP *Policy
	if nilP.Allow(meta("a", core.ProtoTCP, "10.0.0.1:1", "10.0.0.2:80")) {
		t.Fatal("nil policy allowed")
	}
}

func TestFirstMatchWins(t *testing.T) {
	p, err := New([]Rule{
		{Allow: false, Identities: []string{"guest-*"}},
		{Allow: true, Identities: []string{"@sites"}, Dst: []netip.Prefix{netip.MustParsePrefix("10.2.0.0/24")}, Protos: []core.Proto{core.ProtoTCP}, Ports: []PortRange{{22, 22}, {8000, 8999}}},
		{Allow: true, Identities: []string{"@sites"}, Protos: []core.Proto{core.ProtoICMP}},
		{Allow: true, Src: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/24")}, Protos: []core.Proto{core.ProtoUDP}},
	}, map[string][]string{"sites": {"site-*", "hub"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		m    core.FlowMeta
		want bool
	}{
		{meta("site-a", core.ProtoTCP, "10.1.0.5:1", "10.2.0.9:22"), true},
		{meta("site-a", core.ProtoTCP, "10.1.0.5:1", "10.2.0.9:8500"), true},
		{meta("site-a", core.ProtoTCP, "10.1.0.5:1", "10.2.0.9:23"), false},
		{meta("hub", core.ProtoTCP, "10.1.0.5:1", "10.2.0.9:22"), true},
		{meta("hub", core.ProtoTCP, "10.1.0.5:1", "10.3.0.9:22"), false},
		{meta("site-a", core.ProtoUDP, "10.1.0.5:1", "10.2.0.9:22"), true},  // rule 4 by source
		{meta("site-a", core.ProtoUDP, "10.7.0.5:1", "10.2.0.9:22"), false}, // no rule
		{meta("site-b", core.ProtoICMP, "10.1.0.5:7", "10.9.0.1:0"), true},
		{meta("site-b", core.ProtoICMPv6, "[fd00::1]:7", "[fd00::2]:0"), true},
		{meta("guest-1", core.ProtoUDP, "10.1.0.5:1", "10.2.0.9:22"), false}, // rule 1 first
		{meta("site-a", core.ProtoTCP, "[::ffff:10.1.0.5]:1", "[::ffff:10.2.0.9]:22"), true},
	} {
		if got := p.Allow(tc.m); got != tc.want {
			t.Errorf("%+v: got %v", tc.m, got)
		}
	}
}

func TestPortsNeverMatchICMP(t *testing.T) {
	p, _ := New([]Rule{{Allow: true, Ports: []PortRange{{0, 65535}}}}, nil, nil)
	if p.Allow(meta("a", core.ProtoICMP, "10.0.0.1:7", "10.0.0.2:0")) {
		t.Fatal("port rule matched icmp")
	}
	if !p.Allow(meta("a", core.ProtoUDP, "10.0.0.1:7", "10.0.0.2:0")) {
		t.Fatal("port rule missed udp")
	}
}

func TestMayCarry(t *testing.T) {
	p, err := New(nil, map[string][]string{"lan": {"term-*"}}, map[string][]string{
		"hub":   {"*"},
		"gw-a":  {"@lan"},
		"other": {"phone"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		peer, id string
		want     bool
	}{
		{"gw-a", "gw-a", true},
		{"gw-a", "term-1", true},
		{"gw-a", "gw-b", false},
		{"hub", "anyone", true},
		{"other", "phone", true},
		{"other", "phone2", false},
		{"nobody", "x", false},
		{"hub", "", false},
	} {
		if got := p.MayCarry(tc.peer, tc.id); got != tc.want {
			t.Errorf("MayCarry(%q, %q) = %v", tc.peer, tc.id, got)
		}
	}
}

func TestNewErrors(t *testing.T) {
	if _, err := New([]Rule{{Identities: []string{"@nope"}}}, nil, nil); err == nil {
		t.Error("unknown group accepted")
	}
	if _, err := New([]Rule{{Identities: []string{"[bad"}}}, nil, nil); err == nil {
		t.Error("bad glob accepted")
	}
	if _, err := New(nil, map[string][]string{"g": {"@h"}, "h": {"x"}}, map[string][]string{"p": {"@g"}}); err == nil {
		t.Error("nested group accepted")
	}
	if _, err := New([]Rule{{Ports: []PortRange{{9, 1}}}}, nil, nil); err == nil {
		t.Error("reversed port range accepted")
	}
}

func TestPortRangeJSON(t *testing.T) {
	var got []PortRange
	if err := json.Unmarshal([]byte(`[80, "443", "8000-8999"]`), &got); err != nil {
		t.Fatal(err)
	}
	want := []PortRange{{80, 80}, {443, 443}, {8000, 8999}}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v", got)
		}
	}
	for _, bad := range []string{`"9-1"`, `"x"`, `70000`, `"1-70000"`, `true`} {
		var r PortRange
		if err := json.Unmarshal([]byte(bad), &r); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
