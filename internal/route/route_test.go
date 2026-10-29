package route

import (
	"net/netip"
	"reflect"
	"testing"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func ip(s string) netip.Addr    { return netip.MustParseAddr(s) }

func upSet(peers ...string) func(string) bool {
	m := map[string]bool{}
	for _, p := range peers {
		m[p] = true
	}
	return func(p string) bool { return m[p] }
}

func TestLongestPrefixMatch(t *testing.T) {
	tb, err := NewTable("a", []Entry{
		{Prefix: pfx("0.0.0.0/0"), Advertisers: []Advertiser{{Node: "exit"}}},
		{Prefix: pfx("10.0.0.0/8"), Advertisers: []Advertiser{{Node: "b"}}},
		{Prefix: pfx("10.1.0.0/16"), Advertisers: []Advertiser{{Node: "c"}}},
		{Prefix: pfx("10.1.2.3/32"), Advertisers: []Advertiser{{Node: "a"}}},
		{Prefix: pfx("::/0"), Advertisers: []Advertiser{{Node: "exit"}}},
		{Prefix: pfx("fd00::/8"), Advertisers: []Advertiser{{Node: "b"}}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for dst, want := range map[string]string{
		"10.1.2.3":        "10.1.2.3/32",
		"10.1.9.9":        "10.1.0.0/16",
		"10.200.0.1":      "10.0.0.0/8",
		"8.8.8.8":         "0.0.0.0/0",
		"::ffff:10.1.9.9": "10.1.0.0/16", // mapped addresses use the IPv4 table
		"fd00::1":         "fd00::/8",
		"2001:db8::1":     "::/0",
		"fd00::1%eth0":    "fd00::/8",
	} {
		e := tb.Lookup(ip(dst))
		if e == nil || e.Prefix.String() != want {
			t.Errorf("%s: got %v, want %s", dst, e, want)
		}
	}
	empty, _ := NewTable("a", nil, nil)
	if empty.Lookup(ip("1.2.3.4")) != nil {
		t.Fatal("empty table matched")
	}
}

func TestResolveOrderAndFailover(t *testing.T) {
	tb, err := NewTable("a", []Entry{{
		Prefix: pfx("10.2.0.0/24"),
		Advertisers: []Advertiser{
			{Node: "c", Priority: 2, Via: []string{"hub"}},
			{Node: "b", Priority: 1},
			{Node: "d", Priority: 3, Via: []string{AnyPeer}},
		},
	}}, []string{"hub", "x", "b"})
	if err != nil {
		t.Fatal(err)
	}
	dst := ip("10.2.0.7")
	for _, tc := range []struct {
		up   []string
		want []Next
	}{
		{[]string{"b", "c", "hub", "x"}, []Next{{Peer: "b", Advertiser: "b"}, {Peer: "c", Advertiser: "c"}, {Peer: "hub", Advertiser: "c"}, {Peer: "x", Advertiser: "d"}}},
		{[]string{"c", "hub"}, []Next{{Peer: "c", Advertiser: "c"}, {Peer: "hub", Advertiser: "c"}}},
		{[]string{"hub"}, []Next{{Peer: "hub", Advertiser: "c"}}},
		{[]string{"x"}, []Next{{Peer: "x", Advertiser: "d"}}},
		{nil, nil},
	} {
		_, got := tb.Resolve(dst, upSet(tc.up...))
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("up %v: got %+v, want %+v", tc.up, got, tc.want)
		}
	}
}

func TestResolveLocalEndsList(t *testing.T) {
	tb, _ := NewTable("a", []Entry{{
		Prefix:      pfx("10.3.0.0/24"),
		Advertisers: []Advertiser{{Node: "b", Priority: 1}, {Node: "a", Priority: 2}, {Node: "c", Priority: 3}},
	}}, nil)
	_, got := tb.Resolve(ip("10.3.0.1"), upSet("b", "c"))
	if len(got) != 2 || got[0].Peer != "b" || !got[1].Local {
		t.Fatalf("got %+v", got)
	}
	_, got = tb.Resolve(ip("10.3.0.1"), upSet("c"))
	if len(got) != 1 || !got[0].Local {
		t.Fatalf("got %+v", got)
	}
}

func TestNoFallbackToShorterPrefix(t *testing.T) {
	tb, _ := NewTable("a", []Entry{
		{Prefix: pfx("0.0.0.0/0"), Advertisers: []Advertiser{{Node: "exit"}}},
		{Prefix: pfx("10.0.0.0/8"), Advertisers: []Advertiser{{Node: "b"}}},
	}, nil)
	e, next := tb.Resolve(ip("10.0.0.1"), upSet("exit"))
	if e == nil || e.Prefix != pfx("10.0.0.0/8") || len(next) != 0 {
		t.Fatalf("got %v %+v", e, next)
	}
}

func TestNewTableErrors(t *testing.T) {
	for name, entries := range map[string][]Entry{
		"host bits":      {{Prefix: pfx("10.0.0.1/8"), Advertisers: []Advertiser{{Node: "b"}}}},
		"duplicate":      {{Prefix: pfx("10.0.0.0/8"), Advertisers: []Advertiser{{Node: "b"}}}, {Prefix: pfx("10.0.0.0/8"), Advertisers: []Advertiser{{Node: "c"}}}},
		"no advertisers": {{Prefix: pfx("10.0.0.0/8")}},
		"empty node":     {{Prefix: pfx("10.0.0.0/8"), Advertisers: []Advertiser{{}}}},
		"mapped":         {{Prefix: pfx("::ffff:10.0.0.0/104"), Advertisers: []Advertiser{{Node: "b"}}}},
	} {
		if _, err := NewTable("a", entries, nil); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestRouterSwap(t *testing.T) {
	t1, _ := NewTable("a", []Entry{{Prefix: pfx("10.0.0.0/8"), Advertisers: []Advertiser{{Node: "b"}}}}, nil)
	t2, _ := NewTable("a", nil, nil)
	r := NewRouter(t1)
	if r.Table().Lookup(ip("10.0.0.1")) == nil {
		t.Fatal("lookup")
	}
	r.Store(t2)
	if r.Table().Lookup(ip("10.0.0.1")) != nil {
		t.Fatal("old table still used")
	}
}
