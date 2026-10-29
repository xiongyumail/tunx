// Package route holds the route table of a node: destination prefixes, the
// nodes that advertise each one in priority order, and how to reach a remote
// advertiser. A table is immutable; Router swaps whole tables atomically so
// route updates never expose a half-applied state.
package route

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/xiongyumail/tunx/internal/egress"
)

// AnyPeer in Advertiser.Via means any connected peer, in peer priority
// order.
const AnyPeer = "*"

// Advertiser is a node that delivers a prefix.
type Advertiser struct {
	// Node is the advertising node. The table's own node means local
	// delivery.
	Node string
	// Priority orders advertisers; lower is preferred. Equal priorities keep
	// their configured order.
	Priority int
	// Via lists the peers through which Node is reached when there is no
	// session to Node itself, in order of preference. AnyPeer means every
	// connected peer.
	Via []string
	// Egress applies to local delivery.
	Egress egress.Options
}

// Entry is one prefix and its advertisers, sorted by priority.
type Entry struct {
	Prefix      netip.Prefix
	Advertisers []Advertiser
}

// Next is one way to send a flow: deliver it here, or open it on the session
// to Peer.
type Next struct {
	Local  bool
	Egress egress.Options
	// Peer is the next hop; Advertiser is the node expected to deliver.
	Peer       string
	Advertiser string
}

// Table is an immutable longest-prefix-match table.
type Table struct {
	self    string
	entries []*Entry
	// v4[bits] and v6[bits] hold the entries with that prefix length.
	v4, v6    map[int]map[netip.Prefix]*Entry
	lens4     []int // descending
	lens6     []int
	peerOrder []string // peers in priority order, for AnyPeer
}

// NewTable builds a table for node self. peers lists the configured peers in
// priority order (used for AnyPeer). Prefixes must be unique and masked.
func NewTable(self string, entries []Entry, peers []string) (*Table, error) {
	if self == "" {
		return nil, errors.New("route: empty node name")
	}
	t := &Table{
		self:      self,
		v4:        make(map[int]map[netip.Prefix]*Entry),
		v6:        make(map[int]map[netip.Prefix]*Entry),
		peerOrder: slices.Clone(peers),
	}
	for _, e := range entries {
		p := e.Prefix
		if !p.IsValid() {
			return nil, fmt.Errorf("route: invalid prefix %v", p)
		}
		if p.Addr().Is4In6() {
			return nil, fmt.Errorf("route: use a plain IPv4 prefix instead of %v", p)
		}
		if p != p.Masked() {
			return nil, fmt.Errorf("route: prefix %v has host bits set (use %v)", p, p.Masked())
		}
		if len(e.Advertisers) == 0 {
			return nil, fmt.Errorf("route %v: no advertisers", p)
		}
		m := t.v6
		if p.Addr().Is4() {
			m = t.v4
		}
		if m[p.Bits()] == nil {
			m[p.Bits()] = make(map[netip.Prefix]*Entry)
		}
		if _, dup := m[p.Bits()][p]; dup {
			return nil, fmt.Errorf("route %v: duplicate prefix", p)
		}
		ne := &Entry{Prefix: p, Advertisers: slices.Clone(e.Advertisers)}
		for i, a := range ne.Advertisers {
			if a.Node == "" {
				return nil, fmt.Errorf("route %v: advertiser %d has no node", p, i+1)
			}
		}
		slices.SortStableFunc(ne.Advertisers, func(a, b Advertiser) int { return cmp.Compare(a.Priority, b.Priority) })
		m[p.Bits()][p] = ne
		t.entries = append(t.entries, ne)
	}
	t.lens4 = lens(t.v4)
	t.lens6 = lens(t.v6)
	slices.SortFunc(t.entries, func(a, b *Entry) int {
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c
		}
		return cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits())
	})
	return t, nil
}

func lens(m map[int]map[netip.Prefix]*Entry) []int {
	var l []int
	for bits := range m {
		l = append(l, bits)
	}
	slices.SortFunc(l, func(a, b int) int { return cmp.Compare(b, a) })
	return l
}

// Self returns the node the table belongs to.
func (t *Table) Self() string { return t.self }

// Entries returns all entries sorted by prefix. The caller must not modify
// them.
func (t *Table) Entries() []*Entry { return t.entries }

// Lookup returns the longest prefix containing dst, or nil.
func (t *Table) Lookup(dst netip.Addr) *Entry {
	dst = dst.Unmap().WithZone("")
	m, ls := t.v6, t.lens6
	if dst.Is4() {
		m, ls = t.v4, t.lens4
	}
	for _, bits := range ls {
		p, err := dst.Prefix(bits)
		if err != nil {
			continue
		}
		if e := m[bits][p]; e != nil {
			return e
		}
	}
	return nil
}

// Resolve returns the ways to send a flow to dst, best first, given which
// peers have a session up. Advertisers are tried in priority order: the own
// node means local delivery (and ends the list); a remote advertiser is used
// directly when its session is up, otherwise through its Via peers that are
// up. A shorter prefix is never used as a fallback when the longest match has
// no reachable advertiser.
func (t *Table) Resolve(dst netip.Addr, up func(peer string) bool) (*Entry, []Next) {
	e := t.Lookup(dst)
	if e == nil {
		return nil, nil
	}
	return e, t.resolveEntry(e, up)
}

func (t *Table) resolveEntry(e *Entry, up func(peer string) bool) []Next {
	var out []Next
	seen := make(map[string]bool)
	add := func(peer, adv string) {
		if peer == t.self || seen[peer] || !up(peer) {
			return
		}
		seen[peer] = true
		out = append(out, Next{Peer: peer, Advertiser: adv})
	}
	for _, a := range e.Advertisers {
		if a.Node == t.self {
			return append(out, Next{Local: true, Egress: a.Egress, Advertiser: a.Node})
		}
		add(a.Node, a.Node)
		for _, v := range a.Via {
			if v == AnyPeer {
				for _, p := range t.peerOrder {
					add(p, a.Node)
				}
				continue
			}
			add(v, a.Node)
		}
	}
	return out
}

// Selected returns the first way Resolve would pick for e.
func (t *Table) Selected(e *Entry, up func(peer string) bool) (Next, bool) {
	n := t.resolveEntry(e, up)
	if len(n) == 0 {
		return Next{}, false
	}
	return n[0], true
}

// Router holds the current table. Readers never block; Store replaces the
// whole table at once.
type Router struct{ p atomic.Pointer[Table] }

// NewRouter returns a router holding t.
func NewRouter(t *Table) *Router {
	r := &Router{}
	r.p.Store(t)
	return r
}

// Table returns the current table.
func (r *Router) Table() *Table { return r.p.Load() }

// Store replaces the table.
func (r *Router) Store(t *Table) { r.p.Store(t) }
