// Package render computes the tunxd and Xray configs of one node from the
// network description. Output is deterministic: the same Spec always
// renders to the same bytes.
package render

import (
	"cmp"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/xiongyumail/tunx/internal/config"
	"github.com/xiongyumail/tunx/internal/hub/model"
	"github.com/xiongyumail/tunx/internal/policy"
)

// KeyFile is the private key file named in rendered tunxd configs. The node
// writes the key it received at enrolment there, next to the config.
const KeyFile = "node.key"

// Bundle is everything one node needs.
type Bundle struct {
	Node string `json:"node"`
	// Revision is a hash of the rendered content; it changes exactly when
	// the content changes.
	Revision string         `json:"revision"`
	Tunxd    *config.Config `json:"tunxd"`
	Xray     map[string]any `json:"xray"`
	// ClientSOCKS is the local SOCKS server tunxd must run for standard
	// clients attached to this node (not yet in the tunxd config).
	ClientSOCKS *ClientSOCKS `json:"client_socks,omitempty"`
	Warnings    []string     `json:"warnings,omitempty"`
}

// ClientSOCKS lists the per-client accounts of the local SOCKS server. A
// connection authenticated as Name carries the identity Name.
type ClientSOCKS struct {
	Listen string      `json:"listen"`
	Users  []SOCKSUser `json:"users"`
}

// SOCKSUser is one client account.
type SOCKSUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type renderer struct {
	spec     *model.Spec
	self     *model.Node
	g        *graph
	warnings []string
}

// Node renders the configs of one node. The spec must be valid.
func Node(s *model.Spec, name string) (*Bundle, error) {
	self := s.Node(name)
	if self == nil {
		return nil, fmt.Errorf("node %q: %w", name, model.ErrNotFound)
	}
	r := &renderer{spec: s, self: self, g: newGraph(s)}
	for i := range s.Links {
		l := &s.Links[i]
		if l.Disabled || (l.Dialer != name && l.Listener != name) {
			continue
		}
		other := l.Listener
		if other == name {
			other = l.Dialer
		}
		if s.Node(other).PublicKey == "" {
			r.warn("link %q: node %q is not enrolled; link skipped", l.Name, other)
		} else if self.PublicKey == "" {
			r.warn("link %q: this node is not enrolled; link skipped", l.Name)
		} else if best := r.g.best[pairKey(l.Dialer, l.Listener)]; best != l {
			r.warn("link %q: standby for %q (tunxd dials one link per peer)", l.Name, best.Name)
		}
	}
	tc, err := r.tunxd()
	if err != nil {
		return nil, err
	}
	b := &Bundle{Node: name, Tunxd: tc, Xray: r.xray(), ClientSOCKS: r.clientSOCKS()}
	if err := checkTunxd(tc); err != nil {
		return nil, fmt.Errorf("node %q: rendered tunxd config is invalid: %w", name, err)
	}
	b.Warnings = r.warnings
	b.Revision, err = revision(b)
	return b, err
}

func (r *renderer) warn(format string, args ...any) {
	r.warnings = append(r.warnings, fmt.Sprintf(format, args...))
}

func revision(b *Bundle) (string, error) {
	c := *b
	c.Revision, c.Warnings = "", nil
	j, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(j)
	return hex.EncodeToString(h[:12]), nil
}

// checkTunxd validates a copy of the config as tunxd would load it, with a
// throwaway key in place of the key file.
func checkTunxd(c *config.Config) error {
	j, err := json.Marshal(c)
	if err != nil {
		return err
	}
	cp, err := config.Parse(j)
	if err != nil {
		return err
	}
	cp.PrivateKeyFile = ""
	cp.SetKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	return cp.Validate("")
}

// peerLinks returns the active links of this node that tunxd uses, one per
// peer, sorted by peer name.
func (r *renderer) peerLinks() []*model.Link {
	var out []*model.Link
	if r.g.nodes[r.self.Name] == nil {
		return nil
	}
	for k, l := range r.g.best {
		if k[0] == r.self.Name || k[1] == r.self.Name {
			out = append(out, l)
		}
	}
	slices.SortFunc(out, func(a, b *model.Link) int { return cmp.Compare(r.other(a), r.other(b)) })
	return out
}

func (r *renderer) other(l *model.Link) string {
	if l.Dialer == r.self.Name {
		return l.Listener
	}
	return l.Dialer
}

// dialLinks returns the active links this node dials, by name, with the
// loopback port of the Xray inbound tunxd connects to for each.
func (r *renderer) dialLinks() ([]*model.Link, map[string]int) {
	var out []*model.Link
	for i := range r.spec.Links {
		l := &r.spec.Links[i]
		if l.Dialer == r.self.Name && r.g.active(l) {
			out = append(out, l)
		}
	}
	base := cmp.Or(r.self.DialPortBase, model.DefaultDialPortBase)
	ports := map[string]int{}
	for i, l := range out {
		ports[l.Name] = base + i
	}
	return out, ports
}

// listening reports whether some active link arrives at this node.
func (r *renderer) listening() bool {
	for i := range r.spec.Links {
		l := &r.spec.Links[i]
		if l.Listener == r.self.Name && r.g.active(l) {
			return true
		}
	}
	return false
}

func (r *renderer) clientsOf(node string) []*model.Client {
	var out []*model.Client
	for i := range r.spec.Clients {
		if c := &r.spec.Clients[i]; c.Node == node && !c.Disabled {
			out = append(out, c)
		}
	}
	return out
}

func (r *renderer) tunxd() (*config.Config, error) {
	s, n := r.spec, r.self
	c := &config.Config{
		Node:           n.Name,
		Network:        s.Network.Name,
		PrivateKeyFile: KeyFile,
		HopLimit:       s.Network.HopLimit,
		Status:         n.Status,
		LogLevel:       n.LogLevel,
	}
	for _, a := range n.Addresses {
		c.Addresses = append(c.Addresses, netip.MustParseAddr(a))
	}
	if r.listening() {
		c.Listen = []config.Listener{{Address: linkListen(n)}}
	}
	_, ports := r.dialLinks()
	for _, l := range r.peerLinks() {
		peer := r.other(l)
		pk, err := base64.StdEncoding.DecodeString(r.g.nodes[peer].PublicKey)
		if err != nil {
			return nil, fmt.Errorf("node %q: public key: %v", peer, err)
		}
		p := config.Peer{Name: peer, PublicKey: config.PublicKey(pk), Priority: l.Priority}
		if l.Dialer == n.Name {
			p.Dial = net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[l.Name]))
		}
		p.RelayFor = r.relayFor(peer)
		c.Peers = append(c.Peers, p)
	}
	c.Routes = r.routes()
	c.Policy, c.Groups = r.policy(c.Routes)
	if n.TUN != nil {
		c.TUN = r.tun(c.Routes)
	}
	return c, nil
}

func linkListen(n *model.Node) string { return cmp.Or(n.LinkListen, model.DefaultLinkListen) }

// relayFor lists the identities other than its own a peer may carry: the
// clients attached to it and, for a relay, every node (and their clients)
// it reaches without this node.
func (r *renderer) relayFor(peer string) []string {
	var ids []string
	for _, n := range r.g.carried(r.self.Name, peer) {
		if n != peer {
			ids = append(ids, n)
		}
		for _, c := range r.clientsOf(n) {
			ids = append(ids, c.Name)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

type advertiser struct {
	model.RouteAdvertiser
	cost int
}

func (r *renderer) routes() []config.Route {
	s, self := r.spec, r.self.Name
	type entry struct {
		name string
		advs []model.RouteAdvertiser
	}
	entries := map[netip.Prefix]*entry{}
	addAdv := func(p netip.Prefix, name string, a model.RouteAdvertiser) {
		e := entries[p]
		if e == nil {
			e = &entry{name: name}
			entries[p] = e
		}
		if !slices.ContainsFunc(e.advs, func(x model.RouteAdvertiser) bool { return x.Node == a.Node }) {
			e.advs = append(e.advs, a)
		}
	}
	for _, rt := range s.Routes {
		p, _ := model.ParsePrefix(rt.Prefix)
		for _, a := range rt.Advertisers {
			addAdv(p, "route "+rt.Name, a)
		}
	}
	for _, n := range s.Nodes {
		if n.Name == self || r.g.nodes[n.Name] == nil {
			continue
		}
		for _, a := range n.Addresses {
			ip := netip.MustParseAddr(a)
			p := netip.PrefixFrom(ip, ip.BitLen())
			if entries[p] == nil {
				addAdv(p, "node "+n.Name, model.RouteAdvertiser{Node: n.Name})
			}
		}
	}
	for _, a := range r.exits() {
		for _, p := range []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")} {
			addAdv(p, "egress", a)
		}
	}

	var out []config.Route
	for p, e := range entries {
		var advs []advertiser
		for _, a := range e.advs {
			if a.Node == self {
				advs = append(advs, advertiser{RouteAdvertiser: a})
				continue
			}
			if r.g.nodes[a.Node] == nil {
				continue
			}
			h, ok := r.g.reach(self, a.Node)
			if !ok {
				continue
			}
			ra := model.RouteAdvertiser{Node: a.Node, Priority: a.Priority}
			advs = append(advs, advertiser{RouteAdvertiser: ra, cost: h.cost})
		}
		if len(advs) == 0 {
			if strings.HasPrefix(e.name, "route ") {
				r.warn("%s (%v): no advertiser reachable from this node", e.name, p)
			}
			continue
		}
		slices.SortStableFunc(advs, func(a, b advertiser) int {
			return cmp.Or(cmp.Compare(a.Priority, b.Priority), cmp.Compare(a.cost, b.cost))
		})
		cr := config.Route{Prefix: p}
		for _, a := range advs {
			ca := config.Advertiser{Node: a.Node, Priority: a.Priority}
			if a.Node == self {
				ca.Source, ca.Interface, ca.Mark = a.Source, a.Interface, a.Mark
			} else {
				h, _ := r.g.reach(self, a.Node)
				ca.Via = h.via
			}
			cr.Advertisers = append(cr.Advertisers, ca)
		}
		out = append(out, cr)
	}
	slices.SortFunc(out, func(a, b config.Route) int { return comparePrefix(a.Prefix, b.Prefix) })
	return out
}

func comparePrefix(a, b netip.Prefix) int {
	return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
}

// exits returns the default route advertisers of this node: its own
// delivery when it is the exit of an egress policy, else the exits of the
// policies matching it or its clients and, on a relay, of every policy.
func (r *renderer) exits() []model.RouteAdvertiser {
	s, self := r.spec, r.self
	ids := []string{self.Name}
	for _, c := range r.clientsOf(self.Name) {
		ids = append(ids, c.Name)
	}
	var out []model.RouteAdvertiser
	add := func(e model.EgressPolicy) {
		if !slices.ContainsFunc(out, func(a model.RouteAdvertiser) bool { return a.Node == e.Exit }) {
			out = append(out, model.RouteAdvertiser{Node: e.Exit, Priority: e.Priority})
		}
	}
	for _, e := range s.Egress {
		if e.Exit == self.Name {
			return []model.RouteAdvertiser{{Node: self.Name}}
		}
	}
	for _, e := range s.Egress {
		if slices.ContainsFunc(ids, func(id string) bool { return r.matchesAny(e.Sources, id) }) {
			add(e)
		}
	}
	if self.HasCap(model.CapRelay) {
		for _, e := range s.Egress {
			add(e)
		}
	}
	return out
}

func (r *renderer) tun(routes []config.Route) *config.TUN {
	n := r.self
	t := &config.TUN{Name: n.TUN.Name, MTU: n.TUN.MTU}
	for _, a := range n.Addresses {
		ip := netip.MustParseAddr(a)
		if p, ok := r.spec.NetworkPrefix(ip); ok {
			t.Addresses = append(t.Addresses, netip.PrefixFrom(ip, p.Bits()))
		}
	}
	for _, rt := range routes {
		p := rt.Prefix
		if p.Bits() == 0 || slices.ContainsFunc(rt.Advertisers, func(a config.Advertiser) bool { return a.Node == n.Name }) {
			continue
		}
		if _, inOverlay := r.spec.NetworkPrefix(p.Addr()); inOverlay {
			continue
		}
		t.Capture = append(t.Capture, p)
	}
	return t
}

// identityPatterns expands selectors into tunxd identity patterns. A
// "group:" selector stays a group reference.
func (r *renderer) identityPatterns(sels []string) []string {
	var out []string
	for _, sel := range sels {
		kind, val, ok := strings.Cut(sel, ":")
		switch {
		case !ok:
			out = append(out, sel)
		case kind == "node", kind == "client":
			out = append(out, val)
		case kind == "group":
			out = append(out, "@"+val)
		case kind == "tag":
			for _, n := range r.spec.Nodes {
				if n.HasTag(val) {
					out = append(out, n.Name)
				}
			}
			for _, c := range r.spec.Clients {
				if slices.Contains(c.Tags, val) {
					out = append(out, c.Name)
				}
			}
		}
	}
	return out
}

// matchesAny reports whether an identity matches any selector.
func (r *renderer) matchesAny(sels []string, id string) bool {
	for _, p := range r.identityPatterns(sels) {
		if g, ok := strings.CutPrefix(p, "@"); ok {
			if grp := r.spec.Group(g); grp != nil && r.matchesAny(grp.Members, id) {
				return true
			}
			continue
		}
		if ok, _ := path.Match(p, id); ok {
			return true
		}
	}
	return false
}

func (r *renderer) destPrefixes(sels []string) []netip.Prefix {
	var out []netip.Prefix
	addNode := func(n *model.Node) {
		for _, a := range n.Addresses {
			ip := netip.MustParseAddr(a)
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	for _, sel := range sels {
		kind, val, ok := strings.Cut(sel, ":")
		switch {
		case ok && kind == "node":
			addNode(r.spec.Node(val))
		case ok && kind == "tag":
			for i := range r.spec.Nodes {
				if r.spec.Nodes[i].HasTag(val) {
					addNode(&r.spec.Nodes[i])
				}
			}
		case strings.Contains(sel, "/"):
			out = append(out, netip.MustParsePrefix(sel))
		default:
			ip := netip.MustParseAddr(sel)
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	return out
}

// delivered returns the prefixes this node delivers: its addresses, the
// routes it advertises and, for an exit, the default routes.
func (r *renderer) delivered(routes []config.Route) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range r.self.Addresses {
		ip := netip.MustParseAddr(a)
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	for _, rt := range routes {
		if slices.ContainsFunc(rt.Advertisers, func(a config.Advertiser) bool { return a.Node == r.self.Name }) {
			out = append(out, rt.Prefix)
		}
	}
	return out
}

// policy renders the access rules that can apply at this node: rules whose
// sources match an identity entering here (the node and its clients) or
// whose destinations overlap what this node delivers. Dropping the others
// keeps first-match results unchanged for every flow this node checks.
func (r *renderer) policy(routes []config.Route) ([]config.Rule, map[string][]string) {
	self := r.self
	ingress := []string{self.Name}
	for _, c := range r.clientsOf(self.Name) {
		ingress = append(ingress, c.Name)
	}
	delivered := r.delivered(routes)
	var rules []config.Rule
	groups := map[string][]string{}
	for _, a := range r.spec.Access {
		ids := r.identityPatterns(a.Sources)
		dst := r.destPrefixes(a.Destinations)
		if len(a.Sources) > 0 && len(ids) == 0 || len(a.Destinations) > 0 && len(dst) == 0 {
			continue // a selector that selects nothing matches no flow
		}
		srcHere := len(a.Sources) == 0 || slices.ContainsFunc(ingress, func(id string) bool { return r.matchesAny(a.Sources, id) })
		dstHere := len(dst) == 0 || slices.ContainsFunc(dst, func(p netip.Prefix) bool {
			return slices.ContainsFunc(delivered, p.Overlaps)
		})
		if !srcHere && !dstHere {
			continue
		}
		rule := config.Rule{Action: a.Action, Identity: ids, Dst: dst, Proto: a.Proto}
		for _, p := range a.SourcePrefixes {
			rule.Src = append(rule.Src, netip.MustParsePrefix(p))
		}
		for _, p := range a.Ports {
			pr, _ := policy.ParsePortRange(p)
			rule.Ports = append(rule.Ports, pr)
		}
		for _, id := range ids {
			if g, ok := strings.CutPrefix(id, "@"); ok {
				members := r.identityPatterns(r.spec.Group(g).Members)
				if members == nil {
					members = []string{}
				}
				groups[g] = members
			}
		}
		rules = append(rules, rule)
	}
	if len(groups) == 0 {
		groups = nil
	}
	return rules, groups
}

func (r *renderer) clientSOCKS() *ClientSOCKS {
	cs := r.clientsOf(r.self.Name)
	if len(cs) == 0 {
		return nil
	}
	out := &ClientSOCKS{Listen: cmp.Or(r.self.ClientListen, model.DefaultClientListen)}
	for _, c := range cs {
		out.Users = append(out.Users, SOCKSUser{Name: c.Name, Password: c.Password})
	}
	return out
}
