package model

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/xiongyumail/tunx/internal/policy"
)

// MaxNameLen bounds object names; node and client names are tunxd
// identities and follow its limit.
const MaxNameLen = 64

// Ports is a list of destination ports or ranges ("22", "8000-8999"). JSON
// and YAML accept numbers as well as strings.
type Ports []string

func (p *Ports) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("ports: want a list: %v", err)
	}
	out := make(Ports, 0, len(raw))
	for _, r := range raw {
		var n json.Number
		if err := json.Unmarshal(r, &n); err == nil {
			out = append(out, n.String())
			continue
		}
		var s string
		if err := json.Unmarshal(r, &s); err != nil {
			return fmt.Errorf("ports: invalid entry %s", r)
		}
		out = append(out, s)
	}
	*p = out
	return nil
}

func (p *Ports) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return fmt.Errorf("line %d: ports: want a list", n.Line)
	}
	out := make(Ports, 0, len(n.Content))
	for _, c := range n.Content {
		if c.Kind != yaml.ScalarNode {
			return fmt.Errorf("line %d: ports: invalid entry", c.Line)
		}
		out = append(out, c.Value)
	}
	*p = out
	return nil
}

// Canonicalize sorts every list into the order used for storage, export
// and rendering.
func (s *Spec) Canonicalize() {
	byName := func(a, b string) int { return strings.Compare(a, b) }
	slices.SortFunc(s.Groups, func(a, b Group) int { return byName(a.Name, b.Name) })
	slices.SortFunc(s.Nodes, func(a, b Node) int { return byName(a.Name, b.Name) })
	slices.SortFunc(s.Links, func(a, b Link) int { return byName(a.Name, b.Name) })
	slices.SortFunc(s.Routes, func(a, b Route) int { return byName(a.Name, b.Name) })
	slices.SortFunc(s.Access, func(a, b AccessPolicy) int {
		return cmp.Or(cmp.Compare(a.Priority, b.Priority), byName(a.Name, b.Name))
	})
	slices.SortFunc(s.Egress, func(a, b EgressPolicy) int {
		return cmp.Or(cmp.Compare(a.Priority, b.Priority), byName(a.Name, b.Name))
	})
	slices.SortFunc(s.Clients, func(a, b Client) int { return byName(a.Name, b.Name) })
}

var tagRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// CheckName validates an object name. Node and client names are tunxd
// identities: 1..64 bytes, no whitespace or *?[]@/\ and no ':'.
func CheckName(field, s string) error {
	if s == "" || len(s) > MaxNameLen {
		return fmt.Errorf("%s: must be 1..%d bytes", field, MaxNameLen)
	}
	if strings.ContainsAny(s, " \t\r\n*?[]@/\\:%") {
		return fmt.Errorf("%s: %q contains whitespace or one of *?[]@/\\:%%", field, s)
	}
	return nil
}

// Validate checks the whole network: syntax of every object and every
// reference between objects.
func (s *Spec) Validate() error {
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	add(s.validateNetwork())

	identities := map[string]string{}
	addrs := map[netip.Addr]string{}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if err := s.validateNode(n, addrs); err != nil {
			add(fmt.Errorf("node %q: %w", n.Name, err))
		}
		if prev, dup := identities[n.Name]; dup {
			add(fmt.Errorf("node %q: name already used by a %s", n.Name, prev))
		}
		identities[n.Name] = "node"
	}
	for i := range s.Clients {
		c := &s.Clients[i]
		if err := s.validateClient(c); err != nil {
			add(fmt.Errorf("client %q: %w", c.Name, err))
		}
		if prev, dup := identities[c.Name]; dup {
			add(fmt.Errorf("client %q: name already used by a %s", c.Name, prev))
		}
		identities[c.Name] = "client"
	}
	names := map[string]bool{}
	for i := range s.Groups {
		g := &s.Groups[i]
		add(unique(names, "group", g.Name))
		if err := CheckName("name", g.Name); err != nil {
			add(fmt.Errorf("group %q: %w", g.Name, err))
		}
		for _, m := range g.Members {
			if err := s.checkIdentitySelector(m, false); err != nil {
				add(fmt.Errorf("group %q: %w", g.Name, err))
			}
		}
	}
	clear(names)
	for i := range s.Links {
		l := &s.Links[i]
		add(unique(names, "link", l.Name))
		if err := s.validateLink(l); err != nil {
			add(fmt.Errorf("link %q: %w", l.Name, err))
		}
	}
	clear(names)
	prefixes := map[netip.Prefix]string{}
	for i := range s.Routes {
		r := &s.Routes[i]
		add(unique(names, "route", r.Name))
		if err := s.validateRoute(r, prefixes); err != nil {
			add(fmt.Errorf("route %q: %w", r.Name, err))
		}
	}
	clear(names)
	for i := range s.Access {
		a := &s.Access[i]
		add(unique(names, "access policy", a.Name))
		if err := s.validateAccess(a); err != nil {
			add(fmt.Errorf("access policy %q: %w", a.Name, err))
		}
	}
	clear(names)
	for i := range s.Egress {
		e := &s.Egress[i]
		add(unique(names, "egress policy", e.Name))
		if err := s.validateEgress(e); err != nil {
			add(fmt.Errorf("egress policy %q: %w", e.Name, err))
		}
	}
	return errors.Join(errs...)
}

func unique(seen map[string]bool, kind, name string) error {
	if seen[name] {
		return fmt.Errorf("duplicate %s %q", kind, name)
	}
	seen[name] = true
	return nil
}

func (s *Spec) validateNetwork() error {
	n := s.Network
	if err := CheckName("network.name", n.Name); err != nil {
		return err
	}
	for _, p := range n.Prefixes {
		if _, err := ParsePrefix(p); err != nil {
			return fmt.Errorf("network.prefixes: %w", err)
		}
	}
	if n.DNSSuffix != "" && strings.ContainsAny(n.DNSSuffix, " \t/@") {
		return fmt.Errorf("network.dns_suffix: invalid %q", n.DNSSuffix)
	}
	if n.HopLimit < 0 || n.HopLimit > 255 {
		return fmt.Errorf("network.hop_limit: %d out of range 0..255", n.HopLimit)
	}
	return nil
}

// ParsePrefix parses a masked prefix.
func ParsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return p, fmt.Errorf("invalid prefix %q", s)
	}
	if p.Addr().Is4In6() || p.Addr().Zone() != "" {
		return p, fmt.Errorf("invalid prefix %q", s)
	}
	if p != p.Masked() {
		return p, fmt.Errorf("prefix %v has host bits set (use %v)", p, p.Masked())
	}
	return p, nil
}

// NetworkPrefix returns the overlay prefix that contains a.
func (s *Spec) NetworkPrefix(a netip.Addr) (netip.Prefix, bool) {
	for _, ps := range s.Network.Prefixes {
		if p, err := ParsePrefix(ps); err == nil && p.Contains(a) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

var validCaps = []string{CapListen, CapRelay, CapAdvertise, CapExit}

func (s *Spec) validateNode(n *Node, addrs map[netip.Addr]string) error {
	if err := CheckName("name", n.Name); err != nil {
		return err
	}
	if n.PublicKey != "" {
		b, err := base64.StdEncoding.DecodeString(n.PublicKey)
		if err != nil || len(b) != 32 {
			return errors.New("public_key: want base64 of 32 bytes")
		}
	}
	for _, a := range n.Addresses {
		ip, err := netip.ParseAddr(a)
		if err != nil || ip.Zone() != "" || ip.Is4In6() {
			return fmt.Errorf("addresses: invalid address %q", a)
		}
		if _, ok := s.NetworkPrefix(ip); !ok {
			return fmt.Errorf("addresses: %v is outside the network prefixes", ip)
		}
		if prev, dup := addrs[ip]; dup {
			return fmt.Errorf("addresses: %v already used by node %q", ip, prev)
		}
		addrs[ip] = n.Name
	}
	for _, t := range n.Tags {
		if !tagRE.MatchString(t) {
			return fmt.Errorf("tags: invalid tag %q", t)
		}
	}
	for _, c := range n.Capabilities {
		if !slices.Contains(validCaps, c) {
			return fmt.Errorf("capabilities: %q: want one of %s", c, strings.Join(validCaps, ", "))
		}
	}
	if len(n.Endpoints) > 0 && !n.HasCap(CapListen) {
		return errors.New("endpoints need the listen capability")
	}
	seen := map[string]bool{}
	ports := map[string]string{}
	for i := range n.Endpoints {
		e := &n.Endpoints[i]
		if err := unique(seen, "endpoint", e.Name); err != nil {
			return err
		}
		if err := validateEndpoint(e); err != nil {
			return fmt.Errorf("endpoint %q: %w", e.Name, err)
		}
		bind := net.JoinHostPort(cmp.Or(e.Listen, "0.0.0.0"), strconv.Itoa(e.Port))
		if prev, dup := ports[bind]; dup {
			return fmt.Errorf("endpoint %q: %s already used by endpoint %q", e.Name, bind, prev)
		}
		ports[bind] = e.Name
	}
	clear(seen)
	for _, p := range n.Proxies {
		if err := unique(seen, "proxy", p.Name); err != nil {
			return err
		}
		if err := CheckName("proxy name", p.Name); err != nil {
			return err
		}
		if proto, _ := p.Outbound["protocol"].(string); proto == "" {
			return fmt.Errorf("proxy %q: outbound needs a protocol", p.Name)
		}
	}
	if t := n.TUN; t != nil {
		if t.Name == "" || len(t.Name) >= 16 {
			return errors.New("tun.name: must be 1..15 characters")
		}
		if t.MTU != 0 && (t.MTU < 576 || t.MTU > 65535) {
			return fmt.Errorf("tun.mtu: %d out of range 576..65535", t.MTU)
		}
	}
	for field, a := range map[string]string{"link_listen": n.LinkListen, "client_listen": n.ClientListen, "status": n.Status} {
		if a == "" {
			continue
		}
		if err := checkLoopback(a); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	if n.DialPortBase < 0 || n.DialPortBase > 65000 {
		return fmt.Errorf("dial_port_base: %d out of range", n.DialPortBase)
	}
	switch n.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level: %q: want debug, info, warn or error", n.LogLevel)
	}
	return nil
}

func checkLoopback(a string) error {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return fmt.Errorf("address %q: %v", a, err)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("address %q: invalid port", a)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("address %q must be a loopback IP and port", a)
	}
	return nil
}

func validateEndpoint(e *Endpoint) error {
	if err := CheckName("name", e.Name); err != nil {
		return err
	}
	if e.Address == "" || strings.ContainsAny(e.Address, " /") {
		return fmt.Errorf("address: invalid %q", e.Address)
	}
	if e.Port < 1 || e.Port > 65535 {
		return fmt.Errorf("port: %d out of range 1..65535", e.Port)
	}
	if e.Listen != "" {
		if _, err := netip.ParseAddr(e.Listen); err != nil {
			return fmt.Errorf("listen: invalid address %q", e.Listen)
		}
	}
	switch e.Network {
	case "", "raw":
		if e.Path != "" {
			return errors.New("path applies to the xhttp network only")
		}
	case "xhttp":
		if e.Transport == TransportSOCKS {
			return errors.New("socks endpoints use the raw network")
		}
		if e.Path != "" && !strings.HasPrefix(e.Path, "/") {
			return errors.New("path must start with /")
		}
	default:
		return fmt.Errorf("network %q: want raw or xhttp", e.Network)
	}
	switch e.Transport {
	case TransportReality:
		r := e.Reality
		if r == nil || r.Target == "" || len(r.ServerNames) == 0 {
			return errors.New("reality: target and server_names are required")
		}
		if _, _, err := net.SplitHostPort(r.Target); err != nil {
			return fmt.Errorf("reality.target: %v", err)
		}
		if r.PrivateKey != "" {
			if b, err := base64.RawURLEncoding.DecodeString(r.PrivateKey); err != nil || len(b) != 32 {
				return errors.New("reality.private_key: want base64url of 32 bytes")
			}
		}
	case TransportTLS:
		t := e.TLS
		if t == nil || t.ServerName == "" || t.CertFile == "" || t.KeyFile == "" {
			return errors.New("tls: server_name, cert_file and key_file are required")
		}
	case TransportVLESS:
		if !privateAddress(e.Address) {
			return fmt.Errorf("address %q: Xray refuses plain VLESS to public addresses; use a private IP or a .lan, .local, .internal or .home.arpa name, or reality or tls", e.Address)
		}
	case TransportSOCKS:
	default:
		return fmt.Errorf("transport %q: want reality, tls, vless or socks", e.Transport)
	}
	if e.Reality != nil && e.Transport != TransportReality {
		return errors.New("reality settings on a non-reality endpoint")
	}
	if e.TLS != nil && e.Transport != TransportTLS {
		return errors.New("tls settings on a non-tls endpoint")
	}
	if e.Clients && e.Transport == TransportSOCKS {
		return errors.New("standard clients need a VLESS endpoint")
	}
	return nil
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// privateAddress mirrors Xray's rule for unencrypted VLESS: the server
// must be a private IP or a private-use domain.
func privateAddress(a string) bool {
	if ip, err := netip.ParseAddr(a); err == nil {
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip)
	}
	a = strings.ToLower(strings.TrimSuffix(a, "."))
	if a == "localhost" {
		return true
	}
	for _, suf := range []string{".lan", ".local", ".internal", ".home.arpa", ".localhost"} {
		if strings.HasSuffix(a, suf) {
			return true
		}
	}
	return false
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var shortIDRE = regexp.MustCompile(`^([0-9a-f]{2}){0,8}$`)

func (s *Spec) validateLink(l *Link) error {
	if err := CheckName("name", l.Name); err != nil {
		return err
	}
	if l.Dialer == l.Listener {
		return errors.New("dialer and listener are the same node")
	}
	d, ln := s.Node(l.Dialer), s.Node(l.Listener)
	if d == nil {
		return fmt.Errorf("dialer %q: no such node", l.Dialer)
	}
	if ln == nil {
		return fmt.Errorf("listener %q: no such node", l.Listener)
	}
	if ln.Endpoint(l.Endpoint) == nil {
		return fmt.Errorf("endpoint %q: node %q has no such endpoint", l.Endpoint, l.Listener)
	}
	if l.Cost < 0 {
		return errors.New("cost: negative")
	}
	if l.DialerProxy != "" && d.Proxy(l.DialerProxy) == nil {
		return fmt.Errorf("dialer_proxy %q: node %q has no such proxy", l.DialerProxy, l.Dialer)
	}
	if l.Interface != "" && (len(l.Interface) >= 16 || strings.ContainsAny(l.Interface, " /")) {
		return fmt.Errorf("interface: invalid %q", l.Interface)
	}
	if l.UUID != "" && !uuidRE.MatchString(l.UUID) {
		return fmt.Errorf("uuid: invalid %q", l.UUID)
	}
	if !shortIDRE.MatchString(l.ShortID) {
		return fmt.Errorf("short_id: invalid %q", l.ShortID)
	}
	return nil
}

func (s *Spec) validateRoute(r *Route, prefixes map[netip.Prefix]string) error {
	if err := CheckName("name", r.Name); err != nil {
		return err
	}
	p, err := ParsePrefix(r.Prefix)
	if err != nil {
		return err
	}
	if prev, dup := prefixes[p]; dup {
		return fmt.Errorf("prefix %v already routed by %q", p, prev)
	}
	prefixes[p] = r.Name
	if len(r.Advertisers) == 0 {
		return errors.New("no advertisers")
	}
	seen := map[string]bool{}
	for _, a := range r.Advertisers {
		n := s.Node(a.Node)
		if n == nil {
			return fmt.Errorf("advertiser %q: no such node", a.Node)
		}
		if err := unique(seen, "advertiser", a.Node); err != nil {
			return err
		}
		need := CapAdvertise
		if p.Bits() == 0 {
			need = CapExit
		}
		if !n.HasCap(need) {
			return fmt.Errorf("advertiser %q lacks the %s capability", a.Node, need)
		}
		switch a.Source {
		case "", "snat", "preserve":
		default:
			return fmt.Errorf("advertiser %q: source %q: want snat or preserve", a.Node, a.Source)
		}
	}
	return nil
}

var validProtos = []string{"tcp", "udp", "icmp", "any"}

func (s *Spec) validateAccess(a *AccessPolicy) error {
	if err := CheckName("name", a.Name); err != nil {
		return err
	}
	if a.Action != "allow" && a.Action != "deny" {
		return fmt.Errorf("action %q: want allow or deny", a.Action)
	}
	for _, sel := range a.Sources {
		if err := s.checkIdentitySelector(sel, true); err != nil {
			return fmt.Errorf("sources: %w", err)
		}
	}
	for _, p := range a.SourcePrefixes {
		if _, err := ParsePrefix(p); err != nil {
			return fmt.Errorf("source_prefixes: %w", err)
		}
	}
	for _, d := range a.Destinations {
		if err := s.checkDestSelector(d); err != nil {
			return fmt.Errorf("destinations: %w", err)
		}
	}
	for _, p := range a.Proto {
		if !slices.Contains(validProtos, p) {
			return fmt.Errorf("proto %q: want tcp, udp, icmp or any", p)
		}
	}
	for _, p := range a.Ports {
		if _, err := policy.ParsePortRange(p); err != nil {
			return fmt.Errorf("ports: %w", err)
		}
	}
	if len(a.Ports) > 0 && len(a.Proto) == 1 && a.Proto[0] == "icmp" {
		return errors.New("ports given for an icmp-only rule")
	}
	return nil
}

func (s *Spec) validateEgress(e *EgressPolicy) error {
	if err := CheckName("name", e.Name); err != nil {
		return err
	}
	if len(e.Sources) == 0 {
		return errors.New("sources: at least one selector is required")
	}
	for _, sel := range e.Sources {
		if err := s.checkIdentitySelector(sel, true); err != nil {
			return fmt.Errorf("sources: %w", err)
		}
	}
	n := s.Node(e.Exit)
	if n == nil {
		return fmt.Errorf("exit %q: no such node", e.Exit)
	}
	if !n.HasCap(CapExit) {
		return fmt.Errorf("exit %q lacks the exit capability", e.Exit)
	}
	for i, r := range e.XrayRules {
		if _, ok := r["outboundTag"]; !ok {
			if _, ok := r["balancerTag"]; !ok {
				return fmt.Errorf("xray_rules[%d]: outboundTag or balancerTag required", i)
			}
		}
	}
	return nil
}

func (s *Spec) validateClient(c *Client) error {
	if err := CheckName("name", c.Name); err != nil {
		return err
	}
	n := s.Node(c.Node)
	if n == nil {
		return fmt.Errorf("node %q: no such node", c.Node)
	}
	e := n.Endpoint(c.Endpoint)
	if e == nil {
		return fmt.Errorf("endpoint %q: node %q has no such endpoint", c.Endpoint, c.Node)
	}
	if !e.Clients {
		return fmt.Errorf("endpoint %q does not accept clients", c.Endpoint)
	}
	for _, t := range c.Tags {
		if !tagRE.MatchString(t) {
			return fmt.Errorf("tags: invalid tag %q", t)
		}
	}
	if c.UUID != "" && !uuidRE.MatchString(c.UUID) {
		return fmt.Errorf("uuid: invalid %q", c.UUID)
	}
	if !shortIDRE.MatchString(c.ShortID) {
		return fmt.Errorf("short_id: invalid %q", c.ShortID)
	}
	return nil
}

// checkIdentitySelector validates "node:x", "client:x", "tag:t",
// "group:g" (when allowed) or a glob pattern.
func (s *Spec) checkIdentitySelector(sel string, allowGroup bool) error {
	kind, val, ok := strings.Cut(sel, ":")
	if !ok {
		if sel == "" || strings.ContainsAny(sel, " \t@/\\") {
			return fmt.Errorf("invalid identity pattern %q", sel)
		}
		if _, err := path.Match(sel, ""); err != nil {
			return fmt.Errorf("invalid identity pattern %q", sel)
		}
		return nil
	}
	switch kind {
	case "node":
		if s.Node(val) == nil {
			return fmt.Errorf("%q: no such node", sel)
		}
	case "client":
		if s.Client(val) == nil {
			return fmt.Errorf("%q: no such client", sel)
		}
	case "tag":
		if !tagRE.MatchString(val) {
			return fmt.Errorf("%q: invalid tag", sel)
		}
	case "group":
		if !allowGroup {
			return fmt.Errorf("%q: groups cannot be nested", sel)
		}
		if s.Group(val) == nil {
			return fmt.Errorf("%q: no such group", sel)
		}
	default:
		return fmt.Errorf("%q: want node:, client:, tag:, group: or a pattern", sel)
	}
	return nil
}

func (s *Spec) checkDestSelector(sel string) error {
	kind, val, ok := strings.Cut(sel, ":")
	switch {
	case ok && kind == "node":
		if s.Node(val) == nil {
			return fmt.Errorf("%q: no such node", sel)
		}
		return nil
	case ok && kind == "tag":
		if !tagRE.MatchString(val) {
			return fmt.Errorf("%q: invalid tag", sel)
		}
		return nil
	}
	if strings.Contains(sel, "/") {
		_, err := ParsePrefix(sel)
		return err
	}
	if _, err := netip.ParseAddr(sel); err != nil {
		return fmt.Errorf("%q: want a prefix, an address, node: or tag:", sel)
	}
	return nil
}
