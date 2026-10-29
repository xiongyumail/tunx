// Package config reads and validates the node config of tunxd. The file is
// JSON; // line comments and /* block comments */ are allowed.
package config

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/xiongyumail/tunx/internal/core"
	"github.com/xiongyumail/tunx/internal/egress"
	"github.com/xiongyumail/tunx/internal/link"
	"github.com/xiongyumail/tunx/internal/policy"
	"github.com/xiongyumail/tunx/internal/route"
)

// DefaultHopLimit bounds the links a flow may cross.
const DefaultHopLimit = 8

// Config is the config of one node.
type Config struct {
	// Node is this node's name; Network the overlay network ID.
	Node    string `json:"node"`
	Network string `json:"network"`
	// PrivateKey is the base64 ed25519 key (32-byte seed or 64-byte key).
	// PrivateKeyFile names a file holding it instead, relative to the
	// config file.
	PrivateKey     string `json:"private_key,omitempty"`
	PrivateKeyFile string `json:"private_key_file,omitempty"`
	// Addresses are this node's overlay addresses. Each gets a host route
	// delivered locally.
	Addresses []netip.Addr `json:"addresses,omitempty"`
	TUN       *TUN         `json:"tun,omitempty"`
	Listen    []Listener   `json:"listen,omitempty"`
	Peers     []Peer       `json:"peers,omitempty"`
	Routes    []Route      `json:"routes,omitempty"`
	// Groups name lists of identity patterns, referenced as "@name".
	Groups   map[string][]string `json:"groups,omitempty"`
	Policy   []Rule              `json:"policy,omitempty"`
	HopLimit int                 `json:"hop_limit,omitempty"`
	Link     LinkTimers          `json:"link,omitzero"`
	// Status is a loopback address for the HTTP status endpoint; empty
	// disables it.
	Status   string `json:"status,omitempty"`
	LogLevel string `json:"log_level,omitempty"`

	key ed25519.PrivateKey
}

// TUN configures the capture device. tunxd creates it but does not assign
// addresses or routes; Addresses and Capture document what the operator
// sets up (see `tunxd check`).
type TUN struct {
	Name      string         `json:"name"`
	MTU       int            `json:"mtu,omitempty"`
	Addresses []netip.Prefix `json:"addresses,omitempty"`
	Capture   []netip.Prefix `json:"capture,omitempty"`
}

// Listener accepts link connections, normally forwarded by the local Xray
// inbound.
type Listener struct {
	Address string `json:"address"`
}

// Peer is a node this node holds a link with.
type Peer struct {
	Name      string    `json:"name"`
	PublicKey PublicKey `json:"public_key"`
	// Dial is the address to connect to (normally a local Xray outbound
	// inbound wired to the peer). Empty means the peer dials us.
	Dial string `json:"dial,omitempty"`
	// Interface and Mark apply to the dialing socket.
	Interface string `json:"interface,omitempty"`
	Mark      uint32 `json:"mark,omitempty"`
	// Priority orders peers for routes with via "*"; lower first.
	Priority int `json:"priority,omitempty"`
	// RelayFor lists the identities (patterns or "@group") this peer may
	// carry besides its own name.
	RelayFor []string `json:"relay_for,omitempty"`
}

// Route maps a prefix to the nodes that deliver it.
type Route struct {
	Prefix      netip.Prefix `json:"prefix"`
	Advertisers []Advertiser `json:"advertisers"`
}

// Advertiser is one node delivering a route.
type Advertiser struct {
	Node     string `json:"node"`
	Priority int    `json:"priority,omitempty"`
	// Via lists peers that relay to Node when there is no direct session;
	// "*" means any peer.
	Via []string `json:"via,omitempty"`
	// Local delivery only (Node is this node).
	Source    string `json:"source,omitempty"` // snat (default) or preserve
	Interface string `json:"interface,omitempty"`
	Mark      uint32 `json:"mark,omitempty"`
}

// Rule is an access rule; the first match wins, no match denies.
type Rule struct {
	Action   string             `json:"action"`
	Identity []string           `json:"identity,omitempty"`
	Src      []netip.Prefix     `json:"src,omitempty"`
	Dst      []netip.Prefix     `json:"dst,omitempty"`
	Proto    []string           `json:"proto,omitempty"`
	Ports    []policy.PortRange `json:"ports,omitempty"`
}

// LinkTimers override the link defaults.
type LinkTimers struct {
	HandshakeTimeout  Duration `json:"handshake_timeout,omitzero"`
	KeepaliveInterval Duration `json:"keepalive_interval,omitzero"`
	KeepaliveTimeout  Duration `json:"keepalive_timeout,omitzero"`
}

// Duration is a time.Duration written as "5s" in JSON.
type Duration time.Duration

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("invalid duration %q", b)
	}
	if v < 0 {
		return fmt.Errorf("negative duration %q", b)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// PublicKey is a base64 ed25519 public key.
type PublicKey ed25519.PublicKey

func (k *PublicKey) UnmarshalText(b []byte) error {
	v, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil || len(v) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key %q: want base64 of %d bytes", b, ed25519.PublicKeySize)
	}
	*k = v
	return nil
}

func (k PublicKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(k)), nil
}

// Load reads, parses and validates a config file.
func Load(file string) (*Config, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	c, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if err := c.Validate(filepath.Dir(file)); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return c, nil
}

// Parse decodes a config without validating it. Unknown fields are errors.
func Parse(b []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(StripComments(b)))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, describeJSONError(err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after the config object")
	}
	return &c, nil
}

func describeJSONError(err error) error {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) && te.Field != "" {
		return fmt.Errorf("field %s: expected %s, got JSON %s", te.Field, te.Type, te.Value)
	}
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("JSON syntax error at byte %d: %v", se.Offset, err)
	}
	return err
}

// StripComments blanks // and /* */ comments outside strings, keeping byte
// offsets so JSON errors point at the right place.
func StripComments(b []byte) []byte {
	out := slices.Clone(b)
	inStr, esc := false, false
	for i := 0; i < len(out); i++ {
		c := out[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			continue
		}
		if c != '/' || i+1 >= len(out) {
			continue
		}
		switch out[i+1] {
		case '/':
			for ; i < len(out) && out[i] != '\n'; i++ {
				out[i] = ' '
			}
		case '*':
			out[i], out[i+1] = ' ', ' '
			for i += 2; i < len(out); i++ {
				if out[i] == '*' && i+1 < len(out) && out[i+1] == '/' {
					out[i], out[i+1] = ' ', ' '
					i++
					break
				}
				if out[i] != '\n' {
					out[i] = ' '
				}
			}
		}
	}
	return out
}

// Validate checks the config, fills defaults and loads the private key. dir
// resolves a relative PrivateKeyFile.
func (c *Config) Validate(dir string) error {
	if err := checkName("node", c.Node); err != nil {
		return err
	}
	if len(c.Network) > link.MaxNameLen {
		return fmt.Errorf("network: longer than %d bytes", link.MaxNameLen)
	}
	if err := c.loadKey(dir); err != nil {
		return err
	}
	if c.HopLimit == 0 {
		c.HopLimit = DefaultHopLimit
	}
	if c.HopLimit < 1 || c.HopLimit > 255 {
		return fmt.Errorf("hop_limit: %d out of range 1..255", c.HopLimit)
	}
	for _, a := range c.Addresses {
		if !a.IsValid() || a.Zone() != "" {
			return fmt.Errorf("addresses: invalid address %v", a)
		}
	}
	if t := c.TUN; t != nil {
		if t.Name == "" || len(t.Name) >= 16 {
			return errors.New("tun.name: must be 1..15 characters")
		}
		if t.MTU != 0 && (t.MTU < 576 || t.MTU > 65535) {
			return fmt.Errorf("tun.mtu: %d out of range 576..65535", t.MTU)
		}
		for _, p := range t.Capture {
			if p != p.Masked() {
				return fmt.Errorf("tun.capture: prefix %v has host bits set (use %v)", p, p.Masked())
			}
		}
	}
	for i, l := range c.Listen {
		if _, _, err := net.SplitHostPort(l.Address); err != nil {
			return fmt.Errorf("listen[%d]: address %q: %v", i, l.Address, err)
		}
	}
	if c.Status != "" {
		if err := checkLoopback(c.Status); err != nil {
			return fmt.Errorf("status: %w", err)
		}
	}
	if _, err := c.Level(); err != nil {
		return fmt.Errorf("log_level: %w", err)
	}
	lt := c.Link
	if lt.KeepaliveTimeout != 0 && lt.KeepaliveInterval != 0 && lt.KeepaliveTimeout <= lt.KeepaliveInterval {
		return errors.New("link: keepalive_timeout must be longer than keepalive_interval")
	}

	peers := make(map[string]*Peer)
	for i := range c.Peers {
		p := &c.Peers[i]
		if err := checkName(fmt.Sprintf("peers[%d].name", i), p.Name); err != nil {
			return err
		}
		if p.Name == c.Node {
			return fmt.Errorf("peers[%d]: %q is this node", i, p.Name)
		}
		if peers[p.Name] != nil {
			return fmt.Errorf("peers[%d]: duplicate peer %q", i, p.Name)
		}
		if len(p.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("peer %q: public_key missing", p.Name)
		}
		if p.Dial != "" {
			if _, _, err := net.SplitHostPort(p.Dial); err != nil {
				return fmt.Errorf("peer %q: dial %q: %v", p.Name, p.Dial, err)
			}
		} else if p.Interface != "" || p.Mark != 0 {
			return fmt.Errorf("peer %q: interface and mark need a dial address", p.Name)
		}
		peers[p.Name] = p
	}
	if len(c.Peers) > 0 && len(c.Listen) == 0 && !slices.ContainsFunc(c.Peers, func(p Peer) bool { return p.Dial != "" }) {
		return errors.New("no listener and no peer to dial: this node can never form a link")
	}

	for i, r := range c.Routes {
		if !r.Prefix.IsValid() {
			return fmt.Errorf("routes[%d]: prefix missing", i)
		}
		if len(r.Advertisers) == 0 {
			return fmt.Errorf("route %v: no advertisers", r.Prefix)
		}
		for _, a := range r.Advertisers {
			if err := c.checkAdvertiser(a, peers); err != nil {
				return fmt.Errorf("route %v: %w", r.Prefix, err)
			}
		}
	}
	if _, err := c.Table(); err != nil {
		return err
	}
	for i, r := range c.Policy {
		if _, err := r.compile(); err != nil {
			return fmt.Errorf("policy[%d]: %w", i, err)
		}
	}
	if _, err := c.BuildPolicy(); err != nil {
		return err
	}
	return nil
}

func (c *Config) checkAdvertiser(a Advertiser, peers map[string]*Peer) error {
	if a.Node == "" {
		return errors.New("advertiser without node")
	}
	if a.Node == c.Node {
		if len(a.Via) > 0 {
			return errors.New("via makes no sense for this node's own advertisement")
		}
		if _, err := sourceMode(a.Source); err != nil {
			return err
		}
		return nil
	}
	if a.Source != "" || a.Interface != "" || a.Mark != 0 {
		return fmt.Errorf("advertiser %q: source, interface and mark apply only to this node", a.Node)
	}
	if peers[a.Node] == nil && len(a.Via) == 0 {
		return fmt.Errorf("advertiser %q is not a peer; give a via list of peers that reach it", a.Node)
	}
	for _, v := range a.Via {
		if v != route.AnyPeer && peers[v] == nil {
			return fmt.Errorf("advertiser %q: via %q is not a peer", a.Node, v)
		}
	}
	return nil
}

func sourceMode(s string) (egress.SourceMode, error) {
	switch s {
	case "", "snat":
		return egress.SourceSNAT, nil
	case "preserve":
		return egress.SourcePreserve, nil
	}
	return 0, fmt.Errorf("source %q: want snat or preserve", s)
}

func checkName(field, s string) error {
	if s == "" || len(s) > link.MaxNameLen {
		return fmt.Errorf("%s: must be 1..%d bytes", field, link.MaxNameLen)
	}
	if strings.ContainsAny(s, " \t\r\n*?[]@/\\") {
		return fmt.Errorf("%s: %q contains whitespace or one of *?[]@/\\", field, s)
	}
	return nil
}

func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("address %q: %v", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("address %q must be on loopback", addr)
	}
	return nil
}

func (c *Config) loadKey(dir string) error {
	s := c.PrivateKey
	switch {
	case s != "" && c.PrivateKeyFile != "":
		return errors.New("set private_key or private_key_file, not both")
	case c.PrivateKeyFile != "":
		f := c.PrivateKeyFile
		if !filepath.IsAbs(f) && dir != "" {
			f = filepath.Join(dir, f)
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("private_key_file: %w", err)
		}
		s = strings.TrimSpace(string(b))
	case s == "":
		return errors.New("private_key or private_key_file is required")
	}
	k, err := ParsePrivateKey(s)
	if err != nil {
		return err
	}
	c.key = k
	return nil
}

// ParsePrivateKey decodes a base64 ed25519 seed or private key.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("private key: not base64")
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		k := ed25519.PrivateKey(b)
		if !bytes.Equal(ed25519.NewKeyFromSeed(k.Seed()), k) {
			return nil, errors.New("private key: public half does not match")
		}
		return k, nil
	}
	return nil, fmt.Errorf("private key: %d bytes, want %d or %d", len(b), ed25519.SeedSize, ed25519.PrivateKeySize)
}

// GenerateKey returns a new key pair as base64 (seed, public key).
func GenerateKey() (priv, pub string, err error) {
	pk, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(sk.Seed()), base64.StdEncoding.EncodeToString(pk), nil
}

// Level returns the configured log level, info by default.
func (c *Config) Level() (slog.Level, error) {
	var l slog.Level
	if c.LogLevel == "" {
		return slog.LevelInfo, nil
	}
	if err := l.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return 0, fmt.Errorf("%q: want debug, info, warn or error", c.LogLevel)
	}
	return l, nil
}

// Key returns the private key loaded by Validate.
func (c *Config) Key() ed25519.PrivateKey { return c.key }

// SetKey sets the private key directly (for configs built in code).
func (c *Config) SetKey(k ed25519.PrivateKey) {
	c.key = k
	c.PrivateKey = base64.StdEncoding.EncodeToString(k.Seed())
}

// PublicKey returns this node's public key.
func (c *Config) PublicKey() ed25519.PublicKey {
	if c.key == nil {
		return nil
	}
	return c.key.Public().(ed25519.PublicKey)
}

// Peer returns the peer config by name.
func (c *Config) Peer(name string) *Peer {
	for i := range c.Peers {
		if c.Peers[i].Name == name {
			return &c.Peers[i]
		}
	}
	return nil
}

// LinkConfig returns the link config for this node accepting the given
// peers; with no names it accepts every configured peer.
func (c *Config) LinkConfig(names ...string) link.Config {
	peers := make(map[string]ed25519.PublicKey)
	for _, p := range c.Peers {
		if len(names) == 0 || slices.Contains(names, p.Name) {
			peers[p.Name] = ed25519.PublicKey(p.PublicKey)
		}
	}
	return link.Config{
		Network:           c.Network,
		Name:              c.Node,
		PrivateKey:        c.key,
		Peers:             peers,
		HandshakeTimeout:  time.Duration(c.Link.HandshakeTimeout),
		KeepaliveInterval: time.Duration(c.Link.KeepaliveInterval),
		KeepaliveTimeout:  time.Duration(c.Link.KeepaliveTimeout),
	}
}

// Table builds the route table: the configured routes plus a local host
// route for each overlay address.
func (c *Config) Table() (*route.Table, error) {
	var entries []route.Entry
	have := make(map[netip.Prefix]bool)
	for _, r := range c.Routes {
		e := route.Entry{Prefix: r.Prefix}
		for _, a := range r.Advertisers {
			mode, err := sourceMode(a.Source)
			if err != nil {
				return nil, fmt.Errorf("route %v: %w", r.Prefix, err)
			}
			e.Advertisers = append(e.Advertisers, route.Advertiser{
				Node:     a.Node,
				Priority: a.Priority,
				Via:      a.Via,
				Egress:   egress.Options{Source: mode, Interface: a.Interface, Mark: a.Mark},
			})
		}
		entries = append(entries, e)
		have[r.Prefix] = true
	}
	for _, a := range c.Addresses {
		p := netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		if have[p] {
			continue
		}
		entries = append(entries, route.Entry{Prefix: p, Advertisers: []route.Advertiser{{Node: c.Node}}})
		have[p] = true
	}
	order := slices.Clone(c.Peers)
	slices.SortStableFunc(order, func(a, b Peer) int { return a.Priority - b.Priority })
	names := make([]string, len(order))
	for i, p := range order {
		names[i] = p.Name
	}
	return route.NewTable(c.Node, entries, names)
}

// BuildPolicy compiles the access rules and relay permissions.
func (c *Config) BuildPolicy() (*policy.Policy, error) {
	var rules []policy.Rule
	for i, r := range c.Policy {
		pr, err := r.compile()
		if err != nil {
			return nil, fmt.Errorf("policy[%d]: %w", i, err)
		}
		rules = append(rules, pr)
	}
	relay := make(map[string][]string)
	for _, p := range c.Peers {
		if len(p.RelayFor) > 0 {
			relay[p.Name] = p.RelayFor
		}
	}
	return policy.New(rules, c.Groups, relay)
}

func (r Rule) compile() (policy.Rule, error) {
	pr := policy.Rule{Identities: r.Identity, Src: r.Src, Dst: r.Dst, Ports: r.Ports}
	switch r.Action {
	case "allow":
		pr.Allow = true
	case "deny":
	default:
		return pr, fmt.Errorf("action %q: want allow or deny", r.Action)
	}
	for _, p := range r.Proto {
		switch p {
		case "tcp":
			pr.Protos = append(pr.Protos, core.ProtoTCP)
		case "udp":
			pr.Protos = append(pr.Protos, core.ProtoUDP)
		case "icmp", "icmpv6":
			pr.Protos = append(pr.Protos, core.ProtoICMP)
		case "any":
		default:
			return pr, fmt.Errorf("proto %q: want tcp, udp, icmp or any", p)
		}
	}
	if slices.Contains(r.Proto, "any") {
		pr.Protos = nil
	}
	if len(r.Ports) > 0 && slices.Contains(pr.Protos, core.ProtoICMP) && len(pr.Protos) == 1 {
		return pr, errors.New("ports given for an icmp-only rule")
	}
	for _, p := range append(slices.Clone(r.Src), r.Dst...) {
		if p != p.Masked() {
			return pr, fmt.Errorf("prefix %v has host bits set (use %v)", p, p.Masked())
		}
	}
	return pr, nil
}
