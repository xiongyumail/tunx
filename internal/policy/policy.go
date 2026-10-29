// Package policy decides which flows a node lets through. Access rules match
// the flow's identity, source, destination, protocol and port; the first
// matching rule wins and a flow no rule matches is denied. Relay rules say
// which identities a peer may carry over its link.
package policy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"path"
	"strconv"
	"strings"

	"github.com/xiongyumail/tunx/internal/core"
)

// PortRange is an inclusive range of destination ports. In JSON it is a
// number (80) or a string ("80", "8000-8999").
type PortRange struct{ Lo, Hi uint16 }

// ParsePortRange parses "80" or "8000-8999".
func ParsePortRange(s string) (PortRange, error) {
	lo, hi, ok := strings.Cut(strings.TrimSpace(s), "-")
	if !ok {
		hi = lo
	}
	a, err1 := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	b, err2 := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if err1 != nil || err2 != nil || a > b {
		return PortRange{}, fmt.Errorf("invalid port range %q", s)
	}
	return PortRange{uint16(a), uint16(b)}, nil
}

func (r PortRange) String() string {
	if r.Lo == r.Hi {
		return strconv.Itoa(int(r.Lo))
	}
	return strconv.Itoa(int(r.Lo)) + "-" + strconv.Itoa(int(r.Hi))
}

func (r *PortRange) UnmarshalJSON(b []byte) error {
	var n uint16
	if err := json.Unmarshal(b, &n); err == nil {
		*r = PortRange{n, n}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("invalid port range %s", b)
	}
	pr, err := ParsePortRange(s)
	if err != nil {
		return err
	}
	*r = pr
	return nil
}

func (r PortRange) MarshalJSON() ([]byte, error) { return json.Marshal(r.String()) }

// Rule is one access rule. Empty match fields match anything.
type Rule struct {
	Allow bool
	// Identities are glob patterns (path.Match syntax) or "@group".
	Identities []string
	Src        []netip.Prefix
	Dst        []netip.Prefix
	// Protos lists protocols; ProtoICMP also matches ICMPv6.
	Protos []core.Proto
	// Ports match the destination port. A rule with ports never matches
	// ICMP.
	Ports []PortRange
}

type rule struct {
	Rule
	globs []string // identities with groups expanded
}

// Policy is an immutable compiled rule set.
type Policy struct {
	rules []rule
	relay map[string][]string // peer -> identity globs it may carry
}

// New compiles rules. groups maps a group name to identity globs; relayFor
// maps a peer to the identity globs (or "@group") it may carry besides its
// own name.
func New(rules []Rule, groups map[string][]string, relayFor map[string][]string) (*Policy, error) {
	p := &Policy{relay: make(map[string][]string)}
	for i, r := range rules {
		globs, err := expand(r.Identities, groups)
		if err != nil {
			return nil, fmt.Errorf("policy rule %d: %w", i+1, err)
		}
		for _, pr := range r.Ports {
			if pr.Lo > pr.Hi {
				return nil, fmt.Errorf("policy rule %d: invalid port range %v", i+1, pr)
			}
		}
		p.rules = append(p.rules, rule{Rule: r, globs: globs})
	}
	for peer, ids := range relayFor {
		globs, err := expand(ids, groups)
		if err != nil {
			return nil, fmt.Errorf("relay_for of peer %q: %w", peer, err)
		}
		p.relay[peer] = globs
	}
	return p, nil
}

func expand(ids []string, groups map[string][]string) ([]string, error) {
	var out []string
	for _, id := range ids {
		if g, ok := strings.CutPrefix(id, "@"); ok {
			members, ok := groups[g]
			if !ok {
				return nil, fmt.Errorf("unknown group %q", g)
			}
			for _, m := range members {
				if strings.HasPrefix(m, "@") {
					return nil, fmt.Errorf("group %q: nested group %q not supported", g, m)
				}
				if err := checkGlob(m); err != nil {
					return nil, fmt.Errorf("group %q: %w", g, err)
				}
			}
			out = append(out, members...)
			continue
		}
		if err := checkGlob(id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func checkGlob(g string) error {
	if g == "" {
		return fmt.Errorf("empty identity pattern")
	}
	if _, err := path.Match(g, ""); err != nil {
		return fmt.Errorf("bad identity pattern %q", g)
	}
	return nil
}

func matchAny(globs []string, id string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, id); ok {
			return true
		}
	}
	return false
}

// Allow reports whether the first rule matching meta allows it. No match
// denies.
func (p *Policy) Allow(meta core.FlowMeta) bool {
	if p == nil {
		return false
	}
	for i := range p.rules {
		if p.rules[i].match(meta) {
			return p.rules[i].Allow
		}
	}
	return false
}

func (r *rule) match(meta core.FlowMeta) bool {
	if len(r.Identities) > 0 && !matchAny(r.globs, meta.Identity) {
		return false
	}
	if len(r.Src) > 0 && !inAny(r.Src, meta.Src.Addr()) {
		return false
	}
	if len(r.Dst) > 0 && !inAny(r.Dst, meta.Dst.Addr()) {
		return false
	}
	if len(r.Protos) > 0 {
		ok := false
		for _, pr := range r.Protos {
			if pr == meta.Proto || (pr == core.ProtoICMP && meta.Proto == core.ProtoICMPv6) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.Ports) > 0 {
		if meta.Proto == core.ProtoICMP || meta.Proto == core.ProtoICMPv6 {
			return false
		}
		port, ok := meta.Dst.Port(), false
		for _, pr := range r.Ports {
			if port >= pr.Lo && port <= pr.Hi {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func inAny(prefixes []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// MayCarry reports whether a flow claiming identity may arrive over the link
// to peer: the peer speaks for itself, or is configured to relay for that
// identity.
func (p *Policy) MayCarry(peer, identity string) bool {
	if identity == "" {
		return false
	}
	if identity == peer {
		return true
	}
	if p == nil {
		return false
	}
	return matchAny(p.relay[peer], identity)
}
