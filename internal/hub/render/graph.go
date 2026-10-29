package render

import (
	"cmp"
	"math"
	"slices"

	"github.com/xiongyumail/tunx/internal/hub/model"
)

const unreachable = math.MaxInt

// graph is the link graph of the enrolled nodes. Flows may pass through a
// node only when it has the relay capability.
type graph struct {
	nodes map[string]*model.Node
	// adj[a][b] is the lowest cost of an active link between a and b.
	adj map[string]map[string]int
	// best[pair] is the link tunxd uses between a pair of nodes.
	best map[[2]string]*model.Link
	// distCache[[from, banned]] memoizes shortest distances.
	distCache map[[2]string]map[string]int
}

func pairKey(a, b string) [2]string {
	if a > b {
		a, b = b, a
	}
	return [2]string{a, b}
}

func linkCost(l *model.Link) int {
	if l.Cost == 0 {
		return model.DefaultLinkCost
	}
	return l.Cost
}

// linkBetter orders links of one pair: priority, then cost, then name.
func linkBetter(a, b *model.Link) bool {
	return cmp.Or(cmp.Compare(a.Priority, b.Priority), cmp.Compare(linkCost(a), linkCost(b)), cmp.Compare(a.Name, b.Name)) < 0
}

func newGraph(s *model.Spec) *graph {
	g := &graph{
		nodes:     map[string]*model.Node{},
		adj:       map[string]map[string]int{},
		best:      map[[2]string]*model.Link{},
		distCache: map[[2]string]map[string]int{},
	}
	for i := range s.Nodes {
		if n := &s.Nodes[i]; n.PublicKey != "" {
			g.nodes[n.Name] = n
			g.adj[n.Name] = map[string]int{}
		}
	}
	for i := range s.Links {
		l := &s.Links[i]
		if !g.active(l) {
			continue
		}
		c := linkCost(l)
		if old, ok := g.adj[l.Dialer][l.Listener]; !ok || c < old {
			g.adj[l.Dialer][l.Listener] = c
			g.adj[l.Listener][l.Dialer] = c
		}
		k := pairKey(l.Dialer, l.Listener)
		if b := g.best[k]; b == nil || linkBetter(l, b) {
			g.best[k] = l
		}
	}
	return g
}

// active reports whether a link is rendered: enabled and both ends enrolled.
func (g *graph) active(l *model.Link) bool {
	return !l.Disabled && g.nodes[l.Dialer] != nil && g.nodes[l.Listener] != nil
}

func (g *graph) relay(name string) bool {
	n := g.nodes[name]
	return n != nil && n.HasCap(model.CapRelay)
}

func (g *graph) neighbors(name string) []string {
	out := make([]string, 0, len(g.adj[name]))
	for p := range g.adj[name] {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// dist returns the shortest distances from one node to every node, never
// passing through banned and leaving only relay nodes (besides from).
func (g *graph) dist(from, banned string) map[string]int {
	key := [2]string{from, banned}
	if d, ok := g.distCache[key]; ok {
		return d
	}
	d := map[string]int{from: 0}
	done := map[string]bool{}
	for {
		u, best := "", unreachable
		for n, c := range d {
			if !done[n] && (c < best || c == best && n < u) {
				u, best = n, c
			}
		}
		if u == "" {
			break
		}
		done[u] = true
		if u != from && !g.relay(u) {
			continue
		}
		for v, c := range g.adj[u] {
			if v == banned {
				continue
			}
			if old, ok := d[v]; !ok || best+c < old {
				d[v] = best + c
			}
		}
	}
	g.distCache[key] = d
	return d
}

// hop is a way for node self to reach a remote advertiser.
type hop struct {
	cost   int
	direct bool
	via    []string // relaying neighbors, best first
}

// reach computes how self reaches target: directly when they share a link,
// and through each relaying neighbor whose shortest path to target avoids
// self, ordered by total cost.
func (g *graph) reach(self, target string) (hop, bool) {
	type cand struct {
		peer string
		cost int
	}
	var cands []cand
	h := hop{cost: unreachable}
	for _, p := range g.neighbors(self) {
		c := g.adj[self][p]
		if p == target {
			h.direct = true
			h.cost = min(h.cost, c)
			continue
		}
		if !g.relay(p) {
			continue
		}
		if d, ok := g.dist(p, self)[target]; ok {
			cands = append(cands, cand{p, c + d})
		}
	}
	slices.SortStableFunc(cands, func(a, b cand) int { return cmp.Compare(a.cost, b.cost) })
	for _, c := range cands {
		h.via = append(h.via, c.peer)
		h.cost = min(h.cost, c.cost)
	}
	return h, h.direct || len(h.via) > 0
}

// carried returns the nodes whose flows peer may carry to self: peer itself
// and, when peer relays, every node it reaches without passing through self.
func (g *graph) carried(self, peer string) []string {
	if !g.relay(peer) {
		return []string{peer}
	}
	var out []string
	for n := range g.dist(peer, self) {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}
