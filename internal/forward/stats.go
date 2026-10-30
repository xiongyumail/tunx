package forward

import (
	"sync"
	"sync/atomic"
)

// Counter counts flows and bytes. Tx is toward the flow's destination from
// the point of view of the key (identity: bytes it sent; peer: bytes this
// node sent to the peer); Rx the other way.
type Counter struct {
	flows atomic.Uint64
	tx    atomic.Uint64
	rx    atomic.Uint64
}

// CounterValue is a snapshot of a Counter.
type CounterValue struct {
	Flows   uint64 `json:"flows"`
	TxBytes uint64 `json:"tx_bytes"`
	RxBytes uint64 `json:"rx_bytes"`
}

func (c *Counter) value() CounterValue {
	return CounterValue{Flows: c.flows.Load(), TxBytes: c.tx.Load(), RxBytes: c.rx.Load()}
}

// Drop reasons.
const (
	DropNoRoute    = "no_route"
	DropDenied     = "denied"
	DropHopLimit   = "hop_limit"
	DropSpoofed    = "spoofed"
	DropOpenFailed = "open_failed"
	DropDeliver    = "deliver_failed"
	// DropRefused counts flows the next hop refused (the reason is
	// passed back toward the source).
	DropRefused = "refused"
)

// Stats holds per-identity and per-peer counters and drop counts.
type Stats struct {
	mu       sync.Mutex
	identity map[string]*Counter
	peer     map[string]*Counter
	drops    map[string]*atomic.Uint64
}

// NewStats returns empty stats.
func NewStats() *Stats {
	return &Stats{
		identity: make(map[string]*Counter),
		peer:     make(map[string]*Counter),
		drops:    make(map[string]*atomic.Uint64),
	}
}

func get(m map[string]*Counter, k string) *Counter {
	c := m[k]
	if c == nil {
		c = &Counter{}
		m[k] = c
	}
	return c
}

// Identity returns the counter of an identity.
func (s *Stats) Identity(id string) *Counter {
	s.mu.Lock()
	defer s.mu.Unlock()
	return get(s.identity, id)
}

// Peer returns the counter of a peer.
func (s *Stats) Peer(name string) *Counter {
	s.mu.Lock()
	defer s.mu.Unlock()
	return get(s.peer, name)
}

// Drop counts a refused flow.
func (s *Stats) Drop(reason string) {
	s.mu.Lock()
	c := s.drops[reason]
	if c == nil {
		c = &atomic.Uint64{}
		s.drops[reason] = c
	}
	s.mu.Unlock()
	c.Add(1)
}

// Drops returns the count for a reason.
func (s *Stats) Drops(reason string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.drops[reason]; c != nil {
		return c.Load()
	}
	return 0
}

// StatsSnapshot is the JSON form of Stats.
type StatsSnapshot struct {
	Identities map[string]CounterValue `json:"identities"`
	Peers      map[string]CounterValue `json:"peers"`
	Drops      map[string]uint64       `json:"drops"`
}

// Snapshot copies the counters.
func (s *Stats) Snapshot() StatsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := StatsSnapshot{
		Identities: make(map[string]CounterValue),
		Peers:      make(map[string]CounterValue),
		Drops:      make(map[string]uint64),
	}
	for k, c := range s.identity {
		out.Identities[k] = c.value()
	}
	for k, c := range s.peer {
		out.Peers[k] = c.value()
	}
	for k, c := range s.drops {
		out.Drops[k] = c.Load()
	}
	return out
}
