package forward

import (
	"sync"
	"time"

	"github.com/xiongyumail/tunx/internal/link"
)

// Sessions tracks the link sessions that are up, by peer. A peer may have
// more than one (it dials us while we dial it); the newest one is used.
type Sessions struct {
	mu     sync.Mutex
	byPeer map[string][]*sessionInfo
}

type sessionInfo struct {
	s     *link.Session
	dial  bool
	since time.Time
}

// NewSessions returns an empty registry.
func NewSessions() *Sessions {
	return &Sessions{byPeer: make(map[string][]*sessionInfo)}
}

// Add registers s until it ends. dialed says whether this node dialed it.
func (r *Sessions) Add(s *link.Session, dialed bool) {
	info := &sessionInfo{s: s, dial: dialed, since: time.Now()}
	r.mu.Lock()
	r.byPeer[s.Peer()] = append(r.byPeer[s.Peer()], info)
	r.mu.Unlock()
	go func() {
		<-s.Done()
		r.mu.Lock()
		list := r.byPeer[s.Peer()]
		for i, x := range list {
			if x == info {
				list = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(list) == 0 {
			delete(r.byPeer, s.Peer())
		} else {
			r.byPeer[s.Peer()] = list
		}
		r.mu.Unlock()
	}()
}

// Get returns the newest live session to peer, or nil.
func (r *Sessions) Get(peer string) *link.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.byPeer[peer]
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].s.Err() == nil {
			return list[i].s
		}
	}
	return nil
}

// Up reports whether a live session to peer exists.
func (r *Sessions) Up(peer string) bool { return r.Get(peer) != nil }

// CloseAll closes every session.
func (r *Sessions) CloseAll() {
	r.mu.Lock()
	var all []*link.Session
	for _, list := range r.byPeer {
		for _, x := range list {
			all = append(all, x.s)
		}
	}
	r.mu.Unlock()
	for _, s := range all {
		s.Close()
	}
}

// SessionStatus describes one session for the status endpoint.
type SessionStatus struct {
	Peer   string  `json:"peer"`
	Dialed bool    `json:"dialed"`
	Since  string  `json:"since"`
	RTTms  float64 `json:"rtt_ms"`
}

// Snapshot lists the live sessions.
func (r *Sessions) Snapshot() []SessionStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []SessionStatus
	for _, list := range r.byPeer {
		for _, x := range list {
			if x.s.Err() != nil {
				continue
			}
			out = append(out, SessionStatus{
				Peer:   x.s.Peer(),
				Dialed: x.dial,
				Since:  x.since.UTC().Format(time.RFC3339),
				RTTms:  float64(x.s.RTT().Microseconds()) / 1000,
			})
		}
	}
	return out
}
