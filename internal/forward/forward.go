// Package forward is the data plane of a tunxd node: the Forwarder decides
// for every flow whether to deliver it here, open it on a link toward the
// next hop, or refuse it; Node wires the forwarder to listeners, dialed
// peers, the TUN capture and the status endpoint.
package forward

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiongyumail/tunx/internal/core"
	"github.com/xiongyumail/tunx/internal/egress"
	"github.com/xiongyumail/tunx/internal/link"
	"github.com/xiongyumail/tunx/internal/policy"
	"github.com/xiongyumail/tunx/internal/route"
)

// DeliverFunc delivers a flow on this node; egress.Deliver by default.
type DeliverFunc func(ctx context.Context, meta core.FlowMeta, f core.Flow, opts egress.Options) error

// openTimeout bounds sending a stream header to the next hop.
const openTimeout = 10 * time.Second

// answerTimeout bounds waiting for the next hop's answer to a TCP flow. It
// covers the delivering node's connect timeout (egress.DefaultDialTimeout)
// plus the round trips of the hops in between.
const answerTimeout = 20 * time.Second

// Forwarder implements core.Handler for a node.
type Forwarder struct {
	self     string
	hopLimit uint8
	router   *route.Router
	policy   atomic.Pointer[policy.Policy]
	sessions *Sessions
	stats    *Stats
	deliver  DeliverFunc
	log      *slog.Logger
}

// NewForwarder returns a forwarder for node self.
func NewForwarder(self string, hopLimit uint8, router *route.Router, pol *policy.Policy, sessions *Sessions, deliver DeliverFunc, log *slog.Logger) *Forwarder {
	if deliver == nil {
		deliver = egress.Deliver
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	f := &Forwarder{
		self:     self,
		hopLimit: hopLimit,
		router:   router,
		sessions: sessions,
		stats:    NewStats(),
		deliver:  deliver,
		log:      log,
	}
	f.policy.Store(pol)
	return f
}

// Stats returns the counters.
func (fw *Forwarder) Stats() *Stats { return fw.stats }

// SetPolicy replaces the access policy.
func (fw *Forwarder) SetPolicy(p *policy.Policy) { fw.policy.Store(p) }

// HandleFlow routes one flow and returns when it is finished.
//
// A flow that waits for an answer (core.Answerer: a TCP connection from the
// TUN, a flow from a link) is accepted only once the next hop accepted it or
// the local delivery connected, and refused with the reason otherwise. TCP
// waits for that answer before data flows. Datagram relays accept once
// their next-hop stream opens, without confirming downstream delivery.
func (fw *Forwarder) HandleFlow(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
	defer f.Close()
	pol := fw.policy.Load()
	switch in.Kind {
	case "tun":
		meta.Identity = fw.self
		meta.Hops = 0
	case "link":
		// The peer vouches for the identity; it must be one the peer may
		// carry, and never our own (that would be a loop or a forgery).
		if meta.Identity == fw.self || !pol.MayCarry(in.Peer, meta.Identity) {
			fw.drop(DropSpoofed, meta, in, f)
			return
		}
	default:
		if meta.Identity == "" {
			fw.drop(DropSpoofed, meta, in, f)
			return
		}
	}
	if int(meta.Hops) > int(fw.hopLimit) {
		fw.drop(DropHopLimit, meta, in, f)
		return
	}

	_, next := fw.router.Table().Resolve(meta.Dst.Addr(), fw.sessions.Up)
	if len(next) > 0 && next[0].Local {
		// Delivering node: the access policy applies here.
		if !pol.Allow(meta) {
			fw.drop(DropDenied, meta, in, f)
			return
		}
		fw.deliverLocal(ctx, meta, f, in, next[0].Egress)
		return
	}
	if in.Kind != "link" && !pol.Allow(meta) {
		// Ingress node: the access policy applies here too.
		fw.drop(DropDenied, meta, in, f)
		return
	}
	if int(meta.Hops)+1 > int(fw.hopLimit) {
		fw.drop(DropHopLimit, meta, in, f)
		return
	}
	out := meta
	out.Hops++
	tried := false
	var lastRefusal core.Reason
	for _, n := range next {
		if n.Local || n.Peer == in.Peer {
			continue // never send a flow back over the link it came from
		}
		s := fw.sessions.Get(n.Peer)
		if s == nil {
			continue
		}
		tried = true
		octx, cancel := context.WithTimeout(ctx, openTimeout)
		of, err := s.OpenFlow(octx, out)
		cancel()
		if err != nil {
			fw.log.Debug("open flow failed", "peer", n.Peer, "err", err)
			continue
		}
		if !meta.Proto.IsDatagram() {
			actx, cancel := context.WithTimeout(ctx, answerTimeout)
			err := link.WaitOpen(actx, of)
			cancel()
			var oe *core.OpenError
			if errors.As(err, &oe) {
				// Reachability and hop limits depend on the path. Policy,
				// destination resets and protocol errors remain terminal.
				of.Close()
				switch oe.Reason {
				case core.ReasonNoRoute, core.ReasonUnreachable, core.ReasonHopLimit:
					lastRefusal = oe.Reason
					continue
				}
				fw.stats.Drop(DropRefused)
				fw.log.Debug("refused downstream", "reason", oe.Reason, "proto", meta.Proto, "src", meta.Src, "dst", meta.Dst,
					"identity", meta.Identity, "peer", n.Peer)
				core.Refuse(f, oe.Reason)
				return
			}
			if err != nil {
				of.Close()
				fw.log.Debug("no answer", "peer", n.Peer, "err", err)
				continue
			}
		}
		if err := core.Accept(f); err != nil {
			of.Close()
			return
		}
		fw.log.Debug("forward", "proto", meta.Proto, "src", meta.Src, "dst", meta.Dst, "identity", meta.Identity, "hops", out.Hops, "peer", n.Peer, "via_for", n.Advertiser)
		fw.splice(ctx, meta, f, of, in, n.Peer)
		return
	}
	if lastRefusal != 0 {
		fw.stats.Drop(DropRefused)
		core.Refuse(f, lastRefusal)
	} else if !tried {
		fw.drop(DropNoRoute, meta, in, f)
	} else {
		fw.drop(DropOpenFailed, meta, in, f)
	}
}

// dropReasons maps drop counters to the reason sent back to the opener.
var dropReasons = map[string]core.Reason{
	DropNoRoute:    core.ReasonNoRoute,
	DropDenied:     core.ReasonDenied,
	DropSpoofed:    core.ReasonDenied,
	DropHopLimit:   core.ReasonHopLimit,
	DropOpenFailed: core.ReasonUnreachable,
}

// drop counts and refuses a flow.
func (fw *Forwarder) drop(reason string, meta core.FlowMeta, in core.Ingress, f core.Flow) {
	fw.stats.Drop(reason)
	fw.log.Debug("drop", "reason", reason, "proto", meta.Proto, "src", meta.Src, "dst", meta.Dst,
		"identity", meta.Identity, "hops", meta.Hops, "ingress", in.Kind, "peer", in.Peer)
	r, ok := dropReasons[reason]
	if !ok {
		r = core.ReasonError
	}
	core.Refuse(f, r)
}

// counters returns the counters one flow updates: forward bytes go to the
// identity's tx, the ingress peer's rx and the egress peer's tx.
func (fw *Forwarder) counters(meta core.FlowMeta, in core.Ingress, outPeer string) (fwd, back func(int)) {
	id := fw.stats.Identity(meta.Identity)
	id.flows.Add(1)
	var inPeer, outP *Counter
	if in.Kind == "link" {
		inPeer = fw.stats.Peer(in.Peer)
		inPeer.flows.Add(1)
	}
	if outPeer != "" {
		outP = fw.stats.Peer(outPeer)
		outP.flows.Add(1)
	}
	fwd = func(n int) {
		id.tx.Add(uint64(n))
		if inPeer != nil {
			inPeer.rx.Add(uint64(n))
		}
		if outP != nil {
			outP.tx.Add(uint64(n))
		}
	}
	back = func(n int) {
		id.rx.Add(uint64(n))
		if inPeer != nil {
			inPeer.tx.Add(uint64(n))
		}
		if outP != nil {
			outP.rx.Add(uint64(n))
		}
	}
	return fwd, back
}

func (fw *Forwarder) deliverLocal(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress, opts egress.Options) {
	fwd, back := fw.counters(meta, in, "")
	cf := &countingFlow{Flow: f, read: fwd, write: back}
	fw.log.Debug("deliver", "proto", meta.Proto, "src", meta.Src, "dst", meta.Dst, "identity", meta.Identity, "hops", meta.Hops)
	if err := fw.deliver(ctx, meta, cf, opts); err != nil && ctx.Err() == nil {
		fw.stats.Drop(DropDeliver)
		fw.log.Debug("deliver failed", "proto", meta.Proto, "dst", meta.Dst, "err", err)
	}
}

// countingFlow counts bytes read (toward the destination) and written
// (back to the source).
type countingFlow struct {
	core.Flow
	read, write func(int)
}

func (c *countingFlow) Read(p []byte) (int, error) {
	n, err := c.Flow.Read(p)
	if n > 0 {
		c.read(n)
	}
	return n, err
}

func (c *countingFlow) Write(p []byte) (int, error) {
	n, err := c.Flow.Write(p)
	if n > 0 {
		c.write(n)
	}
	return n, err
}

func (c *countingFlow) Accept() error              { return core.Accept(c.Flow) }
func (c *countingFlow) Refuse(r core.Reason) error { return core.Refuse(c.Flow, r) }

func (fw *Forwarder) splice(ctx context.Context, meta core.FlowMeta, a, b core.Flow, in core.Ingress, outPeer string) {
	fwd, back := fw.counters(meta, in, outPeer)
	Splice(ctx, a, b, meta.Proto.IsDatagram(), fwd, back)
}

var bufPool = sync.Pool{New: func() any {
	b := make([]byte, link.MaxDatagram)
	return &b
}}

// Splice copies a to b and b to a until both directions finish, then closes
// both. For a byte stream, EOF on one side half-closes the other (CloseWrite)
// and the other direction continues; for datagrams every message is copied
// as one message and the end of either side ends both. An error on either
// side, or ctx ending, closes both. fwd and back, when not nil, count bytes
// copied a→b and b→a.
func Splice(ctx context.Context, a, b core.Flow, datagram bool, fwd, back func(int)) {
	stop := context.AfterFunc(ctx, func() {
		a.Close()
		b.Close()
	})
	defer stop()
	errc := make(chan error, 2)
	go func() { errc <- copyHalf(b, a, datagram, fwd) }()
	go func() { errc <- copyHalf(a, b, datagram, back) }()
	for range 2 {
		if err := <-errc; err != nil || datagram {
			a.Close()
			b.Close()
		}
	}
	a.Close()
	b.Close()
}

// errEnded marks the clean end of a datagram direction.
var errEnded = errors.New("ended")

func copyHalf(dst, src core.Flow, datagram bool, count func(int)) error {
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	for {
		n, err := src.Read(buf)
		var oe *core.OpenError
		if errors.As(err, &oe) {
			// The far end refused a flow that did not wait for the answer
			// (a datagram flow): pass the refusal on.
			core.Refuse(dst, oe.Reason)
			return err
		}
		if err == nil || (n > 0 && !datagram) {
			if n > 0 || datagram {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return werr
				}
				if count != nil && n > 0 {
					count(n)
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if datagram {
					return errEnded
				}
				return dst.CloseWrite()
			}
			return err
		}
	}
}
