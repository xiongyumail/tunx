package netstack

import (
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/xiongyumail/tunx/internal/core"
)

// handleUDP is called on the dispatch goroutine for the first packet of a
// new (src, dst) pair. The connected endpoint it creates receives that packet
// and every later one of the pair until the flow closes.
func (s *Stack) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return true // drop
	}
	f := &udpFlow{s: s, UDPConn: gonet.NewUDPConn(&wq, ep)}
	f.idle = newIdleTimer(s.cfg.UDPIdleTimeout, func() { f.Close() })
	if !s.track(f) {
		f.Close()
		return true
	}
	meta := core.FlowMeta{
		Proto: core.ProtoUDP,
		Src:   addrPort(id.RemoteAddress, id.RemotePort),
		Dst:   addrPort(id.LocalAddress, id.LocalPort),
	}
	go s.serve(meta, f)
	return true
}

// udpFlow is one UDP (src, dst) pair. Every Read returns one datagram (cut to
// the buffer size) and every Write sends one.
type udpFlow struct {
	*gonet.UDPConn
	s         *Stack
	idle      *idleTimer
	closeOnce sync.Once
}

func (f *udpFlow) Read(b []byte) (int, error) {
	n, err := f.UDPConn.Read(b)
	if err == nil {
		f.idle.touch()
	}
	return n, err
}

func (f *udpFlow) Write(b []byte) (int, error) {
	f.idle.touch()
	return f.UDPConn.Write(b)
}

func (f *udpFlow) CloseWrite() error { return f.Close() }

func (f *udpFlow) Close() error {
	f.closeOnce.Do(func() {
		f.idle.stop()
		f.UDPConn.Close()
		f.s.untrack(f)
	})
	return nil
}

// idleTimer calls fire once no touch happened for the timeout.
type idleTimer struct {
	timeout time.Duration
	fire    func()

	mu      sync.Mutex
	last    time.Time
	t       *time.Timer
	stopped bool
}

func newIdleTimer(d time.Duration, fire func()) *idleTimer {
	it := &idleTimer{timeout: d, fire: fire, last: time.Now()}
	it.mu.Lock()
	it.t = time.AfterFunc(d, it.check)
	it.mu.Unlock()
	return it
}

func (it *idleTimer) touch() {
	it.mu.Lock()
	it.last = time.Now()
	it.mu.Unlock()
}

func (it *idleTimer) check() {
	it.mu.Lock()
	if it.stopped {
		it.mu.Unlock()
		return
	}
	if left := it.timeout - time.Since(it.last); left > 0 {
		it.t.Reset(left)
		it.mu.Unlock()
		return
	}
	it.stopped = true
	it.mu.Unlock()
	it.fire()
}

func (it *idleTimer) stop() {
	it.mu.Lock()
	it.stopped = true
	it.t.Stop()
	it.mu.Unlock()
}
