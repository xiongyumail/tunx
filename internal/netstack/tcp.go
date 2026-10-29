package netstack

import (
	"net"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/xiongyumail/tunx/internal/core"
)

// handleTCP runs in its own goroutine for every new SYN (the forwarder starts
// it). The handshake is completed lazily, on the handler's first read or
// write, so a handler that refuses the flow, or fails to reach the
// destination, leaves the SYN unanswered (or reset, see TCPRejectWithReset).
// The SYN occupies a forwarder slot until then, which bounds the backlog.
func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	f := &tcpFlow{s: s, req: r, ready: make(chan struct{})}
	if !s.track(f) {
		r.Complete(s.cfg.TCPRejectWithReset)
		return
	}
	meta := core.FlowMeta{
		Proto: core.ProtoTCP,
		Src:   addrPort(id.RemoteAddress, id.RemotePort),
		Dst:   addrPort(id.LocalAddress, id.LocalPort),
	}
	s.serve(meta, f)
}

const (
	tcpIdle = iota
	tcpAccepting
	tcpAccepted
	tcpClosed
)

// tcpFlow is a TCP connection from the TUN whose handshake completes on first
// use.
type tcpFlow struct {
	s     *Stack
	req   *tcp.ForwarderRequest
	ready chan struct{} // closed when an accept attempt finishes

	mu    sync.Mutex
	state int
	conn  *gonet.TCPConn
	err   error

	closeOnce sync.Once
}

// accept completes the handshake once; concurrent callers wait for it.
func (f *tcpFlow) accept() (*gonet.TCPConn, error) {
	f.mu.Lock()
	switch f.state {
	case tcpClosed:
		f.mu.Unlock()
		return nil, net.ErrClosed
	case tcpAccepted:
		c := f.conn
		f.mu.Unlock()
		return c, nil
	case tcpAccepting:
		f.mu.Unlock()
		<-f.ready
		f.mu.Lock()
		c, err := f.conn, f.err
		f.mu.Unlock()
		return c, err
	}
	f.state = tcpAccepting
	f.mu.Unlock()

	var wq waiter.Queue
	ep, terr := f.req.CreateEndpoint(&wq)
	if terr != nil {
		f.req.Complete(true)
	} else {
		f.req.Complete(false)
	}

	f.mu.Lock()
	defer close(f.ready)
	defer f.mu.Unlock()
	switch {
	case terr != nil:
		f.err = &net.OpError{Op: "accept", Net: "tcp", Err: tcpError{terr.String()}}
		f.state = tcpClosed
	case f.state == tcpClosed: // closed while the handshake ran
		ep.Close()
		f.err = net.ErrClosed
	default:
		f.conn = gonet.NewTCPConn(&wq, ep)
		f.state = tcpAccepted
	}
	return f.conn, f.err
}

func (f *tcpFlow) Read(b []byte) (int, error) {
	c, err := f.accept()
	if err != nil {
		return 0, err
	}
	return c.Read(b)
}

func (f *tcpFlow) Write(b []byte) (int, error) {
	c, err := f.accept()
	if err != nil {
		return 0, err
	}
	return c.Write(b)
}

func (f *tcpFlow) CloseWrite() error {
	c, err := f.accept()
	if err != nil {
		return err
	}
	return c.CloseWrite()
}

func (f *tcpFlow) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		prev := f.state
		f.state = tcpClosed
		c := f.conn
		f.mu.Unlock()
		switch prev {
		case tcpIdle:
			f.req.Complete(f.s.cfg.TCPRejectWithReset)
		case tcpAccepted:
			c.Close()
		}
		// tcpAccepting: accept sees tcpClosed and closes the endpoint.
		f.s.untrack(f)
	})
	return nil
}

type tcpError struct{ s string }

func (e tcpError) Error() string { return e.s }
