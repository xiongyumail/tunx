package link

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiongyumail/tunx/internal/core"
	"github.com/xtaci/smux"
)

// Control message types. Types below MinControlType belong to this package.
const (
	ctrlPing uint8 = 1
	ctrlPong uint8 = 2

	// MinControlType is the lowest type available to SendControl.
	MinControlType uint8 = 0x10
)

// Session is an authenticated, multiplexed link to one peer. Either side
// opens flows with OpenFlow; flows the peer opens wait until Serve takes them.
type Session struct {
	cfg     Config
	peer    string
	client  bool
	version uint8
	mux     *smux.Session
	start   time.Time

	incoming chan inbound

	ctrlOnce  sync.Once
	ctrlReady chan struct{}
	ctrl      *smux.Stream
	ctrlMu    sync.Mutex  // serializes control writes
	pongs     chan []byte // one pending response; another may be in flight

	lastReceive atomic.Int64 // underlying transport reads, nanoseconds since start
	srtt        atomic.Int64 // smoothed RTT, nanoseconds
	pinging     atomic.Bool

	closeOnce sync.Once
	done      chan struct{}
	err       error
}

type inbound struct {
	meta core.FlowMeta
	flow core.Flow
}

// Client runs the handshake as the dialing side and starts the session. On
// error conn is closed. ctx bounds only the handshake.
func Client(ctx context.Context, conn net.Conn, cfg Config) (*Session, error) {
	return handshake(ctx, conn, cfg, true)
}

// Server runs the handshake as the accepting side and starts the session. On
// error conn is closed. ctx bounds only the handshake.
func Server(ctx context.Context, conn net.Conn, cfg Config) (*Session, error) {
	return handshake(ctx, conn, cfg, false)
}

func handshake(ctx context.Context, conn net.Conn, cfg Config, client bool) (*Session, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		conn.Close()
		return nil, err
	}
	deadline := time.Now().Add(cfg.HandshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })

	var peer string
	var version uint8
	var err error
	if client {
		peer, version, err = clientHandshake(conn, &cfg)
	} else {
		peer, version, err = serverHandshake(conn, &cfg)
	}
	if !stop() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			err = fmt.Errorf("%w (%v)", ctx.Err(), err)
		}
		return nil, fmt.Errorf("link: handshake with %s: %w", conn.RemoteAddr(), err)
	}
	conn.SetDeadline(time.Time{})

	s, err := newSession(conn, cfg, peer, client, version)
	if err != nil {
		conn.Close()
		return nil, err
	}
	cfg.Logger.Info("link session up", "peer", peer, "client", client, "version", version)
	return s, nil
}

func newSession(conn net.Conn, cfg Config, peer string, client bool, version uint8) (*Session, error) {
	mc := &smux.Config{
		Version:           2,
		KeepAliveDisabled: true,
		MaxFrameSize:      muxFrameSize,
		MaxReceiveBuffer:  cfg.MaxReceiveBuffer,
		MaxStreamBuffer:   cfg.MaxStreamBuffer,
	}
	s := &Session{
		cfg:       cfg,
		peer:      peer,
		client:    client,
		version:   version,
		start:     time.Now(),
		incoming:  make(chan inbound),
		ctrlReady: make(chan struct{}),
		pongs:     make(chan []byte, 1),
		done:      make(chan struct{}),
	}
	s.lastReceive.Store(s.since())
	// Start observing only after authentication, before smux can read ahead.
	observed := &receiveConn{Conn: conn, start: s.start, last: &s.lastReceive}
	var mux *smux.Session
	var err error
	if client {
		mux, err = smux.Client(observed, mc)
	} else {
		mux, err = smux.Server(observed, mc)
	}
	if err != nil {
		return nil, err
	}
	s.mux = mux
	if client {
		// The dialing side opens the control stream first.
		st, err := mux.OpenStream()
		if err == nil {
			_, err = st.Write(encodeHeader(streamControl, nil))
		}
		if err != nil {
			mux.Close()
			return nil, err
		}
		s.setControl(st)
	}
	go s.acceptLoop()
	go s.keepalive()
	go func() {
		select {
		case <-mux.CloseChan():
			s.closeWith(ErrClosed)
		case <-s.done:
		}
	}()
	return s, nil
}

// receiveConn observes bytes actually returned by the authenticated transport.
// Buffered application reads and successful writes cannot refresh liveness.
type receiveConn struct {
	net.Conn
	start time.Time
	last  *atomic.Int64
}

func (c *receiveConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		now := int64(time.Since(c.start))
		for old := c.last.Load(); now > old; old = c.last.Load() {
			if c.last.CompareAndSwap(old, now) {
				break
			}
		}
	}
	return n, err
}

// Peer returns the authenticated name of the node on the other end.
func (s *Session) Peer() string { return s.peer }

// Version returns the negotiated protocol version.
func (s *Session) Version() uint8 { return s.version }

// RTT returns the smoothed round-trip time of keepalive pings, or 0 before
// the first pong.
func (s *Session) RTT() time.Duration { return time.Duration(s.srtt.Load()) }

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err returns why the session ended, or nil while it is up.
func (s *Session) Err() error {
	select {
	case <-s.done:
		return s.err
	default:
		return nil
	}
}

// Close ends the session and closes the underlying connection.
func (s *Session) Close() error {
	s.closeWith(ErrClosed)
	return nil
}

func (s *Session) closeWith(err error) {
	s.closeOnce.Do(func() {
		s.err = err
		close(s.done)
		s.mux.Close()
		s.cfg.Logger.Info("link session down", "peer", s.peer, "err", err)
	})
}

// OpenFlow opens a flow to the peer. A deadline on ctx bounds sending the
// stream header. The flow may be written at once; its first Read, or
// WaitOpen, returns the peer's answer first: a *core.OpenError when the peer
// refused the flow.
func (s *Session) OpenFlow(ctx context.Context, meta core.FlowMeta) (core.Flow, error) {
	body, err := encodeFlowMeta(meta)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	st, err := s.mux.OpenStream()
	if err != nil {
		return nil, err
	}
	if d, ok := ctx.Deadline(); ok {
		st.SetWriteDeadline(d)
	}
	if _, err := st.Write(encodeHeader(streamFlow, body)); err != nil {
		st.Close()
		return nil, err
	}
	st.SetWriteDeadline(time.Time{})
	return newFlow(st, meta.Proto, s.answers(), true), nil
}

// Serve hands flows opened by the peer to h, each in its own goroutine, with
// Ingress{Kind: "link", Peer: s.Peer()}. The context passed to h is canceled
// when ctx is or the session ends. Serve returns when either happens.
func (s *Session) Serve(ctx context.Context, h core.Handler) error {
	hctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-s.done:
			cancel()
		case <-hctx.Done():
		}
	}()
	in := core.Ingress{Kind: "link", Peer: s.peer}
	for {
		select {
		case f := <-s.incoming:
			go h.HandleFlow(hctx, f.meta, f.flow, in)
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			return s.err
		}
	}
}

// answers reports whether flows on this session carry an open answer.
func (s *Session) answers() bool { return s.version >= versionAnswer }

func (s *Session) acceptLoop() {
	for {
		st, err := s.mux.AcceptStream()
		if err != nil {
			s.closeWith(ErrClosed)
			return
		}
		go s.handleStream(st)
	}
}

func (s *Session) handleStream(st *smux.Stream) {
	st.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	typ, body, err := readHeader(st)
	st.SetReadDeadline(time.Time{})
	if err != nil {
		s.cfg.Logger.Debug("link: bad stream header", "peer", s.peer, "err", err)
		st.Close()
		return
	}
	switch typ {
	case streamControl:
		if s.client || !s.setControl(st) {
			st.Close()
		}
	case streamFlow:
		meta, err := parseFlowMeta(body)
		if err != nil {
			st.Close()
			return
		}
		f := newFlow(st, meta.Proto, s.answers(), false)
		select {
		case s.incoming <- inbound{meta: meta, flow: f}:
		case <-s.done:
			f.Close()
		}
	default:
		st.Close()
	}
}

// setControl installs the control stream once and starts its reader.
func (s *Session) setControl(st *smux.Stream) bool {
	ok := false
	s.ctrlOnce.Do(func() {
		s.ctrl = st
		close(s.ctrlReady)
		go s.controlLoop(st)
		go s.pongLoop()
		ok = true
	})
	return ok
}

// Control message: type (1), payload length (4), payload.
func (s *Session) controlLoop(st *smux.Stream) {
	var h [5]byte
	for {
		if _, err := io.ReadFull(st, h[:]); err != nil {
			s.closeWith(fmt.Errorf("%w: control stream: %v", ErrClosed, err))
			return
		}
		n := binary.BigEndian.Uint32(h[1:])
		if n > MaxControlLen {
			s.closeWith(fmt.Errorf("%w: control message too large", ErrProtocol))
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(st, payload); err != nil {
			s.closeWith(fmt.Errorf("%w: control stream: %v", ErrClosed, err))
			return
		}
		switch typ := h[0]; {
		case typ == ctrlPing:
			// Do not let an outbound stall stop the sole control reader.
			// Payloads are bounded by MaxControlLen; redundant requests
			// are dropped while one response is pending.
			select {
			case s.pongs <- payload:
			default:
			}
		case typ == ctrlPong:
			s.onPong(payload)
		case typ >= MinControlType && s.cfg.OnControl != nil:
			s.cfg.OnControl(s, typ, payload)
		}
	}
}

// pongLoop is the only pong writer: one in-flight write and one queued
// payload. The queue stays open; done and closing smux unblock shutdown.
func (s *Session) pongLoop() {
	for {
		select {
		case <-s.done:
			return
		case payload := <-s.pongs:
			select {
			case <-s.done:
				return
			default:
			}
			s.writeControl(time.Now().Add(s.cfg.KeepaliveTimeout), ctrlPong, payload)
		}
	}
}

// SendControl sends an application control message to the peer. typ must be
// at least MinControlType. A deadline on ctx bounds the write.
func (s *Session) SendControl(ctx context.Context, typ uint8, payload []byte) error {
	if typ < MinControlType {
		return fmt.Errorf("link: control type %#x is reserved", typ)
	}
	if len(payload) > MaxControlLen {
		return ErrMessageTooLarge
	}
	select {
	case <-s.ctrlReady:
	case <-s.done:
		return s.err
	case <-ctx.Done():
		return ctx.Err()
	}
	d, _ := ctx.Deadline()
	return s.writeControl(d, typ, payload)
}

func (s *Session) writeControl(deadline time.Time, typ uint8, payload []byte) error {
	b := make([]byte, 5, 5+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)))
	b = append(b, payload...)
	s.ctrlMu.Lock()
	defer s.ctrlMu.Unlock()
	s.ctrl.SetWriteDeadline(deadline)
	_, err := s.ctrl.Write(b)
	s.ctrl.SetWriteDeadline(time.Time{})
	return err
}

func (s *Session) since() int64 { return int64(time.Since(s.start)) }

func (s *Session) onPong(payload []byte) {
	if len(payload) != 8 {
		return
	}
	now := s.since()
	sent := int64(binary.BigEndian.Uint64(payload))
	if sent < 0 || sent > now {
		return
	}
	rtt := now - sent
	if old := s.srtt.Load(); old != 0 {
		rtt = (7*old + rtt) / 8
	}
	s.srtt.Store(rtt)
}

// keepalive closes after no transport bytes arrive for KeepaliveTimeout,
// checked every max(timeout/8, 1 ms). Pongs measure RTT independently.
func (s *Session) keepalive() {
	ping := time.NewTicker(s.cfg.KeepaliveInterval)
	defer ping.Stop()
	check := time.NewTicker(max(s.cfg.KeepaliveTimeout/8, time.Millisecond))
	defer check.Stop()
	timeout := int64(s.cfg.KeepaliveTimeout)
	for {
		select {
		case <-s.done:
			return
		case <-check.C:
			if s.since()-s.lastReceive.Load() > timeout {
				s.closeWith(ErrKeepalive)
				return
			}
		case <-ping.C:
			select {
			case <-s.ctrlReady:
			default:
				continue
			}
			if s.pinging.Swap(true) {
				continue // the previous ping is still blocked
			}
			go func() {
				defer s.pinging.Store(false)
				var b [8]byte
				binary.BigEndian.PutUint64(b[:], uint64(s.since()))
				s.writeControl(time.Now().Add(s.cfg.KeepaliveTimeout), ctrlPing, b[:])
			}()
		}
	}
}
