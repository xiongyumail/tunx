package link

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiongyumail/tunx/internal/core"
)

// writeGate leaves reads independent while an underlying write is stalled.
type writeGate struct {
	net.Conn
	enabled atomic.Bool
	active  atomic.Int64
	entered chan struct{}
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newWriteGate(c net.Conn) *writeGate {
	return &writeGate{Conn: c, entered: make(chan struct{}, 1), release: make(chan struct{}), closed: make(chan struct{})}
}

func (c *writeGate) Write(p []byte) (int, error) {
	if c.enabled.Load() {
		c.active.Add(1)
		defer c.active.Add(-1)
		select {
		case c.entered <- struct{}{}:
		default:
		}
		select {
		case <-c.release:
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	return c.Conn.Write(p)
}

func (c *writeGate) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func waitControl(t *testing.T, got <-chan struct{}) {
	t.Helper()
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("control reader stopped progressing")
	}
}

func TestControlBlockedPongKeepsReceiving(t *testing.T) {
	cc, sc := testConfigs(t)
	cc.KeepaliveInterval, sc.KeepaliveInterval = time.Hour, time.Hour
	cc.KeepaliveTimeout, sc.KeepaliveTimeout = 200*time.Millisecond, time.Hour
	got := make(chan struct{}, 1)
	cc.OnControl = func(*Session, uint8, []byte) { got <- struct{}{} }
	c1, c2 := net.Pipe()
	gate := newWriteGate(c1)
	bh := newBlackhole(gate)
	cs, ss := sessionPair(t, cc, sc, bh, c2, nil, nil)
	// Finish the control stream's initial window update before gating writes.
	if err := ss.SendControl(context.Background(), MinControlType, nil); err != nil {
		t.Fatal(err)
	}
	waitControl(t, got)
	gate.enabled.Store(true)
	ping := func() {
		t.Helper()
		var payload [8]byte
		binary.BigEndian.PutUint64(payload[:], uint64(ss.since()))
		if err := ss.writeControl(time.Now().Add(time.Second), ctrlPing, payload[:]); err != nil {
			t.Fatal(err)
		}
	}
	ping()
	waitControl(t, gate.entered)
	baseline := runtime.NumGoroutine()
	first := cs.lastReceive.Load()
	start := time.Now()
	for time.Since(start) < 3*cc.KeepaliveTimeout {
		for range 16 {
			ping()
		}
		if err := ss.SendControl(context.Background(), MinControlType, nil); err != nil {
			t.Fatal(err)
		}
		waitControl(t, got)
		if cs.Err() != nil {
			t.Fatalf("inbound progress did not keep session alive: %v", cs.Err())
		}
		if cap(cs.pongs) != 1 || len(cs.pongs) > 1 || gate.active.Load() != 1 {
			t.Fatal("pong responder exceeded its queue/write bound")
		}
		if n := runtime.NumGoroutine(); n > baseline+4 {
			t.Fatalf("ping burst grew goroutines: before %d, after %d", baseline, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cs.lastReceive.Load() <= first {
		t.Fatal("transport receive timestamp did not advance")
	}
	close(gate.release)
	ping()
	deadline := time.Now().Add(time.Second)
	for ss.RTT() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ss.RTT() == 0 || cs.Err() != nil {
		t.Fatalf("pong did not recover: RTT %v, session %v", ss.RTT(), cs.Err())
	}
	// Successful writes cannot keep a genuinely silent receive path alive.
	bh.enable()
	stopped := time.Now()
	for cs.Err() == nil && time.Since(stopped) < cc.KeepaliveTimeout+100*time.Millisecond {
		cs.SendControl(context.Background(), MinControlType, nil)
		time.Sleep(5 * time.Millisecond)
	}
	waitDone(t, cs, 100*time.Millisecond)
	if !errors.Is(cs.Err(), ErrKeepalive) || time.Since(stopped) > cc.KeepaliveTimeout+150*time.Millisecond {
		t.Fatalf("silent path timeout: %v after %v", cs.Err(), time.Since(stopped))
	}
}

func TestControlCloseBlockedResponder(t *testing.T) {
	cc, sc := testConfigs(t)
	cc.KeepaliveInterval, sc.KeepaliveInterval = time.Hour, time.Hour
	cc.KeepaliveTimeout, sc.KeepaliveTimeout = time.Hour, time.Hour
	got := make(chan struct{}, 1)
	cc.OnControl = func(*Session, uint8, []byte) { got <- struct{}{} }
	c1, c2 := net.Pipe()
	gate := newWriteGate(c1)
	cs, ss := sessionPair(t, cc, sc, gate, c2, nil, nil)
	ss.SendControl(context.Background(), MinControlType, nil)
	waitControl(t, got)
	gate.enabled.Store(true)
	ss.writeControl(time.Now().Add(time.Second), ctrlPing, make([]byte, 8))
	waitControl(t, gate.entered)
	for range 64 {
		ss.writeControl(time.Now().Add(time.Second), ctrlPing, make([]byte, 8))
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { cs.Close() })
	}
	wg.Wait()
	waitDone(t, cs, time.Second)
	deadline := time.Now().Add(time.Second)
	for gate.active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if gate.active.Load() != 0 {
		t.Fatal("closing the session left its pong write blocked")
	}
}

func TestKeepaliveBufferedReadsDoNotRefresh(t *testing.T) {
	cc, sc := testConfigs(t)
	cc.KeepaliveInterval, sc.KeepaliveInterval = time.Hour, time.Hour
	cc.KeepaliveTimeout, sc.KeepaliveTimeout = 240*time.Millisecond, time.Hour
	incoming := make(chan core.Flow, 1)
	h := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
		defer f.Close()
		core.Accept(f)
		incoming <- f
		<-ctx.Done()
	})
	c1, c2 := tcpPair(t)
	bh := newBlackhole(c1)
	cs, ss := sessionPair(t, cc, sc, bh, c2, h, nil)
	out, err := ss.OpenFlow(context.Background(), tcpMeta())
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	in := <-incoming
	payload := bytes.Repeat([]byte("x"), 128)
	if _, err := out.Write(payload); err != nil {
		t.Fatal(err)
	}
	// One read confirms arrival and completes smux's initial window update.
	if _, err := io.ReadFull(in, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	bh.enable()
	last := cs.lastReceive.Load()
	start := time.Now()
	for range 3 {
		time.Sleep(cc.KeepaliveTimeout / 4)
		if _, err := io.ReadFull(in, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		if cs.lastReceive.Load() != last {
			t.Fatal("buffered application read refreshed transport liveness")
		}
	}
	waitDone(t, cs, cc.KeepaliveTimeout/2)
	if !errors.Is(cs.Err(), ErrKeepalive) || time.Since(start) > cc.KeepaliveTimeout+100*time.Millisecond {
		t.Fatalf("buffered reads delayed timeout: %v after %v", cs.Err(), time.Since(start))
	}
}

type readResultConn struct {
	net.Conn
	n   int
	err error
}

func (c *readResultConn) Read(p []byte) (int, error)  { return c.n, c.err }
func (c *readResultConn) Write(p []byte) (int, error) { return len(p), nil }

func TestKeepaliveReceiveCountsBytesWithError(t *testing.T) {
	var last atomic.Int64
	underlying := &readResultConn{n: 1, err: io.EOF}
	conn := &receiveConn{Conn: underlying, start: time.Now().Add(-time.Second), last: &last}
	if n, err := conn.Read(make([]byte, 1)); n != 1 || !errors.Is(err, io.EOF) || last.Load() < int64(time.Second) {
		t.Fatalf("positive read with EOF lost progress: %d %v %d", n, err, last.Load())
	}
	observed := last.Load()
	underlying.n = 0
	conn.Read(make([]byte, 1))
	conn.Write([]byte("write"))
	if last.Load() != observed {
		t.Fatal("empty read or successful write refreshed liveness")
	}
	last.Store(int64(2 * time.Second))
	underlying.n = 1
	conn.Read(make([]byte, 1))
	if last.Load() != int64(2*time.Second) {
		t.Fatal("receive timestamp regressed")
	}
}
