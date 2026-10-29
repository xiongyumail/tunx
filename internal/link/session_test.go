package link

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiongyumail/tunx/internal/core"
)

func tcpMeta() core.FlowMeta {
	return core.FlowMeta{
		Proto:    core.ProtoTCP,
		Src:      netip.MustParseAddrPort("10.0.0.1:40000"),
		Dst:      netip.MustParseAddrPort("10.0.1.1:80"),
		Identity: "node-a",
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	long := string(bytes.Repeat([]byte{'x'}, MaxIdentityLen))
	metas := []core.FlowMeta{
		tcpMeta(),
		{Proto: core.ProtoUDP, Src: netip.MustParseAddrPort("[fd00::1]:53"), Dst: netip.MustParseAddrPort("[2001:db8::2]:5353"), Identity: long, Hops: 7},
		{Proto: core.ProtoICMP, Src: netip.MustParseAddrPort("192.0.2.1:4660"), Dst: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), 0)},
		{Proto: core.ProtoICMPv6, Dst: netip.MustParseAddrPort("[::ffff:1.2.3.4]:0")},
	}
	for _, m := range metas {
		body, err := encodeFlowMeta(m)
		if err != nil {
			t.Fatal(err)
		}
		typ, got, err := readHeader(bytes.NewReader(append(encodeHeader(streamFlow, body), "rest"...)))
		if err != nil || typ != streamFlow {
			t.Fatalf("readHeader: %d %v", typ, err)
		}
		// Trailing fields from a later version are ignored.
		m2, err := parseFlowMeta(append(got, 1, 2, 3))
		if err != nil {
			t.Fatal(err)
		}
		if m2 != m {
			t.Fatalf("round trip: got %+v, want %+v", m2, m)
		}
	}
	if _, err := encodeFlowMeta(core.FlowMeta{Identity: long + "x"}); err == nil {
		t.Fatal("identity over limit accepted")
	}
	if _, err := parseFlowMeta([]byte{6, 0, 5, 1, 2}); err == nil {
		t.Fatal("bad address family accepted")
	}
	if _, _, err := readHeader(bytes.NewReader([]byte{9, 2, 0, 0})); !errors.Is(err, ErrProtocol) {
		t.Fatalf("unknown header version: %v", err)
	}
}

type flowRecord struct {
	meta core.FlowMeta
	in   core.Ingress
}

func TestFlowBothDirections(t *testing.T) {
	cc, sc := testConfigs(t)
	var mu sync.Mutex
	var seen []flowRecord
	record := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
		mu.Lock()
		seen = append(seen, flowRecord{meta, in})
		mu.Unlock()
		echoHandler(ctx, meta, f, in)
	})
	c1, c2 := net.Pipe()
	cs, ss := sessionPair(t, cc, sc, c1, c2, record, record)

	for _, s := range []*Session{cs, ss} {
		meta := tcpMeta()
		meta.Identity = "from-" + s.Peer()
		meta.Hops = 2
		f, err := s.OpenFlow(context.Background(), meta)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("hello " + s.Peer())
		f.Write(msg)
		f.CloseWrite()
		got, err := io.ReadAll(f)
		f.Close()
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("echo via %s: %q %v", s.Peer(), got, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("handlers saw %d flows", len(seen))
	}
	want := map[string]string{"from-node-b": "node-a", "from-node-a": "node-b"}
	for _, r := range seen {
		if r.in.Kind != "link" || r.in.Peer != want[r.meta.Identity] || r.meta.Hops != 2 || r.meta.Dst != tcpMeta().Dst {
			t.Fatalf("unexpected flow %+v %+v", r.meta, r.in)
		}
	}
}

func TestTCPHalfClose(t *testing.T) {
	cc, sc := testConfigs(t)
	// The server reads the whole request first, then answers: the answer
	// can only arrive if the reverse direction survived CloseWrite.
	handler := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
		defer f.Close()
		req, err := io.ReadAll(f)
		if err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
		fmt.Fprintf(f, "got %d bytes: %s", len(req), req)
		f.CloseWrite()
		// The client keeps its side open until it has read our EOF.
		var b [1]byte
		if _, err := f.Read(b[:]); err != io.EOF {
			panic("read after EOF")
		}
	})
	c1, c2 := tcpPair(t)
	cs, _ := sessionPair(t, cc, sc, c1, c2, nil, handler)
	f, err := cs.OpenFlow(context.Background(), tcpMeta())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write([]byte("ping"))
	if err := f.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("x")); err == nil {
		t.Fatal("write after CloseWrite succeeded")
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "got 4 bytes: ping" {
		t.Fatalf("answer %q", got)
	}
}

func TestTCPPeerCloseFailsWrites(t *testing.T) {
	cc, sc := testConfigs(t)
	closer := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
		f.Close()
	})
	c1, c2 := tcpPair(t)
	cs, _ := sessionPair(t, cc, sc, c1, c2, nil, closer)
	f, err := cs.OpenFlow(context.Background(), tcpMeta())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	readErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, f)
		readErr <- err
	}()
	if err := <-readErr; err != nil {
		t.Fatalf("read after peer close: %v", err)
	}
	buf := make([]byte, 16<<10)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := f.Write(buf); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("writes to a closed peer keep succeeding")
		}
	}
}

func TestLargeTransfer(t *testing.T) {
	size := 64 << 20
	if testing.Short() {
		size = 4 << 20
	}
	cc, sc := testConfigs(t)
	c1, c2 := tcpPair(t)
	cs, _ := sessionPair(t, cc, sc, c1, c2, nil, echoHandler)
	f, err := cs.OpenFlow(context.Background(), tcpMeta())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	sent := sha256.New()
	go func() {
		rng := rand.NewChaCha8([32]byte{1})
		buf := make([]byte, 100_000)
		for left := size; left > 0; {
			n := min(left, len(buf))
			rng.Read(buf[:n])
			sent.Write(buf[:n])
			if _, err := f.Write(buf[:n]); err != nil {
				return
			}
			left -= n
		}
		f.CloseWrite()
	}()
	got := sha256.New()
	n, err := io.Copy(got, f)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(size) || !bytes.Equal(got.Sum(nil), sent.Sum(nil)) {
		t.Fatalf("received %d bytes, hash match %v", n, bytes.Equal(got.Sum(nil), sent.Sum(nil)))
	}
}

func TestConcurrentFlows(t *testing.T) {
	cc, sc := testConfigs(t)
	c1, c2 := tcpPair(t)
	cs, ss := sessionPair(t, cc, sc, c1, c2, echoHandler, echoHandler)
	const flows = 200
	var wg sync.WaitGroup
	var failed atomic.Int32
	for i := range flows {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := cs
			if i%2 == 1 {
				s = ss
			}
			f, err := s.OpenFlow(context.Background(), tcpMeta())
			if err != nil {
				failed.Add(1)
				return
			}
			defer f.Close()
			msg := make([]byte, 64<<10)
			rand.NewChaCha8([32]byte{byte(i)}).Read(msg)
			go func() {
				f.Write(msg)
				f.CloseWrite()
			}()
			got, err := io.ReadAll(f)
			if err != nil || !bytes.Equal(got, msg) {
				failed.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := failed.Load(); n > 0 {
		t.Fatalf("%d of %d flows failed", n, flows)
	}
}

func TestDatagramBoundaries(t *testing.T) {
	cc, sc := testConfigs(t)
	c1, c2 := net.Pipe()
	cs, _ := sessionPair(t, cc, sc, c1, c2, nil, echoHandler)
	meta := core.FlowMeta{
		Proto: core.ProtoUDP,
		Src:   netip.MustParseAddrPort("10.0.0.1:5000"),
		Dst:   netip.MustParseAddrPort("10.0.1.1:53"),
	}
	f, err := cs.OpenFlow(context.Background(), meta)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	sizes := []int{1, 0, 100, MaxDatagram, 1500, 1500, 3, 40000}
	go func() {
		for i, n := range sizes {
			f.Write(bytes.Repeat([]byte{byte(i + 1)}, n))
		}
	}()
	buf := make([]byte, MaxDatagram)
	for i, n := range sizes {
		got, err := f.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if got != n || !bytes.Equal(buf[:got], bytes.Repeat([]byte{byte(i + 1)}, n)) {
			t.Fatalf("message %d: got %d bytes, want %d", i, got, n)
		}
	}

	if _, err := f.Write(make([]byte, MaxDatagram+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversize write: %v", err)
	}

	// A short buffer truncates one message and leaves the next intact.
	f.Write([]byte("0123456789"))
	f.Write([]byte("next"))
	small := make([]byte, 4)
	if n, err := f.Read(small); err != nil || string(small[:n]) != "0123" {
		t.Fatalf("truncated read: %q %v", small[:n], err)
	}
	if n, err := f.Read(buf); err != nil || string(buf[:n]) != "next" {
		t.Fatalf("read after truncation: %q %v", buf[:n], err)
	}
}

func TestControlMessages(t *testing.T) {
	cc, sc := testConfigs(t)
	type msg struct {
		at   string
		typ  uint8
		data string
	}
	got := make(chan msg, 4)
	on := func(s *Session, typ uint8, payload []byte) { got <- msg{s.Peer(), typ, string(payload)} }
	cc.OnControl, sc.OnControl = on, on
	c1, c2 := net.Pipe()
	cs, ss := sessionPair(t, cc, sc, c1, c2, nil, nil)

	ctx := context.Background()
	if err := cs.SendControl(ctx, 0x20, []byte("routes v1")); err != nil {
		t.Fatal(err)
	}
	if err := ss.SendControl(ctx, 0x21, nil); err != nil {
		t.Fatal(err)
	}
	want := map[msg]bool{{"node-a", 0x20, "routes v1"}: true, {"node-b", 0x21, ""}: true}
	for range 2 {
		select {
		case m := <-got:
			if !want[m] {
				t.Fatalf("unexpected control message %+v", m)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("control message not delivered")
		}
	}
	if err := cs.SendControl(ctx, ctrlPing, nil); err == nil {
		t.Fatal("reserved control type accepted")
	}
}

func TestKeepaliveTimeout(t *testing.T) {
	cc, sc := testConfigs(t)
	for _, c := range []*Config{&cc, &sc} {
		c.KeepaliveInterval = 50 * time.Millisecond
		c.KeepaliveTimeout = 300 * time.Millisecond
	}
	c1, c2 := tcpPair(t)
	bh := newBlackhole(c1)
	cs, ss := sessionPair(t, cc, sc, bh, c2, nil, nil)

	// Healthy: the session outlives several timeouts.
	time.Sleep(time.Second)
	if cs.Err() != nil || ss.Err() != nil || cs.RTT() == 0 {
		t.Fatalf("healthy session failed: %v %v rtt %v", cs.Err(), ss.Err(), cs.RTT())
	}

	bh.enable()
	start := time.Now()
	waitDone(t, cs, 3*time.Second)
	waitDone(t, ss, 3*time.Second)
	if !errors.Is(cs.Err(), ErrKeepalive) {
		t.Fatalf("client err %v", cs.Err())
	}
	t.Logf("dead link detected in %v (server: %v)", time.Since(start), ss.Err())
}

func TestKeepReconnects(t *testing.T) {
	cc, sc := testConfigs(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				s, err := Server(ctx, c, sc)
				if err != nil {
					return
				}
				s.Serve(ctx, echoHandler)
				s.Close()
			}()
		}
	}()

	conns := make(chan net.Conn, 8)
	dial := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", ln.Addr().String())
		if err == nil {
			conns <- c
		}
		return c, err
	}
	sessions := make(chan *Session, 8)
	keepErr := make(chan error, 1)
	go func() { keepErr <- Keep(ctx, dial, cc, func(s *Session) { sessions <- s }) }()

	echo := func(s *Session) {
		t.Helper()
		f, err := s.OpenFlow(ctx, tcpMeta())
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		f.Write([]byte("hi"))
		f.CloseWrite()
		if got, err := io.ReadAll(f); err != nil || string(got) != "hi" {
			t.Fatalf("echo: %q %v", got, err)
		}
	}
	next := func() *Session {
		t.Helper()
		select {
		case s := <-sessions:
			return s
		case <-time.After(5 * time.Second):
			t.Fatal("no session")
			return nil
		}
	}

	s1 := next()
	echo(s1)
	(<-conns).Close() // kill the transport under the session
	waitDone(t, s1, 3*time.Second)
	s2 := next()
	if s2 == s1 {
		t.Fatal("same session")
	}
	echo(s2)

	cancel()
	select {
	case err := <-keepErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Keep returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Keep did not return")
	}
	waitDone(t, s2, time.Second)
}
