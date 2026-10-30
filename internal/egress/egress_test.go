package egress

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xiongyumail/tunx/internal/core"
)

// msgFlow is one end of an in-memory datagram flow: every Write is one
// message for the peer's Read.
type msgFlow struct {
	in, out    chan []byte
	done, peer chan struct{}
	once       *sync.Once
}

func msgPipe() (*msgFlow, *msgFlow) {
	a2b, b2a := make(chan []byte, 64), make(chan []byte, 64)
	da, db := make(chan struct{}), make(chan struct{})
	a := &msgFlow{in: b2a, out: a2b, done: da, peer: db, once: new(sync.Once)}
	b := &msgFlow{in: a2b, out: b2a, done: db, peer: da, once: new(sync.Once)}
	return a, b
}

func (f *msgFlow) Read(b []byte) (int, error) {
	select {
	case m := <-f.in:
		return copy(b, m), nil
	case <-f.done:
		return 0, io.EOF
	case <-f.peer:
		return 0, io.EOF
	}
}

func (f *msgFlow) Write(b []byte) (int, error) {
	select {
	case <-f.done:
		return 0, net.ErrClosed
	case <-f.peer:
		return 0, net.ErrClosed
	case f.out <- append([]byte(nil), b...):
		return len(b), nil
	}
}

func (f *msgFlow) Close() error      { f.once.Do(func() { close(f.done) }); return nil }
func (f *msgFlow) CloseWrite() error { return f.Close() }

// readMsg reads one message or fails after a timeout.
func readMsg(t *testing.T, f *msgFlow, d time.Duration) []byte {
	t.Helper()
	select {
	case m := <-f.in:
		return m
	case <-time.After(d):
		t.Fatal("no message")
		return nil
	}
}

// tcpPair returns two ends of a loopback TCP connection. A *net.TCPConn is a
// core.Flow, so one end serves as the flow handed to Deliver.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ln.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func listenTCP(t *testing.T, network, addr string) *net.TCPListener {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("listen %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.(*net.TCPListener)
}

func tcpMeta(src string, ln net.Listener) core.FlowMeta {
	return core.FlowMeta{
		Proto: core.ProtoTCP,
		Src:   netip.MustParseAddrPort(src),
		Dst:   ln.Addr().(*net.TCPAddr).AddrPort(),
	}
}

func runDeliver(ctx context.Context, meta core.FlowMeta, f core.Flow, opts Options) <-chan error {
	errc := make(chan error, 1)
	go func() { errc <- Deliver(ctx, meta, f, opts) }()
	return errc
}

func waitErr(t *testing.T, errc <-chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("Deliver did not return")
		return nil
	}
}

// TestTCPClientHalfClose: the requester sends data and half-closes; the
// server sees EOF, answers, and closes.
func TestTCPClientHalfClose(t *testing.T) {
	for _, tc := range []struct{ network, addr, src string }{
		{"tcp4", "127.0.0.1:0", "10.0.0.2:40000"},
		{"tcp6", "[::1]:0", "[fd00::2]:40000"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			ln := listenTCP(t, tc.network, tc.addr)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				n, _ := io.Copy(io.Discard, c)
				c.Write([]byte("n=" + itoa(n)))
			}()
			flow, peer := tcpPair(t)
			errc := runDeliver(context.Background(), tcpMeta(tc.src, ln), flow, Options{})

			payload := bytes.Repeat([]byte("0123456789abcdef"), 1<<14) // 256 KiB
			if _, err := peer.Write(payload); err != nil {
				t.Fatal(err)
			}
			peer.CloseWrite()
			peer.SetReadDeadline(time.Now().Add(10 * time.Second))
			got, err := io.ReadAll(peer)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "n="+itoa(int64(len(payload))) {
				t.Fatalf("got %q", got)
			}
			if err := waitErr(t, errc); err != nil {
				t.Fatalf("Deliver: %v", err)
			}
		})
	}
}

// TestTCPServerHalfClose: the server sends a banner and half-closes; the
// requester still sends afterwards.
func TestTCPServerHalfClose(t *testing.T) {
	ln := listenTCP(t, "tcp4", "127.0.0.1:0")
	gotc := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("banner"))
		c.(*net.TCPConn).CloseWrite()
		b, _ := io.ReadAll(c)
		gotc <- string(b)
	}()
	flow, peer := tcpPair(t)
	errc := runDeliver(context.Background(), tcpMeta("10.0.0.2:40000", ln), flow, Options{})

	peer.SetReadDeadline(time.Now().Add(10 * time.Second))
	banner, err := io.ReadAll(peer) // ends at the server's FIN
	if err != nil || string(banner) != "banner" {
		t.Fatalf("banner %q, %v", banner, err)
	}
	peer.Write([]byte("bye"))
	peer.CloseWrite()
	select {
	case s := <-gotc:
		if s != "bye" {
			t.Fatalf("server got %q", s)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server got nothing")
	}
	if err := waitErr(t, errc); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
}

func TestTCPDialRefused(t *testing.T) {
	ln := listenTCP(t, "tcp4", "127.0.0.1:0")
	meta := tcpMeta("10.0.0.2:40000", ln)
	ln.Close()
	flow, _ := msgPipe()
	if err := Deliver(context.Background(), meta, flow, Options{}); err == nil {
		t.Fatal("dial to closed port succeeded")
	}
	select {
	case <-flow.done:
	default:
		t.Fatal("flow not closed")
	}
}

// answerFlow records the answer Deliver gives.
type answerFlow struct {
	*msgFlow
	mu       sync.Mutex
	accepted bool
	refused  core.Reason
}

func (f *answerFlow) Accept() error {
	f.mu.Lock()
	f.accepted = true
	f.mu.Unlock()
	return nil
}

func (f *answerFlow) Refuse(r core.Reason) error {
	f.mu.Lock()
	f.refused = r
	f.mu.Unlock()
	return f.Close()
}

func (f *answerFlow) answer() (bool, core.Reason) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accepted, f.refused
}

func TestDeliverAnswers(t *testing.T) {
	// A closed port: refused with ReasonRefused.
	ln := listenTCP(t, "tcp4", "127.0.0.1:0")
	meta := tcpMeta("10.0.0.2:40000", ln)
	ln.Close()
	m, _ := msgPipe()
	f := &answerFlow{msgFlow: m}
	Deliver(context.Background(), meta, f, Options{})
	if acc, r := f.answer(); acc || r != core.ReasonRefused {
		t.Fatalf("closed port: accepted %v, refused %v", acc, r)
	}

	// An open port: accepted before any data.
	ln = listenTCP(t, "tcp4", "127.0.0.1:0")
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	m, _ = msgPipe()
	f = &answerFlow{msgFlow: m}
	Deliver(context.Background(), tcpMeta("10.0.0.2:40000", ln), f, Options{})
	if acc, r := f.answer(); !acc || r != 0 {
		t.Fatalf("open port: accepted %v, refused %v", acc, r)
	}

	for err, want := range map[error]core.Reason{
		syscall.ECONNREFUSED: core.ReasonRefused,
		&net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}: core.ReasonUnreachable,
		syscall.ENETUNREACH:      core.ReasonUnreachable,
		context.DeadlineExceeded: core.ReasonUnreachable,
		ErrPreserveNotPermitted:  core.ReasonError,
	} {
		if got := ReasonFor(err); got != want {
			t.Errorf("ReasonFor(%v) = %v, want %v", err, got, want)
		}
	}
}

func TestTCPContextCancel(t *testing.T) {
	ln := listenTCP(t, "tcp4", "127.0.0.1:0")
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(io.Discard, c)
		}
	}()
	flow, _ := tcpPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	errc := runDeliver(ctx, tcpMeta("10.0.0.2:1", ln), flow, Options{})
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := waitErr(t, errc); !errors.Is(err, context.Canceled) {
		t.Fatalf("Deliver: %v", err)
	}
}

func TestUDP(t *testing.T) {
	for _, tc := range []struct{ network, addr, src string }{
		{"udp4", "127.0.0.1:0", "10.0.0.2:5000"},
		{"udp6", "[::1]:0", "[fd00::2]:5000"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			pc, err := net.ListenPacket(tc.network, tc.addr)
			if err != nil {
				t.Skipf("listen: %v", err)
			}
			defer pc.Close()
			go func() {
				buf := make([]byte, 65535)
				for {
					n, from, err := pc.ReadFrom(buf)
					if err != nil {
						return
					}
					pc.WriteTo(append([]byte("re:"), buf[:n]...), from)
				}
			}()
			meta := core.FlowMeta{
				Proto: core.ProtoUDP,
				Src:   netip.MustParseAddrPort(tc.src),
				Dst:   pc.LocalAddr().(*net.UDPAddr).AddrPort(),
			}
			flow, peer := msgPipe()
			errc := runDeliver(context.Background(), meta, flow, Options{IdleTimeout: 300 * time.Millisecond})
			for _, m := range []string{"a", "bb", strings.Repeat("c", 1400)} {
				peer.Write([]byte(m))
				if got := readMsg(t, peer, 5*time.Second); string(got) != "re:"+m {
					t.Fatalf("got %q", got)
				}
			}
			// No traffic for the idle timeout ends the flow.
			start := time.Now()
			if err := waitErr(t, errc); err != nil {
				t.Fatalf("Deliver: %v", err)
			}
			if d := time.Since(start); d < 200*time.Millisecond {
				t.Fatalf("ended after %v", d)
			}
		})
	}
}

func TestUDPFlowClose(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	meta := core.FlowMeta{Proto: core.ProtoUDP, Src: netip.MustParseAddrPort("10.0.0.2:1"), Dst: pc.LocalAddr().(*net.UDPAddr).AddrPort()}
	flow, peer := msgPipe()
	errc := runDeliver(context.Background(), meta, flow, Options{})
	peer.Close()
	if err := waitErr(t, errc); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
}

func pingMeta(proto core.Proto, dst string, id uint16) core.FlowMeta {
	src := "10.0.0.2"
	if proto == core.ProtoICMPv6 {
		src = "fd00::2"
	}
	return core.FlowMeta{
		Proto: proto,
		Src:   netip.AddrPortFrom(netip.MustParseAddr(src), id),
		Dst:   netip.AddrPortFrom(netip.MustParseAddr(dst), 0),
	}
}

func echo(v6, reply bool, id, seq uint16, payload string) []byte {
	m := make([]byte, 8+len(payload))
	switch {
	case !v6 && !reply:
		m[0] = icmpv4EchoRequest
	case !v6:
		m[0] = icmpv4EchoReply
	case !reply:
		m[0] = icmpv6EchoRequest
	default:
		m[0] = icmpv6EchoReply
	}
	binary.BigEndian.PutUint16(m[4:], id)
	binary.BigEndian.PutUint16(m[6:], seq)
	copy(m[8:], payload)
	return m
}

func skipWithoutPing(t *testing.T, meta core.FlowMeta) {
	t.Helper()
	c, err := openPing(meta, Options{})
	if err != nil {
		t.Skipf("ping socket: %v", err)
	}
	c.Close()
}

func TestPing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		proto core.Proto
		dst   string
	}{
		{"v4", core.ProtoICMP, "127.0.0.1"},
		{"v6", core.ProtoICMPv6, "::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v6 := tc.proto == core.ProtoICMPv6
			const id = 0x1234 // the kernel picks another; Deliver maps it back
			meta := pingMeta(tc.proto, tc.dst, id)
			skipWithoutPing(t, meta)
			flow, peer := msgPipe()
			errc := runDeliver(context.Background(), meta, flow, Options{IdleTimeout: 300 * time.Millisecond})
			for seq := uint16(7); seq < 10; seq++ {
				peer.Write(echo(v6, false, id, seq, "payload-"+itoa(int64(seq))))
				got := readMsg(t, peer, 5*time.Second)
				want := echo(v6, true, id, seq, "payload-"+itoa(int64(seq)))
				if !bytes.Equal(got, want) {
					t.Fatalf("reply % x, want % x", got, want)
				}
			}
			// Non-echo messages are not sent.
			peer.Write([]byte{3, 1, 0, 0, 0, 0, 0, 0})
			select {
			case m := <-peer.in:
				t.Fatalf("unexpected message % x", m)
			case <-time.After(100 * time.Millisecond):
			}
			if err := waitErr(t, errc); err != nil {
				t.Fatalf("Deliver: %v", err)
			}
		})
	}
}

func TestPendingEcho(t *testing.T) {
	p := newPending(50 * time.Millisecond)
	p.add(1, 0xabcd)
	if id, ok := p.lookup(1); !ok || id != 0xabcd {
		t.Fatalf("lookup = %#x, %v", id, ok)
	}
	if _, ok := p.lookup(2); ok {
		t.Fatal("unknown sequence matched")
	}
	time.Sleep(60 * time.Millisecond)
	if _, ok := p.lookup(1); ok {
		t.Fatal("expired sequence matched")
	}
}

func TestPreserveSource(t *testing.T) {
	ln := listenTCP(t, "tcp4", "127.0.0.1:0")
	meta := tcpMeta("127.0.0.2:0", ln)
	if os.Geteuid() != 0 {
		_, err := DialTCP(context.Background(), meta, Options{Source: SourcePreserve})
		if !errors.Is(err, ErrPreserveNotPermitted) {
			t.Fatalf("DialTCP without privilege: %v", err)
		}
		t.Skip("preserve mode needs root")
	}
	seen := make(chan net.Addr, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			seen <- c.RemoteAddr()
			c.Close()
		}
	}()
	c, err := DialTCP(context.Background(), meta, Options{Source: SourcePreserve})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if a := (<-seen).(*net.TCPAddr); !a.IP.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("server saw %v", a)
	}
}

func TestPreserveFamilyMismatch(t *testing.T) {
	ln := listenTCP(t, "tcp4", "127.0.0.1:0")
	meta := tcpMeta("[fd00::2]:1", ln)
	if _, err := DialTCP(context.Background(), meta, Options{Source: SourcePreserve}); err == nil {
		t.Fatal("dial with mismatched families succeeded")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
