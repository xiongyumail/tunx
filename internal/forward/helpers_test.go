package forward

import (
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiongyumail/tunx/internal/config"
	"github.com/xiongyumail/tunx/internal/core"
	"github.com/xiongyumail/tunx/internal/egress"
)

// Test topology helpers. Every node listens on loopback; destinations are
// loopback servers on 127.0.x.y addresses, which routes map to nodes.

type keyring map[string]ed25519.PrivateKey

func newKeys(t *testing.T, names ...string) keyring {
	k := make(keyring)
	for _, n := range names {
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		k[n] = priv
	}
	return k
}

func (k keyring) pub(name string) config.PublicKey {
	return config.PublicKey(k[name].Public().(ed25519.PublicKey))
}

const (
	testKeepaliveInterval = 100 * time.Millisecond
	testKeepaliveTimeout  = 600 * time.Millisecond
)

// baseConfig returns a node that listens on loopback and allows everything.
func baseConfig(k keyring, name string) *config.Config {
	c := &config.Config{
		Node:    name,
		Network: "testnet",
		Listen:  []config.Listener{{Address: "127.0.0.1:0"}},
		Status:  "127.0.0.1:0",
		Policy:  []config.Rule{{Action: "allow"}},
		Link: config.LinkTimers{
			HandshakeTimeout:  config.Duration(2 * time.Second),
			KeepaliveInterval: config.Duration(testKeepaliveInterval),
			KeepaliveTimeout:  config.Duration(testKeepaliveTimeout),
		},
	}
	c.SetKey(k[name])
	return c
}

func peer(k keyring, name, dial string, relayFor ...string) config.Peer {
	return config.Peer{Name: name, PublicKey: k.pub(name), Dial: dial, RelayFor: relayFor}
}

func localRoute(prefix, self string) config.Route {
	return config.Route{Prefix: netip.MustParsePrefix(prefix), Advertisers: []config.Advertiser{{Node: self}}}
}

func remoteRoute(prefix string, ads ...config.Advertiser) config.Route {
	return config.Route{Prefix: netip.MustParsePrefix(prefix), Advertisers: ads}
}

// delivery records a flow delivered by a node.
type delivery struct {
	node string
	meta core.FlowMeta
}

// recorder collects deliveries from all nodes of a test.
type recorder struct {
	mu   sync.Mutex
	list []delivery
	ch   chan delivery
}

func newRecorder() *recorder { return &recorder{ch: make(chan delivery, 64)} }

func (r *recorder) deliverFor(node string) DeliverFunc {
	return func(ctx context.Context, meta core.FlowMeta, f core.Flow, opts egress.Options) error {
		r.mu.Lock()
		r.list = append(r.list, delivery{node, meta})
		r.mu.Unlock()
		select {
		case r.ch <- delivery{node, meta}:
		default:
		}
		opts.IdleTimeout = 2 * time.Second
		opts.EchoTimeout = 2 * time.Second
		meta.Dst = netip.AddrPortFrom(toLoopback(meta.Dst.Addr()), meta.Dst.Port())
		return egress.Deliver(ctx, meta, f, opts)
	}
}

// toLoopback maps 198.18.x.y to 127.0.x.y. gVisor drops packets to
// loopback addresses, so flows captured from a TUN use 198.18.0.0/16 and
// the delivering node maps them to loopback servers.
func toLoopback(a netip.Addr) netip.Addr {
	if a.Is4() {
		b := a.As4()
		if b[0] == 198 && b[1] == 18 {
			return netip.AddrFrom4([4]byte{127, 0, b[2], b[3]})
		}
	}
	return a
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.list)
}

func (r *recorder) next(t *testing.T) delivery {
	t.Helper()
	select {
	case d := <-r.ch:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("no delivery")
	}
	return delivery{}
}

func startNode(t *testing.T, cfg *config.Config, rec *recorder, opts Options) *Node {
	t.Helper()
	if err := cfg.Validate(""); err != nil {
		t.Fatalf("config %s: %v", cfg.Node, err)
	}
	if rec != nil {
		opts.Deliver = rec.deliverFor(cfg.Node)
	}
	n, err := Start(cfg, opts)
	if err != nil {
		t.Fatalf("start %s: %v", cfg.Node, err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func addr(n *Node) string { return n.ListenAddrs()[0].String() }

func waitUp(t *testing.T, n *Node, peers ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for _, p := range peers {
		for !n.Sessions().Up(p) {
			if time.Now().After(deadline) {
				t.Fatalf("%s: no session to %s", n.cfg.Node, p)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// tcpPair returns two connected loopback TCP connections.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	c1, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c2 := <-ch
	if c2 == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { c1.Close(); c2.Close() })
	return c1.(*net.TCPConn), c2.(*net.TCPConn)
}

// injectTCP hands one end of a TCP pair to n as a flow captured from the TUN
// toward dst and returns the client end.
func injectTCP(t *testing.T, n *Node, dst netip.AddrPort) *net.TCPConn {
	t.Helper()
	client, flow := tcpPair(t)
	meta := core.FlowMeta{Proto: core.ProtoTCP, Src: netip.MustParseAddrPort("10.9.0.5:40000"), Dst: dst}
	go n.Forwarder().HandleFlow(context.Background(), meta, flow, core.Ingress{Kind: "tun"})
	return client
}

// countServer accepts TCP connections on ip, reads until EOF and answers
// "n=<bytes read>", then closes. accepted counts connections.
type countServer struct {
	ln       net.Listener
	accepted atomic.Int64
}

func newCountServer(t *testing.T, ip string) *countServer {
	t.Helper()
	ln, err := net.Listen("tcp4", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	s := &countServer{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			go func() {
				defer c.Close()
				n, _ := io.Copy(io.Discard, c)
				c.Write([]byte("n=" + strconv.FormatInt(n, 10)))
			}()
		}
	}()
	return s
}

func (s *countServer) addr() netip.AddrPort { return s.ln.Addr().(*net.TCPAddr).AddrPort() }

// tcpExchange sends payload, half-closes, and returns the reply.
func tcpExchange(t *testing.T, c *net.TCPConn, payload []byte) string {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		_, err := c.Write(payload)
		if err == nil {
			err = c.CloseWrite()
		}
		errc <- err
	}()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write: %v", err)
	}
	return string(got)
}

// expectClosedNoData checks that c ends without delivering any byte.
func expectClosedNoData(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	if len(b) > 0 {
		t.Fatalf("got %q from a refused flow", b)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("refused flow was not closed")
	}
}

// udpEcho answers every datagram with "re:" + payload.
func udpEcho(t *testing.T, ip string) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
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
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// msgPipe is an in-memory datagram flow pair. Closing either end closes
// both, like a datagram flow.
type msgPipe struct {
	done chan struct{}
	once sync.Once
}

type msgEnd struct {
	p       *msgPipe
	in, out chan []byte
}

func newMsgPipe() (*msgEnd, *msgEnd) {
	p := &msgPipe{done: make(chan struct{})}
	a2b, b2a := make(chan []byte, 64), make(chan []byte, 64)
	return &msgEnd{p, b2a, a2b}, &msgEnd{p, a2b, b2a}
}

func (e *msgEnd) Read(b []byte) (int, error) {
	select {
	case m := <-e.in:
		return copy(b, m), nil
	case <-e.p.done:
		return 0, io.EOF
	}
}

func (e *msgEnd) Write(b []byte) (int, error) {
	select {
	case e.out <- append([]byte(nil), b...):
		return len(b), nil
	case <-e.p.done:
		return 0, io.ErrClosedPipe
	}
}

func (e *msgEnd) Close() error      { e.p.once.Do(func() { close(e.p.done) }); return nil }
func (e *msgEnd) CloseWrite() error { return e.Close() }

func (e *msgEnd) recv(t *testing.T, d time.Duration) ([]byte, bool) {
	t.Helper()
	select {
	case m := <-e.in:
		return m, true
	case <-e.p.done:
		return nil, false
	case <-time.After(d):
		return nil, false
	}
}

// injectDatagram hands a datagram flow to n as captured from the TUN and
// returns the client end.
func injectDatagram(n *Node, proto core.Proto, src, dst netip.AddrPort) *msgEnd {
	client, flow := newMsgPipe()
	meta := core.FlowMeta{Proto: proto, Src: src, Dst: dst}
	go n.Forwarder().HandleFlow(context.Background(), meta, flow, core.Ingress{Kind: "tun"})
	return client
}
