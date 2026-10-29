package link

import (
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xiongyumail/tunx/internal/core"
)

type testNode struct {
	name string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestNode(t *testing.T, name string) testNode {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return testNode{name: name, pub: pub, priv: priv}
}

func configFor(self testNode, peers ...testNode) Config {
	m := make(map[string]ed25519.PublicKey)
	for _, p := range peers {
		m[p.name] = p.pub
	}
	return Config{
		Network:          "testnet",
		Name:             self.name,
		PrivateKey:       self.priv,
		Peers:            m,
		HandshakeTimeout: 5 * time.Second,
	}
}

// testConfigs returns matching client and server configs.
func testConfigs(t *testing.T) (Config, Config) {
	c, s := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	return configFor(c, s), configFor(s, c)
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- nil
			return
		}
		ch <- c
	}()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c2 := <-ch
	if c2 == nil {
		t.Fatal("accept failed")
	}
	return c1, c2
}

// handshakeBoth runs Client on c1 and Server on c2 concurrently.
func handshakeBoth(cc, sc Config, c1, c2 net.Conn) (cs, ss *Session, cerr, serr error) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ss, serr = Server(context.Background(), c2, sc)
	}()
	cs, cerr = Client(context.Background(), c1, cc)
	wg.Wait()
	return
}

// sessionPair returns two connected sessions; each serves flows with the
// given handler when it is not nil.
func sessionPair(t *testing.T, cc, sc Config, c1, c2 net.Conn, ch, sh core.Handler) (*Session, *Session) {
	t.Helper()
	cs, ss, cerr, serr := handshakeBoth(cc, sc, c1, c2)
	if cerr != nil || serr != nil {
		t.Fatalf("handshake: client %v, server %v", cerr, serr)
	}
	t.Cleanup(func() { cs.Close(); ss.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if ch != nil {
		go cs.Serve(ctx, ch)
	}
	if sh != nil {
		go ss.Serve(ctx, sh)
	}
	return cs, ss
}

// echoHandler returns every message or byte it receives.
var echoHandler = core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
	defer f.Close()
	if meta.Proto.IsDatagram() {
		buf := make([]byte, MaxDatagram)
		for {
			n, err := f.Read(buf)
			if err != nil {
				return
			}
			if _, err := f.Write(buf[:n]); err != nil {
				return
			}
		}
	}
	io.Copy(f, f)
	f.CloseWrite()
})

// blackholeConn drops everything in both directions once enabled, without
// reporting errors, like a path that silently died.
type blackholeConn struct {
	net.Conn
	mu     sync.Mutex
	holed  bool
	closed chan struct{}
	once   sync.Once
}

func newBlackhole(c net.Conn) *blackholeConn {
	return &blackholeConn{Conn: c, closed: make(chan struct{})}
}

func (c *blackholeConn) enable() {
	c.mu.Lock()
	c.holed = true
	c.mu.Unlock()
}

func (c *blackholeConn) isHoled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.holed
}

func (c *blackholeConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(p)
		if !c.isHoled() {
			return n, err
		}
		if err != nil {
			<-c.closed
			return 0, net.ErrClosed
		}
	}
}

func (c *blackholeConn) Write(p []byte) (int, error) {
	if c.isHoled() {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *blackholeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func waitDone(t *testing.T, s *Session, d time.Duration) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(d):
		t.Fatalf("session with %s still up after %v", s.Peer(), d)
	}
}
