package link

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestHandshake(t *testing.T) {
	for _, kind := range []string{"pipe", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			cc, sc := testConfigs(t)
			cc.KeepaliveInterval = 20 * time.Millisecond
			sc.KeepaliveInterval = 20 * time.Millisecond
			var c1, c2 net.Conn
			if kind == "pipe" {
				c1, c2 = net.Pipe()
			} else {
				c1, c2 = tcpPair(t)
			}
			cs, ss := sessionPair(t, cc, sc, c1, c2, nil, nil)
			if cs.Peer() != "node-b" || ss.Peer() != "node-a" {
				t.Fatalf("peers: client sees %q, server sees %q", cs.Peer(), ss.Peer())
			}
			deadline := time.Now().Add(3 * time.Second)
			for cs.RTT() == 0 || ss.RTT() == 0 {
				if time.Now().After(deadline) {
					t.Fatal("no RTT measured")
				}
				time.Sleep(10 * time.Millisecond)
			}
			cs.Close()
			waitDone(t, ss, 3*time.Second)
			if !errors.Is(cs.Err(), ErrClosed) {
				t.Fatalf("client err %v", cs.Err())
			}
		})
	}
}

func TestHandshakeFailures(t *testing.T) {
	a, b, x := newTestNode(t, "node-a"), newTestNode(t, "node-b"), newTestNode(t, "node-x")
	wrongB := testNode{name: "node-b", pub: x.pub, priv: x.priv}
	cases := []struct {
		name       string
		cc, sc     Config
		cerr, serr error
	}{
		{"server has wrong client key", configFor(a, b), configFor(b, testNode{name: "node-a", pub: x.pub}), ErrRejected, ErrAuth},
		{"client has wrong server key", configFor(a, testNode{name: "node-b", pub: x.pub}), configFor(b, a), ErrAuth, nil},
		{"server impersonated", configFor(a, b), configFor(wrongB, a), ErrAuth, nil},
		{"unknown client", configFor(x, b), configFor(b, a), ErrRejected, ErrUnknownPeer},
		{"unknown server", configFor(a, x), configFor(b, a), ErrUnknownPeer, nil},
		{"network mismatch", func() Config { c := configFor(a, b); c.Network = "other"; return c }(), configFor(b, a), ErrRejected, ErrNetworkMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			cs, ss, cerr, serr := handshakeBoth(tc.cc, tc.sc, c1, c2)
			if cs != nil || ss != nil {
				t.Fatal("handshake succeeded")
			}
			if cerr == nil || serr == nil {
				t.Fatalf("expected both to fail: client %v, server %v", cerr, serr)
			}
			if tc.cerr != nil && !errors.Is(cerr, tc.cerr) {
				t.Errorf("client err %v, want %v", cerr, tc.cerr)
			}
			if tc.serr != nil && !errors.Is(serr, tc.serr) {
				t.Errorf("server err %v, want %v", serr, tc.serr)
			}
		})
	}
}

// recConn records what one side writes.
type recConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *recConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recConn) messages(t *testing.T, n int) [][]byte {
	t.Helper()
	c.mu.Lock()
	r := bytes.NewReader(c.buf.Bytes())
	c.mu.Unlock()
	var out [][]byte
	for range n {
		m, err := readMsg(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func TestHandshakeReplay(t *testing.T) {
	cc, sc := testConfigs(t)
	p1, p2 := net.Pipe()
	rc, rs := &recConn{Conn: p1}, &recConn{Conn: p2}
	cs, ss, cerr, serr := handshakeBoth(cc, sc, rc, rs)
	if cerr != nil || serr != nil {
		t.Fatalf("handshake: %v, %v", cerr, serr)
	}
	cs.Close()
	ss.Close()
	clientMsgs := rc.messages(t, 2) // ClientHello, ClientFinish
	serverMsgs := rs.messages(t, 2) // ServerHello, Accept

	t.Run("client messages to new server", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		errc := make(chan error, 1)
		go func() {
			_, err := Server(context.Background(), b, sc)
			errc <- err
		}()
		if err := writeMsg(a, clientMsgs[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := readMsg(a); err != nil {
			t.Fatal(err)
		}
		writeMsg(a, clientMsgs[1])
		if err := <-errc; !errors.Is(err, ErrAuth) {
			t.Fatalf("server accepted replay: %v", err)
		}
	})

	t.Run("server messages to new client", func(t *testing.T) {
		a, b := net.Pipe()
		defer b.Close()
		errc := make(chan error, 1)
		go func() {
			_, err := Client(context.Background(), a, cc)
			errc <- err
		}()
		if _, err := readMsg(b); err != nil {
			t.Fatal(err)
		}
		writeMsg(b, serverMsgs[0])
		go io.Copy(io.Discard, b)
		writeMsg(b, serverMsgs[1])
		if err := <-errc; !errors.Is(err, ErrAuth) {
			t.Fatalf("client accepted replay: %v", err)
		}
	})
}

// flipWriter flips bits of the byte at offset at in the stream written
// through it.
type flipWriter struct {
	w    io.Writer
	off  int
	at   int
	mask byte
}

func (f *flipWriter) Write(p []byte) (int, error) {
	q := append([]byte(nil), p...)
	if i := f.at - f.off; i >= 0 && i < len(q) {
		q[i] ^= f.mask
	}
	f.off += len(p)
	return f.w.Write(q)
}

func TestHandshakeTampered(t *testing.T) {
	cc, sc := testConfigs(t)
	// ClientHello on the wire: len(2) magic(4) version(1) netlen(1) net
	// namelen(1) name nonce(32) extlen(2).
	chName := 8 + len(cc.Network) + 1
	chNonce := chName + len(cc.Name)
	// ServerHello: len(2) magic(4) version(1) namelen(1) name nonce(32) extlen(2) sig(64).
	shNonce := 8 + len(sc.Name)
	cases := []struct {
		name  string
		toSrv bool
		at    int
		mask  byte
	}{
		{"client version", true, 6, 0x02},
		{"client network", true, 8, 0x01},
		{"client name", true, chName, 0x01},
		{"client nonce", true, chNonce + 5, 0x80},
		{"client signature", true, chNonce + 34 + 2 + 10, 0x01},
		{"server version", false, 6, 0x02},
		{"server name", false, 8, 0x01},
		{"server nonce", false, shNonce, 0x01},
		{"server signature", false, shNonce + 34 + 3, 0x01},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c1, m1 := net.Pipe()
			m2, c2 := net.Pipe()
			relay := func(dst, src net.Conn, flip bool) {
				var w io.Writer = dst
				if flip {
					w = &flipWriter{w: dst, at: tc.at, mask: tc.mask}
				}
				io.Copy(w, src)
				dst.Close()
				src.Close()
			}
			go relay(m2, m1, tc.toSrv)
			go relay(m1, m2, !tc.toSrv)
			cs, ss, cerr, serr := handshakeBoth(cc, sc, c1, c2)
			if cs != nil {
				cs.Close()
			}
			if ss != nil {
				ss.Close()
			}
			if cerr == nil || serr == nil {
				t.Fatalf("tampered handshake not rejected: client %v, server %v", cerr, serr)
			}
		})
	}
}

func TestHandshakeTimeout(t *testing.T) {
	cc, _ := testConfigs(t)
	cc.HandshakeTimeout = 100 * time.Millisecond
	c1, c2 := net.Pipe()
	defer c2.Close()
	go io.Copy(io.Discard, c2)
	start := time.Now()
	if _, err := Client(context.Background(), c1, cc); err == nil {
		t.Fatal("handshake with silent peer succeeded")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("timeout took %v", d)
	}

	// Cancellation also ends the handshake.
	c3, c4 := net.Pipe()
	defer c4.Close()
	go io.Copy(io.Discard, c4)
	cc.HandshakeTimeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := Client(ctx, c3, cc); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled handshake: %v", err)
	}
}
