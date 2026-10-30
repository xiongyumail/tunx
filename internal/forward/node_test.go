package forward

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiongyumail/tunx/internal/config"
	"github.com/xiongyumail/tunx/internal/core"
	"github.com/xiongyumail/tunx/internal/egress"
	"github.com/xiongyumail/tunx/internal/link"
	"golang.org/x/sys/unix"
)

// twoNodes starts b (listening, delivers 127.0.1.0/24) and a (dials b,
// routes 127.0.1.0/24 to b and delivers 127.0.2.0/24 itself).
func twoNodes(t *testing.T, rec *recorder, mod func(a, b *config.Config)) (*Node, *Node) {
	k := newKeys(t, "a", "b")
	bc := baseConfig(k, "b")
	bc.Peers = []config.Peer{peer(k, "a", "")}
	bc.Routes = []config.Route{
		localRoute("127.0.1.0/24", "b"),
		remoteRoute("127.0.2.0/24", config.Advertiser{Node: "a"}),
	}
	ac := baseConfig(k, "a")
	ac.Listen = nil
	ac.Routes = []config.Route{
		remoteRoute("127.0.1.0/24", config.Advertiser{Node: "b"}),
		localRoute("127.0.2.0/24", "a"),
	}
	if mod != nil {
		mod(ac, bc)
	}
	b := startNode(t, bc, rec, Options{})
	ac.Peers = []config.Peer{peer(k, "b", addr(b))}
	a := startNode(t, ac, rec, Options{})
	waitUp(t, a, "b")
	waitUp(t, b, "a")
	return a, b
}

func TestTCPAcrossLink(t *testing.T) {
	rec := newRecorder()
	a, b := twoNodes(t, rec, nil)
	srv := newCountServer(t, "127.0.1.1")

	payload := bytes.Repeat([]byte("tunx"), 1<<18) // 1 MiB
	c := injectTCP(t, a, srv.addr())
	if got, want := tcpExchange(t, c, payload), "n="+strconv.Itoa(len(payload)); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	d := rec.next(t)
	if d.node != "b" || d.meta.Identity != "a" || d.meta.Hops != 1 || d.meta.Src != netip.MustParseAddrPort("10.9.0.5:40000") {
		t.Fatalf("delivered %+v", d)
	}

	st := a.Status()
	if id := st.Stats.Identities["a"]; id.TxBytes != uint64(len(payload)) || id.RxBytes == 0 || id.Flows != 1 {
		t.Fatalf("identity counters %+v", id)
	}
	if p := st.Stats.Peers["b"]; p.TxBytes != uint64(len(payload)) {
		t.Fatalf("peer counters on a %+v", p)
	}
	if p := b.Status().Stats.Peers["a"]; p.RxBytes != uint64(len(payload)) {
		t.Fatalf("peer counters on b %+v", p)
	}
}

func TestReloadRoutesAndRejectStaticChange(t *testing.T) {
	k := newKeys(t, "a")
	cfg := baseConfig(k, "a")
	cfg.Routes = []config.Route{localRoute("127.0.1.0/24", "a")}
	n := startNode(t, cfg, newRecorder(), Options{})

	next := *cfg
	next.Routes = []config.Route{localRoute("127.0.2.0/24", "a")}
	next.Policy = []config.Rule{{Action: "allow", Dst: []netip.Prefix{netip.MustParsePrefix("127.0.2.0/24")}}}
	if err := n.Reload(&next); err != nil {
		t.Fatal(err)
	}
	if n.Router().Table().Lookup(netip.MustParseAddr("127.0.1.1")) != nil || n.Router().Table().Lookup(netip.MustParseAddr("127.0.2.1")) == nil {
		t.Fatal("route table was not replaced")
	}

	restart := next
	restart.Listen = []config.Listener{{Address: "127.0.0.1:1"}}
	if !errors.Is(n.Reload(&restart), ErrRestartRequired) {
		t.Fatal("listener change did not require restart")
	}
}

func TestClientSOCKSConnect(t *testing.T) {
	k := newKeys(t, "edge")
	cfg := baseConfig(k, "edge")
	cfg.ClientSOCKS = &config.ClientSOCKS{
		Listen: "127.0.0.1:0",
		Users:  []config.SOCKSUser{{Name: "phone", Password: "secret"}},
	}
	cfg.Routes = []config.Route{localRoute("127.0.1.0/24", "edge")}
	rec := newRecorder()
	n := startNode(t, cfg, rec, Options{})
	srv := newCountServer(t, "127.0.1.1")

	c, err := net.DialTCP("tcp4", nil, n.ClientAddr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:2]); err != nil || !bytes.Equal(reply[:2], []byte{5, 2}) {
		t.Fatalf("method reply % x, %v", reply[:2], err)
	}
	auth := append([]byte{1, 5}, []byte("phone")...)
	auth = append(auth, 6)
	auth = append(auth, []byte("secret")...)
	if _, err := c.Write(auth); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, reply[:2]); err != nil || !bytes.Equal(reply[:2], []byte{1, 0}) {
		t.Fatalf("auth reply % x, %v", reply[:2], err)
	}
	dst := srv.addr()
	ip := dst.Addr().As4()
	req := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(dst.Port() >> 8), byte(dst.Port())}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, reply[:]); err != nil || reply[1] != 0 {
		t.Fatalf("connect reply % x, %v", reply, err)
	}
	if got := tcpExchange(t, c, []byte("hello")); got != "n=5" {
		t.Fatalf("got %q", got)
	}
	if d := rec.next(t); d.meta.Identity != "phone" || d.meta.Dst != dst || d.meta.Hops != 0 {
		t.Fatalf("delivered %+v", d)
	}
}

func TestUDPAcrossLink(t *testing.T) {
	rec := newRecorder()
	a, _ := twoNodes(t, rec, nil)
	dst := udpEcho(t, "127.0.1.1")
	c := injectDatagram(a, core.ProtoUDP, netip.MustParseAddrPort("10.9.0.5:5353"), dst)
	defer c.Close()
	for _, m := range []string{"one", "", "three"} {
		c.Write([]byte(m))
		got, ok := c.recv(t, 5*time.Second)
		if !ok || string(got) != "re:"+m {
			t.Fatalf("sent %q, got %q (ok %v)", m, got, ok)
		}
	}
	if d := rec.next(t); d.node != "b" || d.meta.Proto != core.ProtoUDP {
		t.Fatalf("delivered %+v", d)
	}
}

func TestPingAcrossLink(t *testing.T) {
	if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP); err != nil {
		t.Skip("ping sockets not permitted")
	} else {
		unix.Close(fd)
	}
	rec := newRecorder()
	a, _ := twoNodes(t, rec, nil)
	const id = 0x4242
	c := injectDatagram(a, core.ProtoICMP, netip.AddrPortFrom(netip.MustParseAddr("10.9.0.5"), id), netip.MustParseAddrPort("127.0.1.1:0"))
	defer c.Close()
	for seq := uint16(1); seq <= 3; seq++ {
		req := []byte{8, 0, 0, 0, 0, 0, 0, 0, 'p', 'i', 'n', 'g'}
		binary.BigEndian.PutUint16(req[4:], id)
		binary.BigEndian.PutUint16(req[6:], seq)
		c.Write(req)
		got, ok := c.recv(t, 5*time.Second)
		if !ok || len(got) < 8 || got[0] != 0 || binary.BigEndian.Uint16(got[4:]) != id || binary.BigEndian.Uint16(got[6:]) != seq || string(got[8:]) != "ping" {
			t.Fatalf("seq %d: reply % x (ok %v)", seq, got, ok)
		}
	}
}

// B reaches A's prefix over the session A dialed.
func TestReverseDirection(t *testing.T) {
	rec := newRecorder()
	a, b := twoNodes(t, rec, nil)
	srv := newCountServer(t, "127.0.2.1")
	c := injectTCP(t, b, srv.addr())
	if got := tcpExchange(t, c, []byte("hello")); got != "n=5" {
		t.Fatalf("got %q", got)
	}
	if d := rec.next(t); d.node != "a" || d.meta.Identity != "b" || d.meta.Hops != 1 {
		t.Fatalf("delivered %+v", d)
	}
	if n := len(a.Sessions().Snapshot()); n != 1 {
		t.Fatalf("a has %d sessions, want the single dialed one", n)
	}
}

// A reaches C through B: A only knows C via B.
func TestMultiHop(t *testing.T) {
	k := newKeys(t, "a", "b", "c")
	rec := newRecorder()

	bc := baseConfig(k, "b")
	bc.Peers = []config.Peer{peer(k, "a", ""), peer(k, "c", "")}
	bc.Routes = []config.Route{remoteRoute("127.0.3.0/24", config.Advertiser{Node: "c"})}
	// B relays but delivers nothing: its policy denies all, which must not
	// matter for relayed flows.
	bc.Policy = nil
	b := startNode(t, bc, rec, Options{})

	cc := baseConfig(k, "c")
	cc.Listen = nil
	cc.Peers = []config.Peer{peer(k, "b", addr(b), "a")}
	cc.Routes = []config.Route{localRoute("127.0.3.0/24", "c")}
	c := startNode(t, cc, rec, Options{})

	ac := baseConfig(k, "a")
	ac.Listen = nil
	ac.Peers = []config.Peer{peer(k, "b", addr(b))}
	ac.Routes = []config.Route{remoteRoute("127.0.3.0/24", config.Advertiser{Node: "c", Via: []string{"b"}})}
	a := startNode(t, ac, rec, Options{})
	waitUp(t, a, "b")
	waitUp(t, b, "a", "c")
	waitUp(t, c, "b")

	srv := newCountServer(t, "127.0.3.1")
	conn := injectTCP(t, a, srv.addr())
	if got := tcpExchange(t, conn, []byte("multi-hop")); got != "n=9" {
		t.Fatalf("got %q", got)
	}
	d := rec.next(t)
	if d.node != "c" || d.meta.Identity != "a" || d.meta.Hops != 2 {
		t.Fatalf("delivered %+v", d)
	}
	if sel := a.Status().Routes[0].Selected; sel != "peer:b" {
		t.Fatalf("a selects %q", sel)
	}
	if p := b.Status().Stats.Peers; p["a"].RxBytes != 9 || p["c"].TxBytes != 9 {
		t.Fatalf("b peer counters %+v", p)
	}
	_ = c
}

func TestPolicyDeny(t *testing.T) {
	rec := newRecorder()
	a, b := twoNodes(t, rec, func(a, b *config.Config) {
		// The delivering node denies one host; the ingress node denies UDP.
		b.Policy = []config.Rule{
			{Action: "deny", Identity: []string{"a"}, Dst: []netip.Prefix{netip.MustParsePrefix("127.0.1.2/32")}},
			{Action: "allow"},
		}
		a.Policy = []config.Rule{
			{Action: "deny", Proto: []string{"udp"}},
			{Action: "allow", Identity: []string{"a"}},
		}
	})
	denied := newCountServer(t, "127.0.1.2")
	c := injectTCP(t, a, denied.addr())
	c.Write([]byte("should not arrive"))
	expectClosedNoData(t, c)
	if n := denied.accepted.Load(); n != 0 {
		t.Fatalf("denied server saw %d connections", n)
	}
	if n := b.Forwarder().Stats().Drops(DropDenied); n != 1 {
		t.Fatalf("b denied %d flows", n)
	}

	u := injectDatagram(a, core.ProtoUDP, netip.MustParseAddrPort("10.9.0.5:5353"), udpEcho(t, "127.0.1.1"))
	u.Write([]byte("x"))
	if m, ok := u.recv(t, 500*time.Millisecond); ok {
		t.Fatalf("denied UDP got %q", m)
	}
	if n := a.Forwarder().Stats().Drops(DropDenied); n != 1 {
		t.Fatalf("a denied %d flows", n)
	}

	allowed := newCountServer(t, "127.0.1.1")
	if got := tcpExchange(t, injectTCP(t, a, allowed.addr()), []byte("ok")); got != "n=2" {
		t.Fatalf("allowed flow got %q", got)
	}
	if rec.count() != 1 {
		t.Fatalf("%d deliveries, want 1", rec.count())
	}
}

func TestNoRoute(t *testing.T) {
	rec := newRecorder()
	a, _ := twoNodes(t, rec, nil)
	srv := newCountServer(t, "127.0.9.1")
	expectClosedNoData(t, injectTCP(t, a, srv.addr()))
	if a.Forwarder().Stats().Drops(DropNoRoute) != 1 || rec.count() != 0 || srv.accepted.Load() != 0 {
		t.Fatal("unroutable flow was not dropped")
	}
}

// A peer may only send flows for identities it is allowed to carry.
func TestIdentitySpoof(t *testing.T) {
	k := newKeys(t, "a", "b")
	rec := newRecorder()
	bc := baseConfig(k, "b")
	bc.Peers = []config.Peer{peer(k, "a", "")}
	bc.Routes = []config.Route{localRoute("127.0.1.0/24", "b")}
	b := startNode(t, bc, rec, Options{})
	srv := newCountServer(t, "127.0.1.1")

	// Speak as node a with a raw link session.
	conn, err := net.Dial("tcp", addr(b))
	if err != nil {
		t.Fatal(err)
	}
	s, err := link.Client(context.Background(), conn, link.Config{
		Network: "testnet", Name: "a", PrivateKey: k["a"],
		Peers: map[string]ed25519.PublicKey{"b": ed25519.PublicKey(k.pub("b"))},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for _, tc := range []struct {
		identity string
		hops     uint8
		reason   string
	}{
		{"c", 1, DropSpoofed},    // a may not relay for c
		{"b", 1, DropSpoofed},    // nobody speaks for b to b
		{"", 1, DropSpoofed},     // no identity
		{"a", 200, DropHopLimit}, // beyond the hop limit
	} {
		f, err := s.OpenFlow(context.Background(), core.FlowMeta{
			Proto: core.ProtoTCP, Src: netip.MustParseAddrPort("10.9.0.5:1"), Dst: srv.addr(),
			Identity: tc.identity, Hops: tc.hops,
		})
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte("spoof"))
		f.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(time.Now().Add(5 * time.Second))
		// A refused flow is closed without the end marker: a reset.
		if got, _ := io.ReadAll(f); len(got) > 0 {
			t.Fatalf("identity %q: got %q", tc.identity, got)
		}
		f.Close()
	}
	st := b.Forwarder().Stats()
	if st.Drops(DropSpoofed) != 3 || st.Drops(DropHopLimit) != 1 {
		t.Fatalf("drops %+v", st.Snapshot().Drops)
	}
	if rec.count() != 0 || srv.accepted.Load() != 0 {
		t.Fatal("spoofed flow was delivered")
	}

	// The genuine identity passes.
	f, err := s.OpenFlow(context.Background(), core.FlowMeta{
		Proto: core.ProtoTCP, Src: netip.MustParseAddrPort("10.9.0.5:1"), Dst: srv.addr(), Identity: "a", Hops: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("real"))
	f.CloseWrite()
	got, _ := io.ReadAll(f)
	if string(got) != "n=4" {
		t.Fatalf("genuine flow got %q", got)
	}
}

// cutProxy forwards TCP to target until cut, then silently drops everything
// in both directions, like a path that died without resets.
type cutProxy struct {
	ln  net.Listener
	cut atomic.Bool
	mu  sync.Mutex
	all []net.Conn
}

func newCutProxy(t *testing.T, target string) *cutProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &cutProxy{ln: ln}
	t.Cleanup(func() {
		ln.Close()
		p.mu.Lock()
		for _, c := range p.all {
			c.Close()
		}
		p.mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			p.mu.Lock()
			p.all = append(p.all, c, u)
			p.mu.Unlock()
			go p.pipe(c, u)
			go p.pipe(u, c)
		}
	}()
	return p
}

func (p *cutProxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if err != nil {
			dst.Close()
			return
		}
		if p.cut.Load() {
			continue
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			src.Close()
			return
		}
	}
}

// A prefix advertised by B (priority 1) and C (priority 2) moves to C when
// the path to B dies silently, within the keepalive timeout.
func TestAdvertiserFailover(t *testing.T) {
	k := newKeys(t, "a", "b", "c")
	rec := newRecorder()
	mk := func(name string) *Node {
		cfg := baseConfig(k, name)
		cfg.Peers = []config.Peer{peer(k, "a", "")}
		cfg.Routes = []config.Route{localRoute("127.0.4.0/24", name)}
		return startNode(t, cfg, rec, Options{})
	}
	b, c := mk("b"), mk("c")
	proxy := newCutProxy(t, addr(b))

	ac := baseConfig(k, "a")
	ac.Listen = nil
	ac.Peers = []config.Peer{peer(k, "b", proxy.ln.Addr().String()), peer(k, "c", addr(c))}
	ac.Routes = []config.Route{remoteRoute("127.0.4.0/24",
		config.Advertiser{Node: "c", Priority: 2},
		config.Advertiser{Node: "b", Priority: 1},
	)}
	a := startNode(t, ac, rec, Options{})
	waitUp(t, a, "b", "c")
	srv := newCountServer(t, "127.0.4.1")

	if got := tcpExchange(t, injectTCP(t, a, srv.addr()), []byte("1")); got != "n=1" {
		t.Fatalf("got %q", got)
	}
	if d := rec.next(t); d.node != "b" {
		t.Fatalf("delivered by %s, want b", d.node)
	}

	proxy.cut.Store(true)
	start := time.Now()
	for a.Sessions().Up("b") {
		if time.Since(start) > testKeepaliveTimeout+2*time.Second {
			t.Fatal("session to b still up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	took := time.Since(start)
	t.Logf("session to b dropped after %v", took)
	if took > testKeepaliveTimeout+testKeepaliveTimeout/2 {
		t.Fatalf("failover took %v, keepalive timeout %v", took, testKeepaliveTimeout)
	}
	if sel := a.Status().Routes[0].Selected; sel != "peer:c" {
		t.Fatalf("route selects %q", sel)
	}
	if got := tcpExchange(t, injectTCP(t, a, srv.addr()), []byte("22")); got != "n=2" {
		t.Fatalf("got %q", got)
	}
	if d := rec.next(t); d.node != "c" {
		t.Fatalf("delivered by %s, want c", d.node)
	}
}

// A routing loop B→C→D→B is cut by the hop limit, and only by it.
func TestHopLimitLoop(t *testing.T) {
	names := []string{"a", "b", "c", "d"}
	k := newKeys(t, names...)
	rec := newRecorder()
	cfgs := make(map[string]*config.Config)
	for _, n := range names {
		cfg := baseConfig(k, n)
		cfg.HopLimit = 4
		for _, p := range names {
			if p != n {
				cfg.Peers = append(cfg.Peers, peer(k, p, "", "*"))
			}
		}
		cfgs[n] = cfg
	}
	next := map[string]string{"a": "b", "b": "c", "c": "d", "d": "b"}
	for n, cfg := range cfgs {
		cfg.Routes = []config.Route{remoteRoute("127.0.5.0/24", config.Advertiser{Node: next[n]})}
	}
	// Links: a-b, b-c, c-d, d-b; the second name dials the first.
	nodes := make(map[string]*Node)
	nodes["b"] = startNode(t, cfgs["b"], rec, Options{})
	setDial := func(from, to string) {
		for i := range cfgs[from].Peers {
			if cfgs[from].Peers[i].Name == to {
				cfgs[from].Peers[i].Dial = addr(nodes[to])
			}
		}
	}
	setDial("a", "b")
	setDial("c", "b")
	nodes["c"] = startNode(t, cfgs["c"], rec, Options{})
	setDial("d", "c")
	setDial("d", "b")
	nodes["d"] = startNode(t, cfgs["d"], rec, Options{})
	nodes["a"] = startNode(t, cfgs["a"], rec, Options{})
	waitUp(t, nodes["a"], "b")
	waitUp(t, nodes["b"], "a", "c", "d")
	waitUp(t, nodes["c"], "b", "d")
	waitUp(t, nodes["d"], "b", "c")

	srv := newCountServer(t, "127.0.5.1")
	expectClosedNoData(t, injectTCP(t, nodes["a"], srv.addr()))
	deadline := time.Now().Add(5 * time.Second)
	for nodes["b"].Forwarder().Stats().Drops(DropHopLimit) == 0 {
		if time.Now().After(deadline) {
			for _, n := range names {
				t.Logf("%s drops %+v", n, nodes[n].Forwarder().Stats().Snapshot().Drops)
			}
			t.Fatal("no hop limit drop at b")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// a→b (1), b→c (2), c→d (3), d→b (4); b would need hop 5.
	for _, n := range names {
		st := nodes[n].Forwarder().Stats()
		if st.Drops(DropSpoofed) != 0 || st.Drops(DropNoRoute) != 0 {
			t.Fatalf("%s drops %+v", n, st.Snapshot().Drops)
		}
	}
	if rec.count() != 0 || srv.accepted.Load() != 0 {
		t.Fatal("looping flow was delivered")
	}
}

func TestStatusEndpoint(t *testing.T) {
	a, _ := twoNodes(t, newRecorder(), nil)
	resp, err := http.Get("http://" + a.StatusAddr().String() + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Node != "a" || len(st.Sessions) != 1 || st.Sessions[0].Peer != "b" || !st.Sessions[0].Dialed {
		t.Fatalf("status %+v", st)
	}
	sel := map[string]string{}
	for _, r := range st.Routes {
		sel[r.Prefix] = r.Selected
	}
	if sel["127.0.1.0/24"] != "peer:b" || sel["127.0.2.0/24"] != "local" {
		t.Fatalf("routes %+v", st.Routes)
	}
}

// An established preferred session may lead to a broken downstream route.
// Route-dependent answers can use the alternate; terminal answers cannot.
func TestDownstreamRefusalFallback(t *testing.T) {
	for _, reason := range []core.Reason{core.ReasonNoRoute, core.ReasonUnreachable, core.ReasonHopLimit, core.ReasonDenied, core.ReasonRefused, core.ReasonError} {
		t.Run(reason.String(), func(t *testing.T) {
			k := newKeys(t, "a", "b", "c", "d")
			rec := newRecorder()
			bc := baseConfig(k, "b")
			bc.Peers = []config.Peer{peer(k, "a", ""), peer(k, "d", "")}
			bc.Routes = []config.Route{localRoute("127.0.4.0/24", "b")}
			if reason == core.ReasonNoRoute {
				// The relay is live, but its next hop has no session.
				bc.Routes = []config.Route{remoteRoute("127.0.4.0/24", config.Advertiser{Node: "d"})}
			}
			b := startNode(t, bc, nil, Options{Deliver: func(ctx context.Context, meta core.FlowMeta, f core.Flow, opts egress.Options) error {
				return core.Refuse(f, reason)
			}})
			cc := baseConfig(k, "c")
			cc.Peers = []config.Peer{peer(k, "a", "")}
			cc.Routes = []config.Route{localRoute("127.0.4.0/24", "c")}
			c := startNode(t, cc, rec, Options{})
			ac := baseConfig(k, "a")
			ac.Listen = nil
			ac.Peers = []config.Peer{peer(k, "b", addr(b)), peer(k, "c", addr(c))}
			ac.Routes = []config.Route{remoteRoute("127.0.4.0/24",
				config.Advertiser{Node: "d", Via: []string{"b"}, Priority: 1},
				config.Advertiser{Node: "c", Priority: 2})}
			a := startNode(t, ac, rec, Options{})
			waitUp(t, a, "b", "c")
			srv := newCountServer(t, "127.0.4.1")
			conn := injectTCP(t, a, srv.addr())
			defer conn.Close()
			switch reason {
			case core.ReasonNoRoute, core.ReasonUnreachable, core.ReasonHopLimit:
				if got := tcpExchange(t, conn, []byte("ok")); got != "n=2" {
					t.Fatalf("alternate response %q", got)
				}
				if d := rec.next(t); d.node != "c" {
					t.Fatalf("delivered by %s", d.node)
				}
			default:
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, err := conn.Read(make([]byte, 1)); err == nil {
					t.Fatal("terminal refusal produced data")
				}
				if srv.accepted.Load() != 0 {
					t.Fatal("terminal refusal tried the alternate")
				}
			}
			if !a.Sessions().Up("b") {
				t.Fatal("preferred relay session went down")
			}
		})
	}
}
