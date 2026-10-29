package netstack

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/xiongyumail/tunx/internal/core"
	"github.com/xiongyumail/tunx/internal/egress"
)

// End-to-end: a client stack sends through a channel link into Stack, whose
// handler delivers the flow with egress to a loopback server. Overlay
// destinations are mapped to loopback, as a route lookup would pick an exit.

var overlayToLoopback = map[netip.Addr]netip.Addr{
	netip.MustParseAddr("198.18.0.1"):  netip.MustParseAddr("127.0.0.1"),
	netip.MustParseAddr("2001:db8::1"): netip.MustParseAddr("::1"),
}

func egressHandler(t *testing.T) core.Handler {
	return core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
		lo, ok := overlayToLoopback[meta.Dst.Addr()]
		if !ok {
			f.Close()
			return
		}
		meta.Dst = netip.AddrPortFrom(lo, meta.Dst.Port())
		err := egress.Deliver(ctx, meta, f, egress.Options{IdleTimeout: 2 * time.Second})
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("deliver %v: %v", meta.Proto, err)
		}
	})
}

// newClientStack returns a plain gVisor stack wired to the TUN side of a
// Stack, standing in for the host kernel.
func newClientStack(t *testing.T, tunEP *channel.Endpoint) *stack.Stack {
	t.Helper()
	cs := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	cep := channel.New(512, 1500, "")
	if err := cs.CreateNIC(1, cep); err != nil {
		t.Fatal(err)
	}
	for _, p := range []netip.Prefix{netip.PrefixFrom(client4, 24), netip.PrefixFrom(client6, 64)} {
		proto := ipv4.ProtocolNumber
		if p.Addr().Is6() {
			proto = ipv6.ProtocolNumber
		}
		pa := tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpipAddr(p.Addr()), PrefixLen: p.Bits()}}
		if err := cs.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	cs.SetRouteTable([]tcpip.Route{{Destination: anySubnet4(), NIC: 1}, {Destination: anySubnet6(), NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 2)
	go pump(ctx, cep, tunEP, done)
	go pump(ctx, tunEP, cep, done)
	t.Cleanup(func() {
		cancel()
		<-done
		<-done
		cs.Destroy()
	})
	return cs
}

// pump moves packets sent on from into to.
func pump(ctx context.Context, from, to *channel.Endpoint, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	for {
		pkt := from.ReadContext(ctx)
		if pkt == nil {
			return
		}
		b := pkt.ToView().AsSlice()
		pkt.DecRef()
		inject(to, b)
	}
}

func fullAddr(ap netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	proto := ipv4.ProtocolNumber
	if ap.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpipAddr(ap.Addr()), Port: ap.Port()}, proto
}

func TestEndToEndTCP(t *testing.T) {
	for _, tc := range []struct{ network, listen, overlay string }{
		{"tcp4", "127.0.0.1:0", "198.18.0.1"},
		{"tcp6", "[::1]:0", "2001:db8::1"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			ln, err := net.Listen(tc.network, tc.listen)
			if err != nil {
				t.Skipf("listen: %v", err)
			}
			defer ln.Close()
			peers := make(chan string, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				peers <- c.RemoteAddr().String()
				n, _ := io.Copy(io.Discard, c) // until the client half-closes
				c.Write([]byte("n=" + strconv.FormatInt(n, 10)))
			}()

			_, tunEP := newTestStack(t, egressHandler(t), nil)
			cs := newClientStack(t, tunEP)
			port := uint16(ln.Addr().(*net.TCPAddr).Port)
			addr, proto := fullAddr(netip.AddrPortFrom(netip.MustParseAddr(tc.overlay), port))
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, err := gonet.DialContextTCP(ctx, cs, addr, proto)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()

			payload := bytes.Repeat([]byte("tunx"), 1<<18) // 1 MiB
			if _, err := c.Write(payload); err != nil {
				t.Fatal(err)
			}
			c.CloseWrite()
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatal(err)
			}
			if want := "n=" + strconv.Itoa(len(payload)); string(got) != want {
				t.Fatalf("got %q, want %q", got, want)
			}
			<-peers
		})
	}
}

func TestEndToEndUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

	_, tunEP := newTestStack(t, egressHandler(t), nil)
	cs := newClientStack(t, tunEP)
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	raddr, proto := fullAddr(netip.AddrPortFrom(netip.MustParseAddr("198.18.0.1"), port))
	c, err := gonet.DialUDP(cs, nil, &raddr, proto)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 2048)
	for _, m := range []string{"one", "two", "three"} {
		c.Write([]byte(m))
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "re:"+m {
			t.Fatalf("got %q", buf[:n])
		}
	}
}

func TestEndToEndPing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		src, dst netip.Addr
		proto    tcpip.TransportProtocolNumber
	}{
		{"v4", client4, netip.MustParseAddr("198.18.0.1"), header.ICMPv4ProtocolNumber},
		{"v6", client6, netip.MustParseAddr("2001:db8::1"), header.ICMPv6ProtocolNumber},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Ping sockets may be disabled (net.ipv4.ping_group_range).
			if !pingAllowed(tc.src.Is6()) {
				t.Skip("ping sockets not permitted")
			}
			_, ep := newTestStack(t, egressHandler(t), nil)
			for seq := uint16(1); seq <= 3; seq++ {
				inject(ep, echoPacket(tc.src, tc.dst, 0x7777, seq, []byte("e2e")))
				p := expectPacket(t, ep, tc.proto)
				m := p.l4
				if p.src != tc.dst || p.dst != tc.src {
					t.Fatalf("reply %v -> %v", p.src, p.dst)
				}
				if m[4] != 0x77 || m[5] != 0x77 || uint16(m[6])<<8|uint16(m[7]) != seq || string(m[8:]) != "e2e" {
					t.Fatalf("reply % x", m)
				}
			}
			// An address the handler does not deliver gets no reply.
			other := netip.MustParseAddr("192.0.2.1")
			if tc.src.Is6() {
				other = netip.MustParseAddr("2001:db8::99")
			}
			inject(ep, echoPacket(tc.src, other, 0x7777, 1, nil))
			expectNothing(t, ep, 300*time.Millisecond)
		})
	}
}

// pingAllowed reports whether this process may open a ping socket.
func pingAllowed(v6 bool) bool {
	family, proto := unix.AF_INET, unix.IPPROTO_ICMP
	if v6 {
		family, proto = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}
