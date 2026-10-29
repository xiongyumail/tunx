package forward

import (
	"bytes"
	"context"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/xiongyumail/tunx/internal/config"
)

// The TUN of node a is a gVisor channel endpoint; a second gVisor stack on
// the other end plays the host that sends traffic into the TUN.

var hostAddr = netip.MustParseAddr("10.9.0.5")

func hostStack(t *testing.T, tunEP *channel.Endpoint) *stack.Stack {
	t.Helper()
	hs := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	hep := channel.New(512, 1500, "")
	if err := hs.CreateNIC(1, hep); err != nil {
		t.Fatal(err)
	}
	pa := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4(hostAddr.As4()), PrefixLen: 24},
	}
	if err := hs.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	any4, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	hs.SetRouteTable([]tcpip.Route{{Destination: any4, NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 2)
	go pump(ctx, hep, tunEP, done)
	go pump(ctx, tunEP, hep, done)
	t.Cleanup(func() {
		cancel()
		<-done
		<-done
		hs.Destroy()
	})
	return hs
}

// pump moves packets written to from into to.
func pump(ctx context.Context, from, to *channel.Endpoint, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	for {
		pkt := from.ReadContext(ctx)
		if pkt == nil {
			return
		}
		b := pkt.ToView().AsSlice()
		proto := ipv4.ProtocolNumber
		if header.IPVersion(b) == header.IPv6Version {
			proto = ipv6.ProtocolNumber
		}
		np := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(b))})
		pkt.DecRef()
		to.InjectInbound(proto, np)
		np.DecRef()
	}
}

// overlay maps a loopback server address 127.0.x.y:port to the address the
// host sends to, 198.18.x.y:port.
func overlay(ap netip.AddrPort) tcpip.FullAddress {
	b := ap.Addr().As4()
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{198, 18, b[2], b[3]}), Port: ap.Port()}
}

func TestTUNToRemoteNode(t *testing.T) {
	k := newKeys(t, "a", "b")
	rec := newRecorder()
	bc := baseConfig(k, "b")
	bc.Peers = []config.Peer{peer(k, "a", "")}
	bc.Routes = []config.Route{localRoute("198.18.1.0/24", "b")}
	b := startNode(t, bc, rec, Options{})

	tunEP := channel.New(512, 1500, "")
	ac := baseConfig(k, "a")
	ac.Listen = nil
	ac.Peers = []config.Peer{peer(k, "b", addr(b))}
	ac.Routes = []config.Route{remoteRoute("198.18.1.0/24", config.Advertiser{Node: "b"})}
	a := startNode(t, ac, rec, Options{Endpoint: tunEP})
	waitUp(t, a, "b")
	hs := hostStack(t, tunEP)

	// TCP with half-close.
	srv := newCountServer(t, "127.0.1.1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, hs, overlay(srv.addr()), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := bytes.Repeat([]byte("x"), 300000)
	go func() {
		c.Write(payload)
		c.CloseWrite()
	}()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var got bytes.Buffer
	if _, err := got.ReadFrom(c); err != nil {
		t.Fatal(err)
	}
	if want := "n=" + strconv.Itoa(len(payload)); got.String() != want {
		t.Fatalf("got %q, want %q", got.String(), want)
	}
	d := rec.next(t)
	if d.node != "b" || d.meta.Identity != "a" || d.meta.Src.Addr() != hostAddr {
		t.Fatalf("delivered %+v", d)
	}

	// UDP.
	dst := udpEcho(t, "127.0.1.1")
	raddr := overlay(dst)
	u, err := gonet.DialUDP(hs, nil, &raddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	buf := make([]byte, 2048)
	for _, m := range []string{"one", "two"} {
		u.Write([]byte(m))
		u.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := u.Read(buf)
		if err != nil || string(buf[:n]) != "re:"+m {
			t.Fatalf("udp %q: got %q, %v", m, buf[:n], err)
		}
	}

	// An unroutable destination gets nothing back: the SYN goes unanswered.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel2()
	if c, err := gonet.DialContextTCP(ctx2, hs, overlay(netip.MustParseAddrPort("127.0.9.1:80")), ipv4.ProtocolNumber); err == nil {
		c.Close()
		t.Fatal("connected to an unroutable destination")
	}
}
