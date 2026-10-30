package netstack

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/xiongyumail/tunx/internal/core"
)

var (
	client4 = netip.MustParseAddr("10.0.0.2")
	client6 = netip.MustParseAddr("fd00::2")
)

type flowEvent struct {
	meta core.FlowMeta
	in   core.Ingress
}

func TestTCPHandshakeAndData(t *testing.T) {
	for _, tc := range []struct {
		name     string
		src, dst netip.AddrPort
	}{
		{"v4", netip.AddrPortFrom(client4, 40000), netip.MustParseAddrPort("198.18.0.1:80")},
		{"v6", netip.AddrPortFrom(client6, 40000), netip.MustParseAddrPort("[2001:db8::1]:443")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := make(chan flowEvent, 1)
			got := make(chan []byte, 1)
			h := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
				defer f.Close()
				events <- flowEvent{meta, in}
				buf := make([]byte, 64)
				n, err := f.Read(buf)
				if err != nil {
					t.Errorf("read: %v", err)
					return
				}
				got <- buf[:n]
				f.Write([]byte("world"))
				f.CloseWrite()
				io.Copy(io.Discard, f)
			})
			_, ep := newTestStack(t, h, nil)

			inject(ep, tcpPacket(tc.src, tc.dst, 1000, 0, header.TCPFlagSyn, nil))
			ev := <-events
			want := core.FlowMeta{Proto: core.ProtoTCP, Src: tc.src, Dst: tc.dst}
			if ev.meta != want || ev.in.Kind != "tun" {
				t.Fatalf("flow %+v %+v, want %+v tun", ev.meta, ev.in, want)
			}

			p := expectPacket(t, ep, header.TCPProtocolNumber)
			synack := header.TCP(p.l4)
			if p.src != tc.dst.Addr() || p.dst != tc.src.Addr() || synack.SourcePort() != tc.dst.Port() {
				t.Fatalf("syn-ack from %v:%d to %v", p.src, synack.SourcePort(), p.dst)
			}
			if synack.Flags() != header.TCPFlagSyn|header.TCPFlagAck || synack.AckNumber() != 1001 {
				t.Fatalf("syn-ack flags %v ack %d", synack.Flags(), synack.AckNumber())
			}
			iss := synack.SequenceNumber()
			inject(ep, tcpPacket(tc.src, tc.dst, 1001, iss+1, header.TCPFlagAck|header.TCPFlagPsh, []byte("hello")))
			if b := <-got; string(b) != "hello" {
				t.Fatalf("handler read %q", b)
			}

			// Collect the reply data and the FIN.
			var data []byte
			fin := false
			deadline := time.Now().Add(5 * time.Second)
			for !fin && time.Now().Before(deadline) {
				p := expectPacket(t, ep, header.TCPProtocolNumber)
				seg := header.TCP(p.l4)
				data = append(data, seg.Payload()...)
				fin = seg.Flags().Contains(header.TCPFlagFin)
			}
			if string(data) != "world" || !fin {
				t.Fatalf("reply %q fin %v", data, fin)
			}
		})
	}
}

func TestTCPRefusedFlowGetsNoSynAck(t *testing.T) {
	for _, reset := range []bool{false, true} {
		h := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
			f.Close()
		})
		_, ep := newTestStack(t, h, func(c *Config) { c.TCPRejectWithReset = reset })
		src, dst := netip.AddrPortFrom(client4, 40001), netip.MustParseAddrPort("198.18.0.1:81")
		inject(ep, tcpPacket(src, dst, 1000, 0, header.TCPFlagSyn, nil))
		if !reset {
			expectNothing(t, ep, 300*time.Millisecond)
			continue
		}
		p := expectPacket(t, ep, header.TCPProtocolNumber)
		if f := header.TCP(p.l4).Flags(); !f.Contains(header.TCPFlagRst) {
			t.Fatalf("flags %v, want RST", f)
		}
	}
}

// Only a refusal by the destination answers the SYN with RST; every other
// reason leaves it unanswered. An explicit Accept completes the handshake.
func TestTCPRefuseReasons(t *testing.T) {
	for _, tc := range []struct {
		reason core.Reason // 0: accept
		want   header.TCPFlags
	}{
		{core.ReasonRefused, header.TCPFlagRst},
		{core.ReasonDenied, 0},
		{core.ReasonUnreachable, 0},
		{core.ReasonNoRoute, 0},
		{core.ReasonError, 0},
		{0, header.TCPFlagSyn | header.TCPFlagAck},
	} {
		accepted := make(chan error, 1)
		h := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
			defer f.Close()
			if tc.reason == 0 {
				accepted <- core.Accept(f)
				<-ctx.Done()
				return
			}
			core.Refuse(f, tc.reason)
		})
		_, ep := newTestStack(t, h, nil)
		src, dst := netip.AddrPortFrom(client4, 40002), netip.MustParseAddrPort("198.18.0.1:82")
		inject(ep, tcpPacket(src, dst, 1000, 0, header.TCPFlagSyn, nil))
		if tc.want == 0 {
			expectNothing(t, ep, 300*time.Millisecond)
			continue
		}
		p := expectPacket(t, ep, header.TCPProtocolNumber)
		seg := header.TCP(p.l4)
		if f := seg.Flags(); !f.Contains(tc.want) {
			t.Fatalf("reason %v: flags %v, want %v", tc.reason, f, tc.want)
		}
		if tc.reason == 0 {
			// Accept returns once the handshake is complete.
			inject(ep, tcpPacket(src, dst, 1001, seg.SequenceNumber()+1, header.TCPFlagAck, nil))
			if err := <-accepted; err != nil {
				t.Fatalf("accept: %v", err)
			}
		}
	}
}

func TestUDP(t *testing.T) {
	for _, tc := range []struct {
		name     string
		src, dst netip.AddrPort
	}{
		{"v4", netip.AddrPortFrom(client4, 5000), netip.MustParseAddrPort("198.18.0.9:53")},
		{"v6", netip.AddrPortFrom(client6, 5000), netip.MustParseAddrPort("[2001:db8::53]:53")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var metas []core.FlowMeta
			h := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
				defer f.Close()
				mu.Lock()
				metas = append(metas, meta)
				mu.Unlock()
				buf := make([]byte, 2048)
				for {
					n, err := f.Read(buf)
					if err != nil {
						return
					}
					f.Write(append([]byte("re:"), buf[:n]...))
				}
			})
			_, ep := newTestStack(t, h, nil)
			for _, msg := range []string{"q1", "q2-longer"} {
				inject(ep, udpPacket(tc.src, tc.dst, []byte(msg)))
				p := expectPacket(t, ep, header.UDPProtocolNumber)
				u := header.UDP(p.l4)
				if p.src != tc.dst.Addr() || p.dst != tc.src.Addr() || u.SourcePort() != tc.dst.Port() || u.DestinationPort() != tc.src.Port() {
					t.Fatalf("reply %v:%d -> %v:%d", p.src, u.SourcePort(), p.dst, u.DestinationPort())
				}
				if string(u.Payload()) != "re:"+msg {
					t.Fatalf("reply %q", u.Payload())
				}
			}
			mu.Lock()
			defer mu.Unlock()
			want := core.FlowMeta{Proto: core.ProtoUDP, Src: tc.src, Dst: tc.dst}
			if len(metas) != 1 || metas[0] != want {
				t.Fatalf("flows %+v, want one %+v", metas, want)
			}
		})
	}
}

func TestUDPIdleTimeout(t *testing.T) {
	ended := make(chan time.Duration, 1)
	h := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
		defer f.Close()
		start := time.Now()
		buf := make([]byte, 2048)
		for {
			if _, err := f.Read(buf); err != nil {
				ended <- time.Since(start)
				return
			}
		}
	})
	_, ep := newTestStack(t, h, func(c *Config) { c.UDPIdleTimeout = 200 * time.Millisecond })
	inject(ep, udpPacket(netip.AddrPortFrom(client4, 5001), netip.MustParseAddrPort("198.18.0.9:53"), []byte("x")))
	select {
	case d := <-ended:
		if d < 150*time.Millisecond {
			t.Fatalf("closed after %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("flow did not idle out")
	}
}

func TestICMPEcho(t *testing.T) {
	for _, tc := range []struct {
		name          string
		src, reply    netip.Addr
		silent        netip.Addr
		proto         core.Proto
		transport     uint8
		requestType   byte
		replyTypeWant byte
	}{
		{"v4", client4, netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("192.0.2.1"), core.ProtoICMP, uint8(header.ICMPv4ProtocolNumber), byte(header.ICMPv4Echo), byte(header.ICMPv4EchoReply)},
		{"v6", client6, netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::dead"), core.ProtoICMPv6, uint8(header.ICMPv6ProtocolNumber), byte(header.ICMPv6EchoRequest), byte(header.ICMPv6EchoReply)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v6 := tc.proto == core.ProtoICMPv6
			var mu sync.Mutex
			var metas []core.FlowMeta
			var msgs [][]byte
			h := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
				defer f.Close()
				mu.Lock()
				metas = append(metas, meta)
				mu.Unlock()
				buf := make([]byte, 2048)
				for {
					n, err := f.Read(buf)
					if err != nil {
						return
					}
					m := append([]byte(nil), buf[:n]...)
					mu.Lock()
					msgs = append(msgs, m)
					mu.Unlock()
					if meta.Dst.Addr() == tc.silent {
						continue // the destination does not answer
					}
					r := echoMessage(v6, true, meta.Src.Port(), uint16(m[6])<<8|uint16(m[7]), m[8:])
					if _, err := f.Write(r); err != nil {
						t.Errorf("write reply: %v", err)
					}
				}
			})
			_, ep := newTestStack(t, h, nil)

			payload := []byte("ping-payload")
			for seq := uint16(1); seq <= 2; seq++ {
				inject(ep, echoPacket(tc.src, tc.reply, 0x4242, seq, payload))
				p := expectPacket(t, ep, tcpipProto(tc.transport))
				m := p.l4
				if p.src != tc.reply || p.dst != tc.src || p.ttl != DefaultReplyTTL {
					t.Fatalf("reply %v -> %v ttl %d", p.src, p.dst, p.ttl)
				}
				if m[0] != tc.replyTypeWant || m[1] != 0 || m[4] != 0x42 || m[5] != 0x42 || uint16(m[6])<<8|uint16(m[7]) != seq || !bytes.Equal(m[8:], payload) {
					t.Fatalf("reply message % x", m)
				}
			}

			// A destination that does not answer produces no reply at all.
			inject(ep, echoPacket(tc.src, tc.silent, 0x4343, 1, payload))
			expectNothing(t, ep, 300*time.Millisecond)

			mu.Lock()
			defer mu.Unlock()
			want := []core.FlowMeta{
				{Proto: tc.proto, Src: netip.AddrPortFrom(tc.src, 0x4242), Dst: netip.AddrPortFrom(tc.reply, 0)},
				{Proto: tc.proto, Src: netip.AddrPortFrom(tc.src, 0x4343), Dst: netip.AddrPortFrom(tc.silent, 0)},
			}
			if len(metas) != 2 || metas[0] != want[0] || metas[1] != want[1] {
				t.Fatalf("flows %+v, want %+v", metas, want)
			}
			if len(msgs) != 3 {
				t.Fatalf("handler got %d messages, want 3", len(msgs))
			}
			for _, m := range msgs {
				if m[0] != tc.requestType || !bytes.Equal(m[8:], payload) {
					t.Fatalf("request message % x", m)
				}
			}
		})
	}
}

func TestICMPRefusesNonReply(t *testing.T) {
	errc := make(chan error, 1)
	h := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
		defer f.Close()
		buf := make([]byte, 2048)
		f.Read(buf)
		// Destination unreachable is not passed back.
		_, err := f.Write([]byte{3, 1, 0, 0, 0, 0, 0, 0})
		errc <- err
	})
	_, ep := newTestStack(t, h, nil)
	inject(ep, echoPacket(client4, netip.MustParseAddr("192.0.2.7"), 1, 1, nil))
	if err := <-errc; err == nil {
		t.Fatal("non-echo reply accepted")
	}
	expectNothing(t, ep, 200*time.Millisecond)
}

func TestCloseEndsFlows(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(3)
	h := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
		defer wg.Done()
		defer f.Close()
		buf := make([]byte, 2048)
		for {
			if _, err := f.Read(buf); err != nil {
				return
			}
		}
	})
	s, ep := newTestStack(t, h, nil)
	inject(ep, udpPacket(netip.AddrPortFrom(client4, 6000), netip.MustParseAddrPort("198.18.0.9:53"), []byte("x")))
	inject(ep, echoPacket(client4, netip.MustParseAddr("198.18.0.9"), 9, 1, nil))
	inject(ep, tcpPacket(netip.AddrPortFrom(client4, 6001), netip.MustParseAddrPort("198.18.0.9:80"), 1, 0, header.TCPFlagSyn, nil))
	expectPacket(t, ep, header.TCPProtocolNumber) // handshake done, Read blocks
	done := make(chan struct{})
	go func() {
		s.Close()
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end the flows")
	}
}

func tcpipProto(p uint8) tcpip.TransportProtocolNumber { return tcpip.TransportProtocolNumber(p) }
