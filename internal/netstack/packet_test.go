package netstack

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xiongyumail/tunx/internal/core"
)

// Helpers to craft and parse raw IP packets on a channel endpoint.

func newTestStack(t *testing.T, h core.Handler, mod func(*Config)) (*Stack, *channel.Endpoint) {
	t.Helper()
	ep := channel.New(512, 1500, "")
	cfg := Config{Endpoint: ep, Handler: h}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, ep
}

func inject(ep *channel.Endpoint, b []byte) {
	proto := ipv4.ProtocolNumber
	if b[0]>>4 == 6 {
		proto = ipv6.ProtocolNumber
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b...))})
	ep.InjectInbound(proto, pkt)
	pkt.DecRef()
}

// readPacket returns the next packet the stack sent, or nil after d.
func readPacket(ep *channel.Endpoint, d time.Duration) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	pkt := ep.ReadContext(ctx)
	if pkt == nil {
		return nil
	}
	defer pkt.DecRef()
	return pkt.ToView().AsSlice()
}

func ipPacket(proto tcpip.TransportProtocolNumber, src, dst netip.Addr, payload []byte) []byte {
	if src.Is4() {
		b := make([]byte, header.IPv4MinimumSize+len(payload))
		ip := header.IPv4(b)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(b)),
			TTL:         64,
			Protocol:    uint8(proto),
			SrcAddr:     tcpipAddr(src),
			DstAddr:     tcpipAddr(dst),
		})
		ip.SetChecksum(^ip.CalculateChecksum())
		copy(b[header.IPv4MinimumSize:], payload)
		return b
	}
	b := make([]byte, header.IPv6MinimumSize+len(payload))
	header.IPv6(b).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(payload)),
		TransportProtocol: proto,
		HopLimit:          64,
		SrcAddr:           tcpipAddr(src),
		DstAddr:           tcpipAddr(dst),
	})
	copy(b[header.IPv6MinimumSize:], payload)
	return b
}

func pseudo(proto tcpip.TransportProtocolNumber, src, dst netip.Addr, n int) uint16 {
	return header.PseudoHeaderChecksum(proto, tcpipAddr(src), tcpipAddr(dst), uint16(n))
}

func udpPacket(src, dst netip.AddrPort, payload []byte) []byte {
	seg := make([]byte, header.UDPMinimumSize+len(payload))
	u := header.UDP(seg)
	u.Encode(&header.UDPFields{SrcPort: src.Port(), DstPort: dst.Port(), Length: uint16(len(seg))})
	copy(seg[header.UDPMinimumSize:], payload)
	u.SetChecksum(^checksum.Checksum(seg, pseudo(header.UDPProtocolNumber, src.Addr(), dst.Addr(), len(seg))))
	return ipPacket(header.UDPProtocolNumber, src.Addr(), dst.Addr(), seg)
}

func tcpPacket(src, dst netip.AddrPort, seq, ack uint32, flags header.TCPFlags, payload []byte) []byte {
	seg := make([]byte, header.TCPMinimumSize+len(payload))
	h := header.TCP(seg)
	h.Encode(&header.TCPFields{
		SrcPort:    src.Port(),
		DstPort:    dst.Port(),
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})
	copy(seg[header.TCPMinimumSize:], payload)
	h.SetChecksum(^checksum.Checksum(seg, pseudo(header.TCPProtocolNumber, src.Addr(), dst.Addr(), len(seg))))
	return ipPacket(header.TCPProtocolNumber, src.Addr(), dst.Addr(), seg)
}

// echoMessage builds an ICMP or ICMPv6 echo message with a zero checksum.
func echoMessage(v6, reply bool, id, seq uint16, payload []byte) []byte {
	m := make([]byte, 8+len(payload))
	switch {
	case !v6 && !reply:
		m[0] = byte(header.ICMPv4Echo)
	case !v6 && reply:
		m[0] = byte(header.ICMPv4EchoReply)
	case v6 && !reply:
		m[0] = byte(header.ICMPv6EchoRequest)
	default:
		m[0] = byte(header.ICMPv6EchoReply)
	}
	m[4], m[5] = byte(id>>8), byte(id)
	m[6], m[7] = byte(seq>>8), byte(seq)
	copy(m[8:], payload)
	return m
}

func echoPacket(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	v6 := src.Is6()
	m := echoMessage(v6, false, id, seq, payload)
	if v6 {
		xsum := checksum.Checksum(m, pseudo(header.ICMPv6ProtocolNumber, src, dst, len(m)))
		header.ICMPv6(m).SetChecksum(^xsum)
		return ipPacket(header.ICMPv6ProtocolNumber, src, dst, m)
	}
	header.ICMPv4(m).SetChecksum(^checksum.Checksum(m, 0))
	return ipPacket(header.ICMPv4ProtocolNumber, src, dst, m)
}

// parsed is an IP packet split into the parts tests check.
type parsed struct {
	proto    tcpip.TransportProtocolNumber
	src, dst netip.Addr
	ttl      uint8
	l4       []byte
}

// parsePacket splits b and verifies the IP and transport checksums.
func parsePacket(t *testing.T, b []byte) parsed {
	t.Helper()
	var p parsed
	switch b[0] >> 4 {
	case 4:
		ip := header.IPv4(b)
		if !ip.IsValid(len(b)) || ip.CalculateChecksum() != 0xffff {
			t.Fatalf("bad IPv4 header: % x", b[:header.IPv4MinimumSize])
		}
		p.proto = ip.TransportProtocol()
		p.src, _ = netip.AddrFromSlice(ip.SourceAddressSlice())
		p.dst, _ = netip.AddrFromSlice(ip.DestinationAddressSlice())
		p.ttl = ip.TTL()
		p.l4 = ip.Payload()
	case 6:
		ip := header.IPv6(b)
		if !ip.IsValid(len(b)) {
			t.Fatalf("bad IPv6 header")
		}
		p.proto = ip.TransportProtocol()
		p.src, _ = netip.AddrFromSlice(ip.SourceAddressSlice())
		p.dst, _ = netip.AddrFromSlice(ip.DestinationAddressSlice())
		p.ttl = ip.HopLimit()
		p.l4 = ip.Payload()
	default:
		t.Fatalf("not an IP packet: % x", b)
	}
	var xsum uint16
	switch p.proto {
	case header.ICMPv4ProtocolNumber:
		xsum = checksum.Checksum(p.l4, 0)
	default:
		xsum = checksum.Checksum(p.l4, pseudo(p.proto, p.src, p.dst, len(p.l4)))
	}
	if xsum != 0xffff {
		t.Fatalf("bad %d checksum in % x", p.proto, b)
	}
	return p
}

// expectPacket reads packets until one of proto arrives.
func expectPacket(t *testing.T, ep *channel.Endpoint, proto tcpip.TransportProtocolNumber) parsed {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b := readPacket(ep, time.Until(deadline))
		if b == nil {
			break
		}
		if p := parsePacket(t, b); p.proto == proto {
			return p
		}
	}
	t.Fatalf("no protocol %d packet", proto)
	return parsed{}
}

// expectNothing fails if any packet arrives within d.
func expectNothing(t *testing.T, ep *channel.Endpoint, d time.Duration) {
	t.Helper()
	if b := readPacket(ep, d); b != nil {
		t.Fatalf("unexpected packet % x", b)
	}
}
