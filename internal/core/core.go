// Package core holds the types shared by the data plane: the description of a
// flow, the flow itself, and the handler that decides where a flow goes.
package core

import (
	"context"
	"io"
	"net/netip"
)

// Proto is the IP protocol number of a flow.
type Proto uint8

const (
	ProtoICMP   Proto = 1
	ProtoTCP    Proto = 6
	ProtoUDP    Proto = 17
	ProtoICMPv6 Proto = 58
)

func (p Proto) String() string {
	switch p {
	case ProtoICMP:
		return "icmp"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMPv6:
		return "icmpv6"
	}
	return "proto(" + itoa(int(p)) + ")"
}

// IsDatagram reports whether flows of this protocol carry messages rather
// than a byte stream.
func (p Proto) IsDatagram() bool { return p != ProtoTCP }

// FlowMeta describes a flow. It is carried in the header of every stream on a
// link, so each hop knows who sent the flow and where it goes.
type FlowMeta struct {
	Proto Proto
	// Src is the original source address. For ICMP the port is the echo
	// identifier.
	Src netip.AddrPort
	// Dst is the destination. For ICMP the port is 0.
	Dst netip.AddrPort
	// Identity is the authenticated sender: a node name, or a client name
	// for flows that entered through a standard proxy client.
	Identity string
	// Hops counts the links the flow has crossed; forwarders drop the flow
	// when it exceeds the limit, which breaks routing loops.
	Hops uint8
}

// Flow is one flow between two endpoints.
//
// For TCP it is a byte stream. For UDP, ICMP and ICMPv6 every Write sends one
// message and every Read returns one message: a UDP payload, or a complete
// ICMP message starting with the type byte (checksum may be zero; the
// receiver recomputes it).
type Flow interface {
	io.ReadWriteCloser
	// CloseWrite half-closes a TCP flow. Datagram flows treat it as Close.
	CloseWrite() error
}

// Ingress says where a flow entered this node.
type Ingress struct {
	// Kind is "tun" for traffic captured locally, "link" for traffic from a
	// peer, "client" for a standard proxy client.
	Kind string
	// Peer is the node name on the other end of the link, when Kind is
	// "link".
	Peer string
}

// Handler takes ownership of a flow and decides where it goes: deliver it on
// this node, forward it over a link, or refuse it. HandleFlow returns when the
// flow is finished and must close f.
type Handler interface {
	HandleFlow(ctx context.Context, meta FlowMeta, f Flow, in Ingress)
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, meta FlowMeta, f Flow, in Ingress)

func (h HandlerFunc) HandleFlow(ctx context.Context, meta FlowMeta, f Flow, in Ingress) {
	h(ctx, meta, f, in)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
