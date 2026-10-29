package netstack

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xiongyumail/tunx/internal/core"
)

// icmpQueueLen bounds requests queued for a handler that reads slowly; more
// are dropped, like a congested link would.
const icmpQueueLen = 64

type icmpKey struct {
	src, dst netip.Addr
	id       uint16
}

// handleICMP is the default handler for ICMP and ICMPv6 packets that reached
// the transport layer. It takes echo requests (returning true, which also
// stops gVisor from replying itself) and leaves everything else to the stack.
func (s *Stack) handleICMP(_ stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	hdr := pkt.TransportHeader().Slice()
	var (
		proto core.Proto
		id    uint16
	)
	switch pkt.NetworkProtocolNumber {
	case ipv4.ProtocolNumber:
		h := header.ICMPv4(hdr)
		if len(h) < header.ICMPv4MinimumSize || h.Type() != header.ICMPv4Echo {
			return false
		}
		// IPv4 hands echo requests with a bad checksum to the transport
		// layer too; drop them.
		if checksum.Checksum(h, pkt.Data().Checksum()) != 0xffff {
			return true
		}
		proto, id = core.ProtoICMP, h.Ident()
	case ipv6.ProtocolNumber:
		h := header.ICMPv6(hdr)
		if len(h) < header.ICMPv6EchoMinimumSize || h.Type() != header.ICMPv6EchoRequest {
			return false
		}
		proto, id = core.ProtoICMPv6, h.Ident()
	default:
		return false
	}

	nh := pkt.Network()
	src := addrPort(nh.SourceAddress(), id)
	dst := addrPort(nh.DestinationAddress(), 0)
	v := stack.PayloadSince(pkt.TransportHeader())
	msg := v.ToSlice()
	v.Release()

	key := icmpKey{src: src.Addr(), dst: dst.Addr(), id: id}
	s.mu.Lock()
	f, ok := s.icmp[key]
	if ok && f.isClosed() {
		ok = false
	}
	if !ok {
		if s.closed || len(s.flows) >= s.cfg.MaxFlows {
			s.mu.Unlock()
			return true
		}
		f = &icmpFlow{
			s:    s,
			key:  key,
			meta: core.FlowMeta{Proto: proto, Src: src, Dst: dst},
			in:   make(chan []byte, icmpQueueLen),
			done: make(chan struct{}),
		}
		f.idle = newIdleTimer(s.cfg.ICMPIdleTimeout, func() { f.Close() })
		s.icmp[key] = f
		s.flows[f] = struct{}{}
		s.wg.Add(1)
		go s.serve(f.meta, f)
	}
	s.mu.Unlock()
	f.deliver(msg)
	return true
}

// icmpFlow is one echo session (src, dst, identifier). Read returns echo
// requests from the TUN; Write takes echo replies and injects them.
type icmpFlow struct {
	s    *Stack
	key  icmpKey
	meta core.FlowMeta
	in   chan []byte
	done chan struct{}
	idle *idleTimer

	closeOnce sync.Once
}

func (f *icmpFlow) deliver(msg []byte) {
	select {
	case <-f.done:
	case f.in <- msg:
	default: // queue full
	}
}

func (f *icmpFlow) Read(b []byte) (int, error) {
	select {
	case <-f.done:
		return 0, io.EOF
	case m := <-f.in:
		f.touch()
		return copy(b, m), nil
	}
}

func (f *icmpFlow) touch() { f.idle.touch() }

func (f *icmpFlow) isClosed() bool {
	select {
	case <-f.done:
		return true
	default:
		return false
	}
}

// Write injects one echo reply. Its identifier is set to the flow's and its
// checksum is recomputed. Messages other than echo replies are refused.
func (f *icmpFlow) Write(b []byte) (int, error) {
	select {
	case <-f.done:
		return 0, net.ErrClosed
	default:
	}
	f.touch()
	if err := f.s.writeEchoReply(f.meta, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (f *icmpFlow) CloseWrite() error { return f.Close() }

func (f *icmpFlow) Close() error {
	f.closeOnce.Do(func() {
		close(f.done)
		f.s.mu.Lock()
		if f.s.icmp[f.key] == f {
			delete(f.s.icmp, f.key)
		}
		delete(f.s.flows, f)
		f.s.mu.Unlock()
		f.idle.stop()
	})
	return nil
}

var errNotEchoReply = errors.New("netstack: not an echo reply")

// writeEchoReply sends msg, an ICMP echo reply, from meta.Dst to meta.Src.
func (s *Stack) writeEchoReply(meta core.FlowMeta, b []byte) error {
	msg := make([]byte, len(b))
	copy(msg, b)
	local, remote := tcpipAddr(meta.Dst.Addr()), tcpipAddr(meta.Src.Addr())

	var (
		netProto   tcpip.NetworkProtocolNumber
		transProto tcpip.TransportProtocolNumber
	)
	switch meta.Proto {
	case core.ProtoICMP:
		h := header.ICMPv4(msg)
		if len(h) < header.ICMPv4MinimumSize || h.Type() != header.ICMPv4EchoReply {
			return errNotEchoReply
		}
		h.SetIdent(meta.Src.Port())
		h.SetChecksum(0)
		h.SetChecksum(^checksum.Checksum(msg, 0))
		netProto, transProto = ipv4.ProtocolNumber, header.ICMPv4ProtocolNumber
	case core.ProtoICMPv6:
		h := header.ICMPv6(msg)
		if len(h) < header.ICMPv6EchoMinimumSize || h.Type() != header.ICMPv6EchoReply {
			return errNotEchoReply
		}
		h.SetIdent(meta.Src.Port())
		h.SetChecksum(0)
		xsum := header.PseudoHeaderChecksum(header.ICMPv6ProtocolNumber, local, remote, uint16(len(msg)))
		h.SetChecksum(^checksum.Checksum(msg, xsum))
		netProto, transProto = ipv6.ProtocolNumber, header.ICMPv6ProtocolNumber
	default:
		return fmt.Errorf("netstack: bad echo protocol %v", meta.Proto)
	}

	r, terr := s.st.FindRoute(nicID, local, remote, netProto, false)
	if terr != nil {
		return fmt.Errorf("netstack: route for echo reply: %s", terr)
	}
	defer r.Release()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(msg),
	})
	defer pkt.DecRef()
	pkt.TransportProtocolNumber = transProto
	if terr := r.WritePacket(stack.NetworkHeaderParams{Protocol: transProto, TTL: s.cfg.ReplyTTL}, pkt); terr != nil {
		return fmt.Errorf("netstack: write echo reply: %s", terr)
	}
	return nil
}
