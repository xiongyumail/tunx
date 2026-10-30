// Package netstack captures traffic from a TUN device with gVisor's network
// stack and hands every TCP connection, UDP 5-tuple and ICMP echo session to
// a core.Handler as a core.Flow.
//
// The stack accepts packets for any destination (promiscuous) and answers as
// any address (spoofing). It never answers on its own: ICMP echo requests
// become flows and a reply is written back only when the handler returns one,
// and ICMP errors such as port unreachable are not generated.
package netstack

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/xiongyumail/tunx/internal/core"
)

const nicID tcpip.NICID = 1

// Defaults for zero Config fields.
const (
	DefaultMTU             = 1500
	DefaultUDPIdleTimeout  = 60 * time.Second
	DefaultICMPIdleTimeout = 30 * time.Second
	DefaultTCPMaxInFlight  = 1024
	DefaultMaxFlows        = 65536
	DefaultReplyTTL        = 64
)

// Config configures a Stack. Exactly one of FD, Name and Endpoint is set.
type Config struct {
	// FD is an open TUN file descriptor (IFF_TUN | IFF_NO_PI). The stack
	// takes ownership and closes it on Close. Zero means unset.
	FD int
	// Name is a TUN device to open (or create, which needs CAP_NET_ADMIN).
	Name string
	// Endpoint is a link endpoint to use instead of a TUN device, such as a
	// gVisor channel endpoint in tests. Its MTU is used as is.
	Endpoint stack.LinkEndpoint

	// MTU of the TUN device. Zero reads it from the device named by Name,
	// or uses DefaultMTU.
	MTU uint32
	// Addresses are optionally assigned to the stack. None are needed: the
	// stack accepts and answers for any address.
	Addresses []netip.Prefix

	// Handler receives every flow. Required.
	Handler core.Handler

	// UDPIdleTimeout closes a UDP flow with no traffic either way.
	UDPIdleTimeout time.Duration
	// ICMPIdleTimeout closes an echo flow with no traffic either way.
	ICMPIdleTimeout time.Duration
	// TCPMaxInFlight bounds connections whose handshake is pending, that is,
	// accepted SYNs whose handler has not yet read or written.
	TCPMaxInFlight int
	// MaxFlows bounds open flows of all protocols. New flows beyond it are
	// dropped silently.
	MaxFlows int
	// TCPRejectWithReset makes every TCP flow refused or closed before the
	// handshake answer the SYN with RST. By default only a refusal with
	// core.ReasonRefused does; otherwise the SYN is dropped, so an
	// unreachable or denied destination looks like a silent one.
	TCPRejectWithReset bool
	// ReplyTTL is the IP TTL (hop limit) of injected echo replies.
	ReplyTTL uint8
}

// Stack is a gVisor network stack attached to a TUN device.
type Stack struct {
	cfg    Config
	st     *stack.Stack
	fd     int // owned TUN fd, or -1
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	closed    bool
	flows     map[flowCloser]struct{}
	icmp      map[icmpKey]*icmpFlow
	wg        sync.WaitGroup // handler goroutines
	closeOnce sync.Once
}

type flowCloser interface{ Close() error }

// New builds a stack and starts capturing.
func New(cfg Config) (*Stack, error) {
	if cfg.Handler == nil {
		return nil, errors.New("netstack: no handler")
	}
	set := 0
	for _, b := range []bool{cfg.FD > 0, cfg.Name != "", cfg.Endpoint != nil} {
		if b {
			set++
		}
	}
	if set != 1 {
		return nil, errors.New("netstack: set exactly one of FD, Name, Endpoint")
	}
	if cfg.UDPIdleTimeout <= 0 {
		cfg.UDPIdleTimeout = DefaultUDPIdleTimeout
	}
	if cfg.ICMPIdleTimeout <= 0 {
		cfg.ICMPIdleTimeout = DefaultICMPIdleTimeout
	}
	if cfg.TCPMaxInFlight <= 0 {
		cfg.TCPMaxInFlight = DefaultTCPMaxInFlight
	}
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = DefaultMaxFlows
	}
	if cfg.ReplyTTL == 0 {
		cfg.ReplyTTL = DefaultReplyTTL
	}

	s := &Stack{
		cfg:   cfg,
		fd:    -1,
		flows: make(map[flowCloser]struct{}),
		icmp:  make(map[icmpKey]*icmpFlow),
	}
	ep := cfg.Endpoint
	if ep == nil {
		var err error
		if ep, err = s.openTUN(); err != nil {
			return nil, err
		}
	}
	if err := s.init(ep); err != nil {
		if s.fd >= 0 {
			unix.Close(s.fd)
		}
		return nil, err
	}
	return s, nil
}

func (s *Stack) openTUN() (stack.LinkEndpoint, error) {
	fd := s.cfg.FD
	if s.cfg.Name != "" {
		var err error
		if fd, err = tun.Open(s.cfg.Name); err != nil {
			return nil, fmt.Errorf("netstack: open tun %q: %w", s.cfg.Name, err)
		}
	}
	s.fd = fd
	mtu := s.cfg.MTU
	if mtu == 0 && s.cfg.Name != "" {
		if m, err := rawfile.GetMTU(s.cfg.Name); err == nil {
			mtu = m
		}
	}
	if mtu == 0 {
		mtu = DefaultMTU
	}
	ep, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: mtu})
	if err != nil {
		unix.Close(fd)
		s.fd = -1
		return nil, fmt.Errorf("netstack: tun endpoint: %w", err)
	}
	return ep, nil
}

func (s *Stack) init(ep stack.LinkEndpoint) error {
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	s.st = st
	s.ctx, s.cancel = context.WithCancel(context.Background())
	fail := func(what string, err tcpip.Error) error {
		st.Destroy()
		s.cancel()
		return fmt.Errorf("netstack: %s: %s", what, err)
	}

	// A burst of zero makes the rate limiter refuse every rate-limited ICMP
	// error (destination unreachable, time exceeded, parameter problem), so
	// the stack never answers on behalf of a destination.
	st.SetICMPBurst(0)

	// TCP keepalive stays off (the gVisor default): idle connections are
	// the client's business.
	sack := tcpip.TCPSACKEnabled(true)
	st.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultReceiveBufferSize, Max: 4 << 20}
	st.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv)
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcp.DefaultSendBufferSize, Max: 4 << 20}
	st.SetTransportProtocolOption(tcp.ProtocolNumber, &snd)
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	st.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate)

	tcpFwd := tcp.NewForwarder(st, 0, s.cfg.TCPMaxInFlight, s.handleTCP)
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(st, s.handleUDP)
	st.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		if s.full() {
			return true // drop without a port unreachable
		}
		return udpFwd.HandlePacket(id, pkt)
	})
	// Returning true for echo requests also suppresses gVisor's built-in
	// echo reply.
	st.SetTransportProtocolHandler(icmp.ProtocolNumber4, s.handleICMP)
	st.SetTransportProtocolHandler(icmp.ProtocolNumber6, s.handleICMP)

	if err := st.CreateNIC(nicID, ep); err != nil {
		return fail("create nic", err)
	}
	if err := st.SetPromiscuousMode(nicID, true); err != nil {
		return fail("promiscuous mode", err)
	}
	if err := st.SetSpoofing(nicID, true); err != nil {
		return fail("spoofing", err)
	}
	for _, p := range s.cfg.Addresses {
		proto := ipv4.ProtocolNumber
		if p.Addr().Is6() {
			proto = ipv6.ProtocolNumber
		}
		pa := tcpip.ProtocolAddress{
			Protocol: proto,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(p.Addr().Unmap().AsSlice()),
				PrefixLen: p.Bits(),
			},
		}
		if err := st.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
			return fail("add address "+p.String(), err)
		}
	}
	st.SetRouteTable([]tcpip.Route{
		{Destination: anySubnet4(), NIC: nicID},
		{Destination: anySubnet6(), NIC: nicID},
	})
	return nil
}

// Close stops capturing, closes every open flow and waits for the handlers
// to return.
func (s *Stack) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		s.mu.Lock()
		s.closed = true
		flows := make([]flowCloser, 0, len(s.flows))
		for f := range s.flows {
			flows = append(flows, f)
		}
		s.mu.Unlock()
		for _, f := range flows {
			f.Close()
		}
		s.st.Destroy()
		s.wg.Wait()
		if s.fd >= 0 {
			unix.Close(s.fd)
		}
	})
	return nil
}

// track registers a flow so Close can reach it. It fails when the stack is
// closed or the flow limit is reached.
func (s *Stack) track(f flowCloser) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.flows) >= s.cfg.MaxFlows {
		return false
	}
	s.flows[f] = struct{}{}
	s.wg.Add(1)
	return true
}

func (s *Stack) untrack(f flowCloser) {
	s.mu.Lock()
	delete(s.flows, f)
	s.mu.Unlock()
}

func (s *Stack) full() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed || len(s.flows) >= s.cfg.MaxFlows
}

// serve runs the handler for a tracked flow and closes it afterwards, in
// case the handler did not.
func (s *Stack) serve(meta core.FlowMeta, f core.Flow) {
	defer s.wg.Done()
	defer s.untrack(f)
	defer f.Close()
	s.cfg.Handler.HandleFlow(s.ctx, meta, f, core.Ingress{Kind: "tun"})
}

func anySubnet4() tcpip.Subnet {
	sn, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	return sn
}

func anySubnet6() tcpip.Subnet {
	sn, _ := tcpip.NewSubnet(tcpip.AddrFrom16([16]byte{}), tcpip.MaskFromBytes(make([]byte, 16)))
	return sn
}

func addrPort(a tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip, port)
}

func tcpipAddr(a netip.Addr) tcpip.Address {
	return tcpip.AddrFromSlice(a.Unmap().AsSlice())
}
