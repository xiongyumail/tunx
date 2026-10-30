package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xiongyumail/tunx/internal/core"
)

// ICMP message types used here.
const (
	icmpv4EchoReply   = 0
	icmpv4EchoRequest = 8
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
	icmpEchoHeaderLen = 8
)

// openPing opens an unprivileged ping socket (SOCK_DGRAM, IPPROTO_ICMP or
// IPPROTO_ICMPV6) with the options applied, bound to the original source in
// preserve mode.
func openPing(meta core.FlowMeta, opts Options) (*net.UDPConn, error) {
	v6 := meta.Proto == core.ProtoICMPv6
	family, proto := unix.AF_INET, unix.IPPROTO_ICMP
	if v6 {
		family, proto = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}
	if dst := meta.Dst.Addr().Unmap(); !dst.IsValid() || dst.Is6() != v6 {
		return nil, fmt.Errorf("egress: %v flow to %v: address family mismatch", meta.Proto, meta.Dst.Addr())
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, proto)
	if err != nil {
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			return nil, ErrPingNotPermitted
		}
		return nil, fmt.Errorf("egress: ping socket: %w", err)
	}
	if err := setupPing(fd, meta, opts, v6); err != nil {
		unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "ping")
	pc, err := net.FilePacketConn(file)
	file.Close()
	if err != nil {
		return nil, fmt.Errorf("egress: ping socket: %w", err)
	}
	c, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("egress: ping socket: unexpected %T", pc)
	}
	return c, nil
}

func setupPing(fd int, meta core.FlowMeta, opts Options, v6 bool) error {
	if err := setSockopts(fd, opts, v6); err != nil {
		return err
	}
	if opts.Source != SourcePreserve {
		return nil
	}
	src, err := preserveSource(meta, v6)
	if err != nil {
		return err
	}
	// Port 0 lets the kernel pick the echo identifier.
	var sa unix.Sockaddr
	if v6 {
		sa = &unix.SockaddrInet6{Addr: src.As16()}
	} else {
		sa = &unix.SockaddrInet4{Addr: src.As4()}
	}
	if err := unix.Bind(fd, sa); err != nil {
		return fmt.Errorf("egress: bind ping socket to %v: %w", src, err)
	}
	return nil
}

// deliverEcho sends every echo request read from f as a real echo and writes
// the replies back with the requester's identifier. The kernel replaces the
// identifier on a ping socket; sequence numbers pass through unchanged and
// are used to match replies to requests. A request without a reply produces
// nothing.
func deliverEcho(ctx context.Context, meta core.FlowMeta, f core.Flow, opts Options) error {
	c, err := openPing(meta, opts)
	if err != nil {
		core.Refuse(f, core.ReasonError)
		return err
	}
	defer c.Close()
	if err := core.Accept(f); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() {
		c.Close()
		f.Close()
	})
	defer stop()

	v6 := meta.Proto == core.ProtoICMPv6
	reqType, replyType := byte(icmpv4EchoRequest), byte(icmpv4EchoReply)
	if v6 {
		reqType, replyType = icmpv6EchoRequest, icmpv6EchoReply
	}
	dst := meta.Dst.Addr().Unmap()
	to := &net.UDPAddr{IP: dst.AsSlice(), Zone: dst.Zone()}
	pend := newPending(opts.EchoTimeout)
	act := newActivity()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, maxDatagram)
		for {
			n, err := f.Read(buf)
			if err != nil {
				c.Close()
				return
			}
			msg := buf[:n]
			if n < icmpEchoHeaderLen || msg[0] != reqType || msg[1] != 0 {
				continue
			}
			act.touch()
			id := binary.BigEndian.Uint16(msg[4:])
			seq := binary.BigEndian.Uint16(msg[6:])
			pend.add(seq, id)
			// The kernel fills in the identifier and checksum.
			msg[2], msg[3] = 0, 0
			if _, err := c.WriteTo(msg, to); err != nil && !transient(err) {
				if isClosed(err) {
					return
				}
				continue // a failed send is a lost echo, nothing more
			}
		}
	}()

	buf := make([]byte, maxDatagram)
	for {
		c.SetReadDeadline(time.Now().Add(opts.IdleTimeout))
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				if act.idleFor() < opts.IdleTimeout {
					continue
				}
				break
			}
			if transient(err) {
				continue
			}
			break
		}
		msg := buf[:n]
		if n < icmpEchoHeaderLen || msg[0] != replyType || msg[1] != 0 {
			continue
		}
		if fa, ok := netipFrom(from); !ok || fa != dst.WithZone("") {
			continue
		}
		seq := binary.BigEndian.Uint16(msg[6:])
		id, ok := pend.lookup(seq)
		if !ok {
			continue // late or unsolicited
		}
		act.touch()
		binary.BigEndian.PutUint16(msg[4:], id)
		msg[2], msg[3] = 0, 0 // the receiver recomputes it
		if _, err := f.Write(msg); err != nil {
			break
		}
	}
	f.Close()
	c.Close()
	<-done
	return ctx.Err()
}

func isClosed(err error) bool { return errors.Is(err, net.ErrClosed) }

// netipFrom returns the address of a without zone.
func netipFrom(a *net.UDPAddr) (netip.Addr, bool) {
	if a == nil {
		return netip.Addr{}, false
	}
	ip := a.AddrPort().Addr()
	return ip.Unmap().WithZone(""), ip.IsValid()
}

// pending remembers the identifier of each echo sequence number sent within
// the echo timeout. A reply to an expired or unknown sequence is dropped;
// duplicate replies within the timeout pass, as they would on the wire.
type pending struct {
	timeout time.Duration
	mu      sync.Mutex
	m       map[uint16]pendingEcho
}

type pendingEcho struct {
	id      uint16
	expires time.Time
}

func newPending(timeout time.Duration) *pending {
	return &pending{timeout: timeout, m: make(map[uint16]pendingEcho)}
}

func (p *pending) add(seq, id uint16) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.m) >= 1024 {
		for s, e := range p.m {
			if now.After(e.expires) {
				delete(p.m, s)
			}
		}
	}
	p.m[seq] = pendingEcho{id: id, expires: now.Add(p.timeout)}
}

func (p *pending) lookup(seq uint16) (uint16, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[seq]
	if !ok {
		return 0, false
	}
	if time.Now().After(e.expires) {
		delete(p.m, seq)
		return 0, false
	}
	return e.id, true
}

// activity records the time of the last message either way.
type activity struct{ last atomic.Int64 }

func newActivity() *activity {
	a := &activity{}
	a.touch()
	return a
}

func (a *activity) touch() { a.last.Store(time.Now().UnixNano()) }

func (a *activity) idleFor() time.Duration {
	return time.Duration(time.Now().UnixNano() - a.last.Load())
}
