// Package egress delivers a flow on the local host: TCP and UDP are dialed
// through the kernel, ICMP echo is sent as real echo requests through
// unprivileged ping sockets.
package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xiongyumail/tunx/internal/core"
)

// SourceMode selects the source address of delivered traffic.
type SourceMode int

const (
	// SourceSNAT dials from the host's own address.
	SourceSNAT SourceMode = iota
	// SourcePreserve dials from the flow's original source address with
	// IP_TRANSPARENT / IPV6_TRANSPARENT, which needs CAP_NET_ADMIN. The
	// source port is not preserved. Replies only come back if the network
	// routes the source prefix to this host.
	SourcePreserve
)

func (m SourceMode) String() string {
	switch m {
	case SourceSNAT:
		return "snat"
	case SourcePreserve:
		return "preserve"
	}
	return fmt.Sprintf("SourceMode(%d)", int(m))
}

// Defaults for zero Options fields.
const (
	DefaultDialTimeout = 10 * time.Second
	DefaultIdleTimeout = 60 * time.Second
	DefaultEchoTimeout = 10 * time.Second
)

// Options control delivery.
type Options struct {
	Source SourceMode
	// Interface binds sockets to a device (SO_BINDTODEVICE).
	Interface string
	// Mark sets SO_MARK on sockets, so policy routing can tell this
	// traffic apart. Zero leaves it unset.
	Mark uint32
	// DialTimeout bounds a TCP connect.
	DialTimeout time.Duration
	// IdleTimeout ends a UDP or ICMP flow with no traffic either way.
	IdleTimeout time.Duration
	// EchoTimeout is how long an echo request waits for its reply; later
	// replies are dropped.
	EchoTimeout time.Duration
}

func (o Options) withDefaults() Options {
	if o.DialTimeout <= 0 {
		o.DialTimeout = DefaultDialTimeout
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = DefaultIdleTimeout
	}
	if o.EchoTimeout <= 0 {
		o.EchoTimeout = DefaultEchoTimeout
	}
	return o
}

// ErrPreserveNotPermitted is returned when SourcePreserve is requested
// without CAP_NET_ADMIN.
var ErrPreserveNotPermitted = errors.New("egress: source mode preserve needs CAP_NET_ADMIN (IP_TRANSPARENT)")

// ErrPingNotPermitted is returned when the process may not open ping sockets
// (see sysctl net.ipv4.ping_group_range).
var ErrPingNotPermitted = errors.New("egress: ping sockets not permitted (net.ipv4.ping_group_range)")

// Deliver sends flow f to meta.Dst from this host and pumps data both ways
// until either side finishes, the flow idles out, or ctx is cancelled. It
// accepts f (core.Accept) once the socket toward the destination is
// connected, refuses it (core.Refuse, see ReasonFor) when that fails, and
// always closes f.
func Deliver(ctx context.Context, meta core.FlowMeta, f core.Flow, opts Options) error {
	defer f.Close()
	opts = opts.withDefaults()
	switch meta.Proto {
	case core.ProtoTCP:
		c, err := DialTCP(ctx, meta, opts)
		if err != nil {
			core.Refuse(f, ReasonFor(err))
			return err
		}
		if err := core.Accept(f); err != nil {
			c.Close()
			return err
		}
		return pumpStream(ctx, f, c)
	case core.ProtoUDP:
		c, err := DialUDP(ctx, meta, opts)
		if err != nil {
			core.Refuse(f, ReasonFor(err))
			return err
		}
		if err := core.Accept(f); err != nil {
			c.Close()
			return err
		}
		return pumpDatagram(ctx, f, c, opts.IdleTimeout)
	case core.ProtoICMP, core.ProtoICMPv6:
		return deliverEcho(ctx, meta, f, opts)
	}
	core.Refuse(f, core.ReasonError)
	return fmt.Errorf("egress: unsupported protocol %v", meta.Proto)
}

// ReasonFor maps a delivery error to the reason a flow is refused with:
// a reset from the destination is core.ReasonRefused, an unreachable
// destination or a connect timeout core.ReasonUnreachable, anything else
// core.ReasonError.
func ReasonFor(err error) core.Reason {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return core.ReasonRefused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.ETIMEDOUT), isTimeout(err):
		return core.ReasonUnreachable
	}
	return core.ReasonError
}

// DialTCP connects to meta.Dst.
func DialTCP(ctx context.Context, meta core.FlowMeta, opts Options) (*net.TCPConn, error) {
	opts = opts.withDefaults()
	c, err := dial(ctx, "tcp", meta, opts)
	if err != nil {
		return nil, err
	}
	return c.(*net.TCPConn), nil
}

// DialUDP returns a UDP socket connected to meta.Dst.
func DialUDP(ctx context.Context, meta core.FlowMeta, opts Options) (*net.UDPConn, error) {
	opts = opts.withDefaults()
	c, err := dial(ctx, "udp", meta, opts)
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

func dial(ctx context.Context, network string, meta core.FlowMeta, opts Options) (net.Conn, error) {
	dst := netip.AddrPortFrom(meta.Dst.Addr().Unmap(), meta.Dst.Port())
	v6 := dst.Addr().Is6()
	if v6 {
		network += "6"
	} else {
		network += "4"
	}
	d := net.Dialer{
		Timeout: opts.DialTimeout,
		Control: controlFunc(opts, v6),
	}
	if opts.Source == SourcePreserve {
		src, err := preserveSource(meta, v6)
		if err != nil {
			return nil, err
		}
		if network[:3] == "tcp" {
			d.LocalAddr = &net.TCPAddr{IP: src.AsSlice(), Zone: src.Zone()}
		} else {
			d.LocalAddr = &net.UDPAddr{IP: src.AsSlice(), Zone: src.Zone()}
		}
	}
	c, err := d.DialContext(ctx, network, dst.String())
	if err != nil {
		var serr *sockoptError
		if errors.As(err, &serr) {
			return nil, serr.err
		}
		return nil, err
	}
	return c, nil
}

func preserveSource(meta core.FlowMeta, v6 bool) (netip.Addr, error) {
	src := meta.Src.Addr().Unmap()
	if !src.IsValid() || src.Is6() != v6 {
		return netip.Addr{}, fmt.Errorf("egress: cannot preserve source %v toward %v: address families differ", meta.Src.Addr(), meta.Dst.Addr())
	}
	return src, nil
}

// sockoptError carries a setsockopt failure through net.Dialer, which would
// otherwise wrap it beyond recognition.
type sockoptError struct{ err error }

func (e *sockoptError) Error() string { return e.err.Error() }
func (e *sockoptError) Unwrap() error { return e.err }

func controlFunc(opts Options, v6 bool) func(string, string, syscall.RawConn) error {
	return func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) { serr = setSockopts(int(fd), opts, v6) }); err != nil {
			return err
		}
		if serr != nil {
			return &sockoptError{serr}
		}
		return nil
	}
}

// setSockopts applies the source mode, interface and mark to a socket before
// it is bound or connected.
func setSockopts(fd int, opts Options, v6 bool) error {
	if opts.Source == SourcePreserve {
		var err error
		if v6 {
			err = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		} else {
			err = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		}
		if errors.Is(err, unix.EPERM) {
			return ErrPreserveNotPermitted
		}
		if err != nil {
			return fmt.Errorf("egress: set transparent: %w", err)
		}
	}
	if opts.Interface != "" {
		if err := unix.BindToDevice(fd, opts.Interface); err != nil {
			return fmt.Errorf("egress: bind to device %q: %w", opts.Interface, err)
		}
	}
	if opts.Mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(opts.Mark)); err != nil {
			return fmt.Errorf("egress: set mark %#x: %w", opts.Mark, err)
		}
	}
	return nil
}

// pumpStream copies both ways and propagates half-close: EOF from one side
// becomes CloseWrite on the other.
func pumpStream(ctx context.Context, f core.Flow, c *net.TCPConn) error {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() {
		c.Close()
		f.Close()
	})
	defer stop()

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(c, f)
		if err == nil {
			err = c.CloseWrite()
		}
		errc <- err
	}()
	go func() {
		_, err := io.Copy(f, c)
		if err == nil {
			err = f.CloseWrite()
		}
		errc <- err
	}()
	var first error
	for range 2 {
		if err := <-errc; err != nil {
			// An error on one side ends both.
			c.Close()
			f.Close()
			if first == nil {
				first = err
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return first
}

// maxDatagram is large enough for any UDP payload or ICMP message.
const maxDatagram = 65535

// pumpDatagram relays messages between f and a connected socket until
// neither side has sent anything for idle.
func pumpDatagram(ctx context.Context, f core.Flow, c *net.UDPConn, idle time.Duration) error {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() {
		c.Close()
		f.Close()
	})
	defer stop()

	act := newActivity()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, maxDatagram)
		for {
			n, err := f.Read(buf)
			if err != nil {
				c.Close() // flow ended: stop the reader below
				return
			}
			act.touch()
			if _, err := c.Write(buf[:n]); err != nil && !transient(err) {
				c.Close()
				return
			}
		}
	}()

	buf := make([]byte, maxDatagram)
	var err error
	for {
		c.SetReadDeadline(time.Now().Add(idle))
		var n int
		n, err = c.Read(buf)
		if err != nil {
			if isTimeout(err) {
				if act.idleFor() < idle {
					continue
				}
				err = nil
				break
			}
			if transient(err) {
				continue
			}
			break
		}
		act.touch()
		if _, werr := f.Write(buf[:n]); werr != nil {
			break
		}
	}
	f.Close()
	c.Close()
	<-done
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// transient reports errors from ICMP feedback on a connected UDP socket,
// which must not end the flow.
func transient(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EMSGSIZE)
}
