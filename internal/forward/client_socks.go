package forward

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xiongyumail/tunx/internal/config"
	"github.com/xiongyumail/tunx/internal/core"
)

const socksHandshakeTimeout = 10 * time.Second

func (n *Node) startClientSOCKS(cfg *config.ClientSOCKS) error {
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	n.clientLn = ln
	users := make(map[string][32]byte, len(cfg.Users))
	for _, u := range cfg.Users {
		users[u.Name] = sha256.Sum256([]byte(u.Password))
	}
	n.wg.Add(1)
	go n.clientAcceptLoop(ln, users)
	return nil
}

func (n *Node) clientAcceptLoop(ln net.Listener, users map[string][32]byte) {
	defer n.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if n.ctx.Err() == nil {
				n.log.Error("client SOCKS accept failed", "addr", ln.Addr(), "err", err)
			}
			return
		}
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			stopHandshake := context.AfterFunc(n.ctx, func() { conn.Close() })
			identity, dst, err := socksHandshake(n.ctx, conn, users)
			if err != nil {
				stopHandshake()
				conn.Close()
				n.log.Debug("client SOCKS handshake failed", "remote", conn.RemoteAddr(), "err", err)
				return
			}
			if !stopHandshake() {
				conn.Close()
				return
			}
			flow := &socksFlow{Conn: conn}
			meta := core.FlowMeta{Proto: core.ProtoTCP, Src: conn.RemoteAddr().(*net.TCPAddr).AddrPort(), Dst: dst, Identity: identity}
			n.fwd.HandleFlow(n.ctx, meta, flow, core.Ingress{Kind: "client"})
		}()
	}
}

func socksHandshake(ctx context.Context, conn net.Conn, users map[string][32]byte) (string, netip.AddrPort, error) {
	if err := conn.SetDeadline(time.Now().Add(socksHandshakeTimeout)); err != nil {
		return "", netip.AddrPort{}, err
	}
	defer conn.SetDeadline(time.Time{})

	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return "", netip.AddrPort{}, err
	}
	methods := make([]byte, int(head[1]))
	if head[0] != 5 || len(methods) == 0 {
		return "", netip.AddrPort{}, errSOCKSProtocol
	}
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", netip.AddrPort{}, err
	}
	hasPassword := false
	for _, method := range methods {
		hasPassword = hasPassword || method == 2
	}
	if !hasPassword {
		_, _ = conn.Write([]byte{5, 0xff})
		return "", netip.AddrPort{}, errSOCKSAuth
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return "", netip.AddrPort{}, err
	}

	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return "", netip.AddrPort{}, err
	}
	if head[0] != 1 || head[1] == 0 {
		return "", netip.AddrPort{}, errSOCKSProtocol
	}
	name := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, name); err != nil {
		return "", netip.AddrPort{}, err
	}
	if _, err := io.ReadFull(conn, head[:1]); err != nil {
		return "", netip.AddrPort{}, err
	}
	password := make([]byte, int(head[0]))
	if len(password) == 0 {
		return "", netip.AddrPort{}, errSOCKSAuth
	}
	if _, err := io.ReadFull(conn, password); err != nil {
		return "", netip.AddrPort{}, err
	}
	want, ok := users[string(name)]
	got := sha256.Sum256(password)
	if !ok || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		_, _ = conn.Write([]byte{1, 1})
		return "", netip.AddrPort{}, errSOCKSAuth
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return "", netip.AddrPort{}, err
	}

	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return "", netip.AddrPort{}, err
	}
	if req[0] != 5 || req[2] != 0 {
		writeSOCKSReply(conn, 1)
		return "", netip.AddrPort{}, errSOCKSProtocol
	}
	if req[1] != 1 {
		writeSOCKSReply(conn, 7)
		return "", netip.AddrPort{}, errSOCKSCommand
	}
	addr, err := readSOCKSAddr(ctx, conn, req[3])
	if err != nil {
		writeSOCKSReply(conn, 4)
		return "", netip.AddrPort{}, err
	}
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return "", netip.AddrPort{}, err
	}
	return string(name), netip.AddrPortFrom(addr, binary.BigEndian.Uint16(head[:])), nil
}

func readSOCKSAddr(ctx context.Context, r io.Reader, atyp byte) (netip.Addr, error) {
	switch atyp {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return netip.Addr{}, err
		}
		return netip.AddrFrom4(b), nil
	case 4:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return netip.Addr{}, err
		}
		return netip.AddrFrom16(b).Unmap(), nil
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil || size[0] == 0 {
			return netip.Addr{}, errSOCKSProtocol
		}
		name := make([]byte, int(size[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return netip.Addr{}, err
		}
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", string(name))
		if err != nil || len(addrs) == 0 {
			return netip.Addr{}, errSOCKSResolve
		}
		return addrs[0].Unmap(), nil
	default:
		return netip.Addr{}, errSOCKSProtocol
	}
}

type socksProtocolError string

func (e socksProtocolError) Error() string { return string(e) }

const (
	errSOCKSProtocol socksProtocolError = "invalid SOCKS5 request"
	errSOCKSAuth     socksProtocolError = "SOCKS5 authentication failed"
	errSOCKSCommand  socksProtocolError = "SOCKS5 command is not supported"
	errSOCKSResolve  socksProtocolError = "SOCKS5 destination cannot be resolved"
)

type socksFlow struct {
	net.Conn
	mu       sync.Mutex
	answered bool
}

func (f *socksFlow) Accept() error { return f.answer(0) }

func (f *socksFlow) Refuse(reason core.Reason) error {
	reply := byte(1)
	switch reason {
	case core.ReasonDenied:
		reply = 2
	case core.ReasonNoRoute:
		reply = 3
	case core.ReasonUnreachable:
		reply = 4
	case core.ReasonRefused:
		reply = 5
	case core.ReasonHopLimit:
		reply = 6
	}
	err := f.answer(reply)
	f.Conn.Close()
	return err
}

func (f *socksFlow) answer(reply byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.answered {
		return nil
	}
	f.answered = true
	return writeSOCKSReply(f.Conn, reply)
}

func (f *socksFlow) CloseWrite() error {
	if c, ok := f.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return f.Conn.Close()
}

func (f *socksFlow) Close() error {
	_ = f.answer(1)
	return f.Conn.Close()
}

func writeSOCKSReply(w io.Writer, reply byte) error {
	_, err := w.Write([]byte{5, reply, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
