package forward

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xiongyumail/tunx/internal/config"
	"github.com/xiongyumail/tunx/internal/link"
	"github.com/xiongyumail/tunx/internal/netstack"
	"github.com/xiongyumail/tunx/internal/route"
)

// Options adjust a Node beyond its config, mostly for tests.
type Options struct {
	Logger *slog.Logger
	// Endpoint replaces the TUN device with a link endpoint (for example a
	// gVisor channel endpoint). The config's tun section is then not needed.
	Endpoint stack.LinkEndpoint
	// Deliver replaces egress.Deliver.
	Deliver DeliverFunc
	// Listeners are accepted on in addition to the configured ones.
	Listeners []net.Listener
	// Dial replaces dialing a peer's configured address.
	Dial func(ctx context.Context, p config.Peer) (net.Conn, error)
}

// Node is a running tunxd: listeners, dialed peers, the forwarder, the
// optional TUN capture and the status endpoint.
type Node struct {
	cfg      *config.Config
	log      *slog.Logger
	router   *route.Router
	sessions *Sessions
	fwd      *Forwarder

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	listeners []net.Listener
	stack     *netstack.Stack
	status    *http.Server
	statusLn  net.Listener

	closeOnce sync.Once
}

// Start runs a node from a validated config. It returns once listeners are
// open and dialers started.
func Start(cfg *config.Config, opts Options) (*Node, error) {
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if cfg.Key() == nil {
		return nil, errors.New("forward: config not validated (no private key)")
	}
	table, err := cfg.Table()
	if err != nil {
		return nil, err
	}
	pol, err := cfg.BuildPolicy()
	if err != nil {
		return nil, err
	}
	n := &Node{
		cfg:      cfg,
		log:      log,
		router:   route.NewRouter(table),
		sessions: NewSessions(),
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	n.fwd = NewForwarder(cfg.Node, uint8(cfg.HopLimit), n.router, pol, n.sessions, opts.Deliver, log.With("component", "forward"))

	fail := func(err error) (*Node, error) {
		n.Close()
		return nil, err
	}
	for _, l := range cfg.Listen {
		lc := net.ListenConfig{Control: sockopts("", 0, l.Congestion)}
		ln, err := lc.Listen(context.Background(), "tcp", l.Address)
		if err != nil {
			return fail(fmt.Errorf("listen %s: %w", l.Address, err))
		}
		n.listeners = append(n.listeners, ln)
	}
	n.listeners = append(n.listeners, opts.Listeners...)
	if cfg.Status != "" {
		ln, err := net.Listen("tcp", cfg.Status)
		if err != nil {
			return fail(fmt.Errorf("status listen %s: %w", cfg.Status, err))
		}
		n.statusLn = ln
		mux := http.NewServeMux()
		mux.HandleFunc("GET /status", n.serveStatus)
		n.status = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			n.status.Serve(ln)
		}()
	}
	if opts.Endpoint != nil || cfg.TUN != nil {
		nc := netstack.Config{Endpoint: opts.Endpoint, Handler: n.fwd}
		if opts.Endpoint == nil {
			nc.Name = cfg.TUN.Name
			nc.MTU = uint32(cfg.TUN.MTU)
		}
		st, err := netstack.New(nc)
		if err != nil {
			return fail(err)
		}
		n.stack = st
	}

	linkLog := log.With("component", "link")
	for _, ln := range n.listeners {
		lc := cfg.LinkConfig()
		lc.Logger = linkLog
		n.wg.Add(1)
		go n.acceptLoop(ln, lc)
	}
	for _, p := range cfg.Peers {
		if p.Dial == "" {
			continue
		}
		lc := cfg.LinkConfig(p.Name)
		lc.Logger = linkLog.With("dial", p.Name) // sessions log the authenticated peer
		dial := func(ctx context.Context) (net.Conn, error) {
			if opts.Dial != nil {
				return opts.Dial(ctx, p)
			}
			return dialPeer(ctx, p)
		}
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			link.Keep(n.ctx, dial, lc, func(s *link.Session) {
				n.sessions.Add(s, true)
				n.wg.Add(1)
				go func() {
					defer n.wg.Done()
					s.Serve(n.ctx, n.fwd)
				}()
			})
		}()
	}
	log.Info("node started", "node", cfg.Node, "network", cfg.Network, "listeners", len(n.listeners), "peers", len(cfg.Peers), "tun", n.stack != nil)
	return n, nil
}

func (n *Node) acceptLoop(ln net.Listener, lc link.Config) {
	defer n.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if n.ctx.Err() == nil {
				n.log.Error("accept failed", "addr", ln.Addr(), "err", err)
			}
			return
		}
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			s, err := link.Server(n.ctx, conn, lc)
			if err != nil {
				n.log.Info("link handshake failed", "remote", conn.RemoteAddr(), "err", err)
				return
			}
			n.sessions.Add(s, false)
			s.Serve(n.ctx, n.fwd)
			s.Close()
		}()
	}
}

// dialPeer connects to the peer's dial address, bound to its interface and
// mark and with its congestion control when configured.
func dialPeer(ctx context.Context, p config.Peer) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, Control: sockopts(p.Interface, p.Mark, p.Congestion)}
	return d.DialContext(ctx, "tcp", p.Dial)
}

// sockopts returns a socket Control function applying the interface, mark
// and congestion control that are set, or nil when none is. Accepted
// connections inherit the congestion control of their listener.
func sockopts(iface string, mark uint32, congestion string) func(string, string, syscall.RawConn) error {
	if congestion == "default" {
		congestion = ""
	}
	if iface == "" && mark == 0 && congestion == "" {
		return nil
	}
	return func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			if iface != "" {
				if serr = unix.BindToDevice(int(fd), iface); serr != nil {
					serr = fmt.Errorf("bind to device %q: %w", iface, serr)
					return
				}
			}
			if mark != 0 {
				if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark)); serr != nil {
					serr = fmt.Errorf("set mark %#x: %w", mark, serr)
					return
				}
			}
			if congestion != "" {
				if serr = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, congestion); serr != nil {
					serr = fmt.Errorf("congestion %q (see net.ipv4.tcp_available_congestion_control): %w", congestion, serr)
				}
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// Forwarder returns the node's forwarder (for injecting flows in tests).
func (n *Node) Forwarder() *Forwarder { return n.fwd }

// Sessions returns the session registry.
func (n *Node) Sessions() *Sessions { return n.sessions }

// Router returns the route table holder.
func (n *Node) Router() *route.Router { return n.router }

// ListenAddrs returns the addresses link listeners are bound to.
func (n *Node) ListenAddrs() []net.Addr {
	var out []net.Addr
	for _, ln := range n.listeners {
		out = append(out, ln.Addr())
	}
	return out
}

// StatusAddr returns the status endpoint address, or nil.
func (n *Node) StatusAddr() net.Addr {
	if n.statusLn == nil {
		return nil
	}
	return n.statusLn.Addr()
}

// Done is closed when the node is closed.
func (n *Node) Done() <-chan struct{} { return n.ctx.Done() }

// Close stops accepting and dialing, closes all sessions and flows and waits
// for the background goroutines.
func (n *Node) Close() error {
	n.closeOnce.Do(func() {
		n.cancel()
		for _, ln := range n.listeners {
			ln.Close()
		}
		if n.status != nil {
			n.status.Close()
		}
		n.sessions.CloseAll()
		if n.stack != nil {
			n.stack.Close()
		}
		n.wg.Wait()
		n.log.Info("node stopped", "node", n.cfg.Node)
	})
	return nil
}

// Status is the JSON body of GET /status.
type Status struct {
	Node     string          `json:"node"`
	Network  string          `json:"network"`
	Sessions []SessionStatus `json:"sessions"`
	Routes   []RouteStatus   `json:"routes"`
	Stats    StatsSnapshot   `json:"stats"`
}

// RouteStatus is one route and the way it currently resolves.
type RouteStatus struct {
	Prefix      string             `json:"prefix"`
	Advertisers []AdvertiserStatus `json:"advertisers"`
	// Selected is "local", "peer:<name>", or "" when unreachable.
	Selected string `json:"selected"`
}

// AdvertiserStatus is one advertiser of a route.
type AdvertiserStatus struct {
	Node     string   `json:"node"`
	Priority int      `json:"priority"`
	Via      []string `json:"via,omitempty"`
}

// Status returns the current state.
func (n *Node) Status() Status {
	st := Status{
		Node:     n.cfg.Node,
		Network:  n.cfg.Network,
		Sessions: n.sessions.Snapshot(),
		Stats:    n.fwd.stats.Snapshot(),
	}
	t := n.router.Table()
	for _, e := range t.Entries() {
		rs := RouteStatus{Prefix: e.Prefix.String()}
		for _, a := range e.Advertisers {
			rs.Advertisers = append(rs.Advertisers, AdvertiserStatus{Node: a.Node, Priority: a.Priority, Via: a.Via})
		}
		if next, ok := t.Selected(e, n.sessions.Up); ok {
			if next.Local {
				rs.Selected = "local"
			} else {
				rs.Selected = "peer:" + next.Peer
			}
		}
		st.Routes = append(st.Routes, rs)
	}
	return st
}

func (n *Node) serveStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(n.Status())
}
