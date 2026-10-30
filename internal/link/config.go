// Package link implements the session between two tunxd nodes: mutual
// authentication by node key, a multiplexed session over any net.Conn, stream
// headers that carry core.FlowMeta, flow framing, keepalive and control
// messages. The wire format is specified in docs/protocol.md.
package link

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Defaults for the zero values of Config.
const (
	DefaultHandshakeTimeout  = 10 * time.Second
	DefaultKeepaliveInterval = 5 * time.Second
	DefaultKeepaliveTimeout  = 15 * time.Second
	DefaultMaxReceiveBuffer  = 16 << 20
	// The stream buffer is the flow-control window of one flow: about half
	// of it is in flight, so 4 MiB allows some 200 Mbit/s at 80 ms RTT
	// (1 MiB capped a flow at 52 Mbit/s).
	DefaultMaxStreamBuffer = 4 << 20
)

// Limits of the wire format.
const (
	MaxNameLen     = 64    // node name and network ID, bytes
	MaxIdentityLen = 255   // FlowMeta.Identity, bytes
	MaxDatagram    = 65535 // one datagram message, bytes
	MaxControlLen  = 1 << 20
)

// Errors returned by sessions and flows.
var (
	ErrAuth            = errors.New("link: peer authentication failed")
	ErrUnknownPeer     = errors.New("link: unknown peer")
	ErrNetworkMismatch = errors.New("link: network mismatch")
	ErrVersion         = errors.New("link: no common protocol version")
	ErrRejected        = errors.New("link: handshake rejected by peer")
	ErrProtocol        = errors.New("link: protocol violation")
	ErrClosed          = errors.New("link: session closed")
	ErrKeepalive       = errors.New("link: keepalive timeout")
	ErrFlowReset       = errors.New("link: flow reset by peer")
	ErrMessageTooLarge = errors.New("link: message too large")
)

// Config configures one end of a link. The same Config may be used for many
// sessions.
type Config struct {
	// Network is the overlay network ID. Both ends must agree.
	Network string
	// Name is this node's name, at most MaxNameLen bytes.
	Name string
	// PrivateKey is this node's ed25519 key.
	PrivateKey ed25519.PrivateKey
	// Peers maps the names of nodes this end accepts to their public keys.
	// A dialer that expects one specific peer lists only that peer.
	Peers map[string]ed25519.PublicKey

	// HandshakeTimeout bounds the handshake and the reading of each stream
	// header.
	HandshakeTimeout time.Duration
	// KeepaliveInterval is how often a ping is sent on the control stream.
	KeepaliveInterval time.Duration
	// KeepaliveTimeout closes after this long without an underlying
	// transport read returning bytes. Checks run every max(timeout/8, 1 ms).
	KeepaliveTimeout time.Duration

	// MaxReceiveBuffer and MaxStreamBuffer size the multiplexer buffers for
	// the whole session and for one stream.
	MaxReceiveBuffer int
	MaxStreamBuffer  int

	// OnControl receives application control messages (type >=
	// MinControlType). It runs on the control stream reader and must not
	// block for long.
	OnControl func(s *Session, typ uint8, payload []byte)

	// Logger receives session events. Nil discards them.
	Logger *slog.Logger

	// maxVersion caps the offered protocol version (tests only); zero
	// means ProtocolVersion.
	maxVersion uint8
}

// highest returns the highest protocol version this end speaks.
func (c *Config) highest() uint8 {
	if c.maxVersion != 0 {
		return c.maxVersion
	}
	return ProtocolVersion
}

func (c Config) withDefaults() Config {
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if c.KeepaliveInterval <= 0 {
		c.KeepaliveInterval = DefaultKeepaliveInterval
	}
	if c.KeepaliveTimeout <= 0 {
		c.KeepaliveTimeout = DefaultKeepaliveTimeout
	}
	if c.MaxReceiveBuffer <= 0 {
		c.MaxReceiveBuffer = DefaultMaxReceiveBuffer
	}
	if c.MaxStreamBuffer <= 0 {
		c.MaxStreamBuffer = DefaultMaxStreamBuffer
	}
	if c.MaxStreamBuffer > c.MaxReceiveBuffer {
		c.MaxStreamBuffer = c.MaxReceiveBuffer
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	return c
}

func (c *Config) validate() error {
	if c.Name == "" || len(c.Name) > MaxNameLen {
		return fmt.Errorf("link: node name must be 1..%d bytes", MaxNameLen)
	}
	if len(c.Network) > MaxNameLen {
		return fmt.Errorf("link: network ID longer than %d bytes", MaxNameLen)
	}
	if len(c.PrivateKey) != ed25519.PrivateKeySize {
		return errors.New("link: invalid private key")
	}
	if len(c.Peers) == 0 {
		return errors.New("link: no peers configured")
	}
	for name, key := range c.Peers {
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("link: invalid public key for peer %q", name)
		}
	}
	return nil
}
