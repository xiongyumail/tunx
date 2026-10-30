package link

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Protocol versions this implementation speaks.
const (
	ProtocolVersion uint8 = 2
	minVersion      uint8 = 1
)

// versionAnswer is the first version in which the acceptor of a flow answers
// whether it opened (docs/protocol.md, "Open answer").
const versionAnswer uint8 = 2

const (
	magic           = "TUNX"
	nonceSize       = 32
	maxHandshakeMsg = 2048
	maxExtensions   = 1024

	labelTranscript = "tunx link transcript"
	labelServerSig  = "tunx link server signature"
	labelClientSig  = "tunx link client signature"

	acceptOK = 0
)

// hello is the common part of ClientHello and ServerHello.
type hello struct {
	version uint8
	network string // ClientHello only
	name    string
	nonce   [nonceSize]byte
	ext     []byte
}

func (h *hello) encode(client bool) []byte {
	b := make([]byte, 0, 128)
	b = append(b, magic...)
	b = append(b, h.version)
	if client {
		b = appendStr8(b, h.network)
	}
	b = appendStr8(b, h.name)
	b = append(b, h.nonce[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.ext)))
	return append(b, h.ext...)
}

func parseHello(b []byte, client bool) (*hello, error) {
	p := parser{b: b}
	h := &hello{}
	if string(p.bytes(len(magic))) != magic {
		return nil, fmt.Errorf("%w: bad magic", ErrProtocol)
	}
	h.version = p.u8()
	if client {
		h.network = p.str8()
	}
	h.name = p.str8()
	copy(h.nonce[:], p.bytes(nonceSize))
	h.ext = p.bytes(int(p.u16()))
	if p.bad || len(p.b) != 0 {
		return nil, fmt.Errorf("%w: malformed hello", ErrProtocol)
	}
	if h.name == "" || len(h.name) > MaxNameLen || len(h.network) > MaxNameLen || len(h.ext) > maxExtensions {
		return nil, fmt.Errorf("%w: hello field out of range", ErrProtocol)
	}
	return h, nil
}

// transcriptHash binds the whole handshake: both hellos, and with them both
// nonces, both names, the network ID, the versions and the extensions.
func transcriptHash(clientHello, serverHello []byte) []byte {
	h := sha256.New()
	h.Write([]byte(labelTranscript))
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(clientHello)))
	h.Write(l[:])
	h.Write(clientHello)
	binary.BigEndian.PutUint16(l[:], uint16(len(serverHello)))
	h.Write(l[:])
	h.Write(serverHello)
	return h.Sum(nil)
}

func signedMessage(label string, th []byte) []byte {
	m := make([]byte, 0, len(label)+1+len(th))
	m = append(m, label...)
	m = append(m, 0)
	return append(m, th...)
}

// clientHandshake runs the dialing side. It returns the peer name and the
// negotiated version.
func clientHandshake(rw io.ReadWriter, cfg *Config) (string, uint8, error) {
	ch := hello{version: cfg.highest(), network: cfg.Network, name: cfg.Name}
	rand.Read(ch.nonce[:])
	chBytes := ch.encode(true)
	if err := writeMsg(rw, chBytes); err != nil {
		return "", 0, err
	}

	msg, err := readMsg(rw)
	if errors.Is(err, io.EOF) {
		// The server closes without a reply when it refuses the hello.
		return "", 0, fmt.Errorf("%w: %v", ErrRejected, err)
	} else if err != nil {
		return "", 0, err
	}
	if len(msg) < ed25519.SignatureSize {
		return "", 0, fmt.Errorf("%w: short server hello", ErrProtocol)
	}
	shBytes, sig := msg[:len(msg)-ed25519.SignatureSize], msg[len(msg)-ed25519.SignatureSize:]
	sh, err := parseHello(shBytes, false)
	if err != nil {
		return "", 0, err
	}
	if sh.version < minVersion || sh.version > cfg.highest() {
		return "", 0, ErrVersion
	}
	key, ok := cfg.Peers[sh.name]
	if !ok {
		return "", 0, fmt.Errorf("%w: %q", ErrUnknownPeer, sh.name)
	}
	th := transcriptHash(chBytes, shBytes)
	if !ed25519.Verify(key, signedMessage(labelServerSig, th), sig) {
		return "", 0, ErrAuth
	}

	if err := writeMsg(rw, ed25519.Sign(cfg.PrivateKey, signedMessage(labelClientSig, th))); err != nil {
		return "", 0, err
	}
	acc, err := readMsg(rw)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if len(acc) != 1 || acc[0] != acceptOK {
		return "", 0, ErrRejected
	}
	return sh.name, sh.version, nil
}

// serverHandshake runs the accepting side.
func serverHandshake(rw io.ReadWriter, cfg *Config) (string, uint8, error) {
	chBytes, err := readMsg(rw)
	if err != nil {
		return "", 0, err
	}
	ch, err := parseHello(chBytes, true)
	if err != nil {
		return "", 0, err
	}
	version := min(ch.version, cfg.highest())
	if version < minVersion {
		return "", 0, ErrVersion
	}
	if ch.network != cfg.Network {
		return "", 0, fmt.Errorf("%w: %q", ErrNetworkMismatch, ch.network)
	}
	key, ok := cfg.Peers[ch.name]
	if !ok {
		return "", 0, fmt.Errorf("%w: %q", ErrUnknownPeer, ch.name)
	}

	sh := hello{version: version, name: cfg.Name}
	rand.Read(sh.nonce[:])
	shBytes := sh.encode(false)
	th := transcriptHash(chBytes, shBytes)
	sig := ed25519.Sign(cfg.PrivateKey, signedMessage(labelServerSig, th))
	if err := writeMsg(rw, append(shBytes, sig...)); err != nil {
		return "", 0, err
	}

	fin, err := readMsg(rw)
	if err != nil {
		return "", 0, err
	}
	if len(fin) != ed25519.SignatureSize || !ed25519.Verify(key, signedMessage(labelClientSig, th), fin) {
		return "", 0, ErrAuth
	}
	if err := writeMsg(rw, []byte{acceptOK}); err != nil {
		return "", 0, err
	}
	return ch.name, version, nil
}

// writeMsg writes one length-prefixed handshake message in a single Write.
func writeMsg(w io.Writer, body []byte) error {
	b := make([]byte, 2, 2+len(body))
	binary.BigEndian.PutUint16(b, uint16(len(body)))
	_, err := w.Write(append(b, body...))
	return err
}

func readMsg(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n > maxHandshakeMsg {
		return nil, fmt.Errorf("%w: handshake message too large", ErrProtocol)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func appendStr8(b []byte, s string) []byte {
	b = append(b, byte(len(s)))
	return append(b, s...)
}

// parser reads big-endian fields; any short read sets bad.
type parser struct {
	b   []byte
	bad bool
}

func (p *parser) bytes(n int) []byte {
	if n > len(p.b) {
		p.bad = true
		p.b = nil
		return nil
	}
	v := p.b[:n]
	p.b = p.b[n:]
	return v
}

func (p *parser) u8() uint8 {
	if b := p.bytes(1); b != nil {
		return b[0]
	}
	return 0
}

func (p *parser) u16() uint16 {
	if b := p.bytes(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func (p *parser) str8() string { return string(p.bytes(int(p.u8()))) }
