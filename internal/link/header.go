package link

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	"github.com/xiongyumail/tunx/internal/core"
)

// Stream header: version, type, body length, body.
const (
	headerVersion = 1
	maxHeaderBody = 1024

	streamControl uint8 = 1
	streamFlow    uint8 = 2
)

const (
	famNone = 0
	famIPv4 = 4
	famIPv6 = 6
)

func encodeHeader(typ uint8, body []byte) []byte {
	b := make([]byte, 0, 4+len(body))
	b = append(b, headerVersion, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
	return append(b, body...)
}

func encodeFlowMeta(m core.FlowMeta) ([]byte, error) {
	if len(m.Identity) > MaxIdentityLen {
		return nil, fmt.Errorf("link: identity longer than %d bytes", MaxIdentityLen)
	}
	b := make([]byte, 0, 48+len(m.Identity))
	b = append(b, byte(m.Proto), m.Hops)
	b = appendAddrPort(b, m.Src)
	b = appendAddrPort(b, m.Dst)
	b = appendStr8(b, m.Identity)
	return b, nil
}

func appendAddrPort(b []byte, ap netip.AddrPort) []byte {
	a := ap.Addr()
	switch {
	case !a.IsValid():
		b = append(b, famNone)
	case a.Is4():
		b = append(b, famIPv4)
		b = append(b, a.AsSlice()...)
	default:
		b = append(b, famIPv6)
		b16 := a.As16()
		b = append(b, b16[:]...)
	}
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

func parseAddrPort(p *parser) netip.AddrPort {
	var a netip.Addr
	switch p.u8() {
	case famNone:
	case famIPv4:
		if b := p.bytes(4); b != nil {
			a = netip.AddrFrom4([4]byte(b))
		}
	case famIPv6:
		if b := p.bytes(16); b != nil {
			a = netip.AddrFrom16([16]byte(b))
		}
	default:
		p.bad = true
	}
	return netip.AddrPortFrom(a, p.u16())
}

// parseFlowMeta decodes a flow header body. Bytes after the known fields are
// ignored so later versions can append fields.
func parseFlowMeta(body []byte) (core.FlowMeta, error) {
	p := parser{b: body}
	var m core.FlowMeta
	m.Proto = core.Proto(p.u8())
	m.Hops = p.u8()
	m.Src = parseAddrPort(&p)
	m.Dst = parseAddrPort(&p)
	m.Identity = p.str8()
	if p.bad {
		return core.FlowMeta{}, fmt.Errorf("%w: malformed flow header", ErrProtocol)
	}
	return m, nil
}

// readHeader reads a stream header and returns its type and body.
func readHeader(r io.Reader) (uint8, []byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	if h[0] != headerVersion {
		return 0, nil, fmt.Errorf("%w: stream header version %d", ErrProtocol, h[0])
	}
	n := int(binary.BigEndian.Uint16(h[2:]))
	if n > maxHeaderBody {
		return 0, nil, fmt.Errorf("%w: stream header too large", ErrProtocol)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return h[1], body, nil
}
