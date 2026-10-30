package link

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xiongyumail/tunx/internal/core"
)

func udpMeta() core.FlowMeta {
	return core.FlowMeta{
		Proto:    core.ProtoUDP,
		Src:      netip.MustParseAddrPort("10.0.0.1:5353"),
		Dst:      netip.MustParseAddrPort("10.0.1.1:53"),
		Identity: "node-a",
	}
}

// answerHandler answers every flow according to its destination port:
// 1 accepts and echoes, 2 refuses with ReasonRefused after reading one
// message or chunk, 3 closes without an answer, 4 never answers.
var answerHandler = core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
	defer f.Close()
	switch meta.Dst.Port() {
	case 1:
		if err := core.Accept(f); err != nil {
			return
		}
		echoHandler(ctx, meta, f, in)
	case 2:
		buf := make([]byte, 64)
		f.Read(buf)
		core.Refuse(f, core.ReasonRefused)
	case 3:
	case 4:
		<-ctx.Done()
	}
})

func withPort(m core.FlowMeta, port uint16) core.FlowMeta {
	m.Dst = netip.AddrPortFrom(m.Dst.Addr(), port)
	return m
}

func wantRefused(t *testing.T, err error, r core.Reason) {
	t.Helper()
	var oe *core.OpenError
	if !errors.As(err, &oe) || oe.Reason != r {
		t.Fatalf("got %v, want a refusal with %v", err, r)
	}
}

func TestOpenAnswer(t *testing.T) {
	cc, sc := testConfigs(t)
	c1, c2 := tcpPair(t)
	cs, ss := sessionPair(t, cc, sc, c1, c2, nil, answerHandler)
	if cs.Version() != ProtocolVersion || ss.Version() != ProtocolVersion {
		t.Fatalf("versions %d %d", cs.Version(), ss.Version())
	}
	ctx := context.Background()

	for _, meta := range []core.FlowMeta{tcpMeta(), udpMeta()} {
		t.Run(meta.Proto.String(), func(t *testing.T) {
			// Accepted: WaitOpen returns nil and data flows.
			f, err := cs.OpenFlow(ctx, withPort(meta, 1))
			if err != nil {
				t.Fatal(err)
			}
			if err := WaitOpen(ctx, f); err != nil {
				t.Fatalf("WaitOpen: %v", err)
			}
			f.Write([]byte("hi"))
			buf := make([]byte, 16)
			if n, err := f.Read(buf); err != nil || string(buf[:n]) != "hi" {
				t.Fatalf("echo %q %v", buf[:n], err)
			}
			f.Close()

			// Refused after data was sent ahead of the answer: the
			// reason reaches the opener, through Read as well.
			f, _ = cs.OpenFlow(ctx, withPort(meta, 2))
			f.Write([]byte("early"))
			wantRefused(t, WaitOpen(ctx, f), core.ReasonRefused)
			_, err = f.Read(buf)
			wantRefused(t, err, core.ReasonRefused)
			f.Close()

			f, _ = cs.OpenFlow(ctx, withPort(meta, 2))
			f.Write([]byte("early"))
			_, err = f.Read(buf)
			wantRefused(t, err, core.ReasonRefused)
			f.Close()

			// Closed without an answer.
			f, _ = cs.OpenFlow(ctx, withPort(meta, 3))
			wantRefused(t, WaitOpen(ctx, f), core.ReasonError)
			f.Close()

			// No answer: WaitOpen gives up with the context.
			f, _ = cs.OpenFlow(ctx, withPort(meta, 4))
			wctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			err = WaitOpen(wctx, f)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("WaitOpen without an answer: %v", err)
			}
			f.Close()
		})
	}
}

// A TCP flow refused after it was accepted is reset, not refused.
func TestRefuseAfterAccept(t *testing.T) {
	cc, sc := testConfigs(t)
	h := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
		f.Write([]byte("x"))
		core.Refuse(f, core.ReasonDenied)
	})
	c1, c2 := net.Pipe()
	cs, _ := sessionPair(t, cc, sc, c1, c2, nil, h)
	f, err := cs.OpenFlow(context.Background(), tcpMeta())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := WaitOpen(context.Background(), f); err != nil {
		t.Fatalf("WaitOpen: %v", err)
	}
	got, err := io.ReadAll(f)
	if string(got) != "x" || !errors.Is(err, ErrFlowReset) {
		t.Fatalf("read %q, %v; want x and a reset", got, err)
	}
}

// A version 2 node speaks version 1 with an older peer: no answers, a
// refusal is a plain close.
func TestVersion1Peer(t *testing.T) {
	for _, oldClient := range []bool{true, false} {
		cc, sc := testConfigs(t)
		if oldClient {
			cc.maxVersion = 1
		} else {
			sc.maxVersion = 1
		}
		c1, c2 := net.Pipe()
		cs, ss := sessionPair(t, cc, sc, c1, c2, nil, answerHandler)
		if cs.Version() != 1 || ss.Version() != 1 {
			t.Fatalf("versions %d %d, want 1", cs.Version(), ss.Version())
		}
		ctx := context.Background()
		f, err := cs.OpenFlow(ctx, withPort(tcpMeta(), 1))
		if err != nil {
			t.Fatal(err)
		}
		if err := WaitOpen(ctx, f); err != nil {
			t.Fatalf("WaitOpen: %v", err)
		}
		f.Write([]byte("v1"))
		f.CloseWrite()
		if got, err := io.ReadAll(f); string(got) != "v1" || err != nil {
			t.Fatalf("echo %q %v", got, err)
		}
		f.Close()

		f, _ = cs.OpenFlow(ctx, withPort(tcpMeta(), 2))
		f.Write([]byte("x"))
		// Version 1 has no refusal: the flow just ends without data.
		if got, err := io.ReadAll(f); len(got) != 0 || !errors.Is(err, ErrFlowReset) {
			t.Fatalf("refused v1 flow read %q %v, want a reset", got, err)
		}
		f.Close()
		cs.Close()
		ss.Close()
	}
}

func TestUnknownOpenAnswer(t *testing.T) {
	for _, proto := range []core.Proto{core.ProtoTCP, core.ProtoUDP} {
		t.Run(proto.String(), func(t *testing.T) {
			cc, sc := testConfigs(t)
			h := core.HandlerFunc(func(ctx context.Context, meta core.FlowMeta, f core.Flow, in core.Ingress) {
				defer f.Close()
				// Write a malformed wire answer without the Answerer helpers.
				switch flow := f.(type) {
				case *tcpFlow:
					flow.st.Write([]byte{255})
				case *datagramFlow:
					flow.st.Write([]byte{255})
				}
			})
			c1, c2 := tcpPair(t)
			cs, _ := sessionPair(t, cc, sc, c1, c2, nil, h)
			meta := tcpMeta()
			meta.Proto = proto
			f, err := cs.OpenFlow(context.Background(), meta)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			wantRefused(t, WaitOpen(ctx, f), core.ReasonError)
			_, err = f.Read(make([]byte, 1))
			wantRefused(t, err, core.ReasonError)
		})
	}
}
