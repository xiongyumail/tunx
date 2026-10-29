package link

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/xiongyumail/tunx/internal/core"
	"github.com/xtaci/smux"
)

const (
	muxFrameSize = 32768
	// tcpChunk makes one framed chunk fill exactly one multiplexer frame.
	tcpChunk     = muxFrameSize - 2
	closeTimeout = 2 * time.Second
)

var bufPool = sync.Pool{New: func() any {
	b := make([]byte, 2+MaxDatagram)
	return &b
}}

// newFlow wraps a stream whose header has been sent or read. Both flow types
// also have SetDeadline, SetReadDeadline and SetWriteDeadline.
func newFlow(st *smux.Stream, proto core.Proto) core.Flow {
	if proto.IsDatagram() {
		return &datagramFlow{st: st}
	}
	return &tcpFlow{st: st}
}

// tcpFlow carries a byte stream as chunks: a 2-byte length and that many
// bytes. A zero length is the end-of-stream marker sent by CloseWrite. A
// multiplexer FIN means the peer closed the flow entirely; seen before the
// marker it is a reset.
type tcpFlow struct {
	st *smux.Stream

	rmu    sync.Mutex // serializes readers
	remain int        // bytes left in the current chunk
	eof    bool       // marker read; guarded by rmu

	wmu   sync.Mutex // serializes writers
	wdone bool       // marker sent; guarded by wmu

	mu       sync.Mutex // guards the two flags below
	readEOF  bool
	wrClosed bool

	closeOnce sync.Once
}

func (f *tcpFlow) Read(p []byte) (int, error) {
	f.rmu.Lock()
	defer f.rmu.Unlock()
	if f.eof {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	for f.remain == 0 {
		var h [2]byte
		if _, err := io.ReadFull(f.st, h[:]); err != nil {
			return 0, streamErr(err)
		}
		f.remain = int(binary.BigEndian.Uint16(h[:]))
		if f.remain == 0 {
			f.eof = true
			f.mu.Lock()
			f.readEOF = true
			both := f.wrClosed
			f.mu.Unlock()
			if both {
				f.st.Close()
			} else {
				go f.awaitPeerClose()
			}
			return 0, io.EOF
		}
	}
	if len(p) > f.remain {
		p = p[:f.remain]
	}
	n, err := f.st.Read(p)
	f.remain -= n
	if err != nil {
		return n, streamErr(err)
	}
	return n, nil
}

// awaitPeerClose runs after the marker was read. Nothing more may arrive, so
// the next stream event is the peer's FIN or the local close; either way the
// stream is closed so that further local writes fail instead of filling a
// window nobody reads.
func (f *tcpFlow) awaitPeerClose() {
	var b [1]byte
	f.st.Read(b[:])
	f.st.Close()
}

func (f *tcpFlow) Write(p []byte) (int, error) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if f.wdone {
		return 0, io.ErrClosedPipe
	}
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	written := 0
	for len(p) > 0 {
		n := min(len(p), tcpChunk)
		binary.BigEndian.PutUint16(buf, uint16(n))
		copy(buf[2:], p[:n])
		if _, err := f.st.Write(buf[:2+n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite sends the end-of-stream marker. The peer reads io.EOF; the other
// direction keeps flowing.
func (f *tcpFlow) CloseWrite() error {
	f.wmu.Lock()
	if f.wdone {
		f.wmu.Unlock()
		return nil
	}
	f.wdone = true
	_, err := f.st.Write([]byte{0, 0})
	f.wmu.Unlock()

	f.mu.Lock()
	f.wrClosed = true
	both := f.readEOF
	f.mu.Unlock()
	if both {
		f.st.Close()
	}
	return err
}

// Close sends the end-of-stream marker if it has not been sent and no write
// is in progress, then closes the stream. Data the peer sends afterwards is
// discarded and its writes fail, like a TCP close.
func (f *tcpFlow) Close() error {
	f.closeOnce.Do(func() {
		if f.wmu.TryLock() {
			if !f.wdone {
				f.wdone = true
				f.st.SetWriteDeadline(time.Now().Add(closeTimeout))
				f.st.Write([]byte{0, 0})
			}
			f.wmu.Unlock()
		}
		f.st.Close()
	})
	return nil
}

func (f *tcpFlow) SetDeadline(t time.Time) error      { return f.st.SetDeadline(t) }
func (f *tcpFlow) SetReadDeadline(t time.Time) error  { return f.st.SetReadDeadline(t) }
func (f *tcpFlow) SetWriteDeadline(t time.Time) error { return f.st.SetWriteDeadline(t) }

// streamErr maps a stream ending without the end-of-stream marker to
// ErrFlowReset.
func streamErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrFlowReset
	}
	return err
}

// datagramFlow carries messages, each a 2-byte length and the payload.
type datagramFlow struct {
	st  *smux.Stream
	rmu sync.Mutex
	wmu sync.Mutex
}

// Read returns one message. A message longer than p is truncated, like a UDP
// socket.
func (f *datagramFlow) Read(p []byte) (int, error) {
	f.rmu.Lock()
	defer f.rmu.Unlock()
	var h [2]byte
	if _, err := io.ReadFull(f.st, h[:]); err != nil {
		if errors.Is(err, io.EOF) {
			// The peer closed; close too so local writes fail.
			f.st.Close()
			return 0, io.EOF
		}
		return 0, f.fail(err)
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	m := min(n, len(p))
	if _, err := io.ReadFull(f.st, p[:m]); err != nil {
		return 0, f.fail(err)
	}
	if n > m {
		if _, err := io.CopyN(io.Discard, f.st, int64(n-m)); err != nil {
			return 0, f.fail(err)
		}
	}
	return m, nil
}

// fail closes the flow after an error inside a message, since the framing
// can no longer be trusted.
func (f *datagramFlow) fail(err error) error {
	f.st.Close()
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// Write sends p as one message.
func (f *datagramFlow) Write(p []byte) (int, error) {
	if len(p) > MaxDatagram {
		return 0, ErrMessageTooLarge
	}
	bp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bp)
	buf := *bp
	binary.BigEndian.PutUint16(buf, uint16(len(p)))
	copy(buf[2:], p)
	f.wmu.Lock()
	_, err := f.st.Write(buf[:2+len(p)])
	f.wmu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (f *datagramFlow) CloseWrite() error { return f.Close() }

func (f *datagramFlow) Close() error {
	f.st.Close()
	return nil
}

func (f *datagramFlow) SetDeadline(t time.Time) error      { return f.st.SetDeadline(t) }
func (f *datagramFlow) SetReadDeadline(t time.Time) error  { return f.st.SetReadDeadline(t) }
func (f *datagramFlow) SetWriteDeadline(t time.Time) error { return f.st.SetWriteDeadline(t) }
