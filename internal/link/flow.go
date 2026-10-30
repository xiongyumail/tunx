package link

import (
	"context"
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

// answerOpen is the open answer that accepts a flow; any other value is a
// core.Reason.
const answerOpen = 0

// newFlow wraps a stream whose header has been sent (opener) or read. With
// answers (protocol version 2) the acceptor owes the opener one answer byte
// before any data, and the opener reads it before any data. Both flow types
// also have SetDeadline, SetReadDeadline and SetWriteDeadline, and
// implement core.Answerer.
func newFlow(st *smux.Stream, proto core.Proto, answers, opener bool) core.Flow {
	a := answer{await: answers && opener, owe: answers && !opener}
	if proto.IsDatagram() {
		return &datagramFlow{st: st, ans: a}
	}
	return &tcpFlow{st: st, ans: a}
}

// WaitOpen waits for the peer's answer to a flow opened with OpenFlow: nil
// when the peer opened it, a *core.OpenError when it refused it. If ctx ends
// first, the flow is closed and ctx's error returned. Flows of version 1
// sessions, and flows from elsewhere, return nil at once.
func WaitOpen(ctx context.Context, f core.Flow) error {
	if w, ok := f.(interface{ waitOpen(context.Context) error }); ok {
		return w.waitOpen(ctx)
	}
	return nil
}

// answer is the open-answer state of a flow. await and err are guarded by
// the flow's read lock, owe by its write lock.
type answer struct {
	await bool  // opener: the answer has not been read yet
	err   error // opener: the refusal, once read
	owe   bool  // acceptor: the answer has not been sent yet
}

// read reads the answer once and returns the refusal, if any. A stream that
// ends before the answer is a refusal with core.ReasonError.
func (a *answer) read(st *smux.Stream) error {
	if !a.await {
		return a.err
	}
	var b [1]byte
	if _, err := io.ReadFull(st, b[:]); err != nil {
		if !errors.Is(err, io.EOF) {
			return err
		}
		b[0] = byte(core.ReasonError)
	}
	a.await = false
	if b[0] != answerOpen {
		r := core.Reason(b[0])
		if r < core.ReasonError || r > core.ReasonHopLimit {
			r = core.ReasonError
		}
		a.err = &core.OpenError{Reason: r}
		st.Close()
	}
	return a.err
}

// wait is read bounded by ctx.
func (a *answer) wait(ctx context.Context, st *smux.Stream) error {
	if !a.await {
		return a.err
	}
	stop := context.AfterFunc(ctx, func() { st.Close() })
	err := a.read(st)
	if !stop() {
		return ctx.Err()
	}
	return err
}

// send writes the answer if it is still owed.
func (a *answer) send(st *smux.Stream, code byte) error {
	if !a.owe {
		return nil
	}
	a.owe = false
	_, err := st.Write([]byte{code})
	return err
}

// refuse sends a refusal if no answer was sent yet, bounded by closeTimeout.
func (a *answer) refuse(st *smux.Stream, r core.Reason) {
	if !a.owe {
		return
	}
	if r == answerOpen {
		r = core.ReasonError
	}
	st.SetWriteDeadline(time.Now().Add(closeTimeout))
	a.send(st, byte(r))
}

// tcpFlow carries a byte stream as chunks: a 2-byte length and that many
// bytes. A zero length is the end-of-stream marker sent by CloseWrite. A
// multiplexer FIN means the peer closed the flow entirely; seen before the
// marker it is a reset.
type tcpFlow struct {
	st  *smux.Stream
	ans answer

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
	if err := f.ans.read(f.st); err != nil {
		return 0, err
	}
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
	if err := f.ans.send(f.st, answerOpen); err != nil {
		return 0, err
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
	err := f.ans.send(f.st, answerOpen)
	if err == nil {
		_, err = f.st.Write([]byte{0, 0})
	}
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
// discarded and its writes fail, like a TCP close. A flow closed before it
// was answered is refused (core.ReasonError).
func (f *tcpFlow) Close() error {
	f.closeOnce.Do(func() {
		if f.wmu.TryLock() {
			if f.ans.owe {
				f.wdone = true // no marker: the opener reads the end as a refusal
			}
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

// Accept sends the open answer if it is still owed.
func (f *tcpFlow) Accept() error {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if !f.ans.owe {
		return nil
	}
	if f.wdone {
		return io.ErrClosedPipe
	}
	return f.ans.send(f.st, answerOpen)
}

// Refuse sends a refusal if no answer was sent yet and closes the flow. After
// an accept it resets the flow.
func (f *tcpFlow) Refuse(r core.Reason) error {
	f.wmu.Lock()
	f.ans.refuse(f.st, r)
	f.wdone = true
	f.wmu.Unlock()
	return f.Close()
}

func (f *tcpFlow) waitOpen(ctx context.Context) error {
	f.rmu.Lock()
	defer f.rmu.Unlock()
	return f.ans.wait(ctx, f.st)
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
	ans answer
	rmu sync.Mutex
	wmu sync.Mutex
}

// Read returns one message. A message longer than p is truncated, like a UDP
// socket.
func (f *datagramFlow) Read(p []byte) (int, error) {
	f.rmu.Lock()
	defer f.rmu.Unlock()
	if err := f.ans.read(f.st); err != nil {
		return 0, err
	}
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
	err := f.ans.send(f.st, answerOpen)
	if err == nil {
		_, err = f.st.Write(buf[:2+len(p)])
	}
	f.wmu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Accept sends the open answer if it is still owed.
func (f *datagramFlow) Accept() error {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	return f.ans.send(f.st, answerOpen)
}

// Refuse sends a refusal if no answer was sent yet and closes the flow.
func (f *datagramFlow) Refuse(r core.Reason) error {
	f.wmu.Lock()
	f.ans.refuse(f.st, r)
	f.wmu.Unlock()
	return f.Close()
}

func (f *datagramFlow) waitOpen(ctx context.Context) error {
	f.rmu.Lock()
	defer f.rmu.Unlock()
	return f.ans.wait(ctx, f.st)
}

func (f *datagramFlow) CloseWrite() error { return f.Close() }

func (f *datagramFlow) Close() error {
	f.st.Close()
	return nil
}

func (f *datagramFlow) SetDeadline(t time.Time) error      { return f.st.SetDeadline(t) }
func (f *datagramFlow) SetReadDeadline(t time.Time) error  { return f.st.SetReadDeadline(t) }
func (f *datagramFlow) SetWriteDeadline(t time.Time) error { return f.st.SetWriteDeadline(t) }
