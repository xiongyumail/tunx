package link

import (
	"context"
	"math/rand/v2"
	"net"
	"time"
)

// Backoff between redials in Keep.
const (
	minBackoff = 250 * time.Millisecond
	maxBackoff = 10 * time.Second
)

// Keep maintains a client session: it dials, runs the handshake and calls
// onSession with each new session, then waits for the session to end and
// dials again. Failed attempts back off exponentially with jitter up to
// maxBackoff; a successful handshake resets the backoff. onSession may block
// (for example by running Serve). Keep returns ctx.Err() after closing the
// current session when ctx is canceled.
func Keep(ctx context.Context, dial func(context.Context) (net.Conn, error), cfg Config, onSession func(*Session)) error {
	log := cfg.withDefaults().Logger
	backoff := minBackoff
	for {
		conn, err := dial(ctx)
		if err == nil {
			var s *Session
			s, err = Client(ctx, conn, cfg)
			if err == nil {
				backoff = minBackoff
				onSession(s)
				select {
				case <-s.Done():
				case <-ctx.Done():
					s.Close()
					return ctx.Err()
				}
				err = s.Err()
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		wait := backoff/2 + rand.N(backoff/2+1)
		log.Warn("link: redialing", "err", err, "in", wait.Round(time.Millisecond).String())
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
		backoff = min(backoff*2, maxBackoff)
	}
}
