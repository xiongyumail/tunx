package forward

import (
	"context"
	"net"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/xiongyumail/tunx/internal/config"
)

// congestionOf reads TCP_CONGESTION of a connection.
func congestionOf(t *testing.T, c net.Conn) string {
	t.Helper()
	rc, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var name string
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		name, gerr = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return strings.TrimRight(name, "\x00")
}

// TestCongestion checks that the dialing socket and the connections a
// listener accepts get the configured congestion control. reno is always
// built in and allowed for unprivileged sockets.
func TestCongestion(t *testing.T) {
	lc := net.ListenConfig{Control: sockopts("", 0, "reno")}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	c, err := dialPeer(context.Background(), config.Peer{Dial: ln.Addr().String(), Congestion: "reno"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := congestionOf(t, c); got != "reno" {
		t.Errorf("dialed socket: congestion %q, want reno", got)
	}
	a, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	defer a.Close()
	if got := congestionOf(t, a); got != "reno" {
		t.Errorf("accepted socket: congestion %q, want reno", got)
	}

	if sockopts("", 0, "default") != nil || sockopts("", 0, "") != nil {
		t.Error("default congestion should leave the socket alone")
	}
	_, err = dialPeer(context.Background(), config.Peer{Dial: ln.Addr().String(), Congestion: "no_such_cc"})
	if err == nil || !strings.Contains(err.Error(), "no_such_cc") {
		t.Errorf("unknown congestion control: err %v", err)
	}
}
