//go:build tunxroot

// Tests on a real TUN device. They need root and change the host's network
// (a TUN device, addresses, routes), so they only build with -tags tunxroot
// and are meant for a disposable test VM:
//
//	go test -tags tunxroot -run TUN ./internal/netstack/

package netstack

import (
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const testTUN = "tunxt0"

func setupTUN(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	s, err := New(Config{Name: testTUN, Handler: egressHandler(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, args := range [][]string{
		{"link", "set", testTUN, "up"},
		{"addr", "add", "10.99.0.1/24", "dev", testTUN},
		{"-6", "addr", "add", "fd99::1/64", "dev", testTUN, "nodad"},
		{"route", "add", "198.18.0.0/24", "dev", testTUN},
		{"-6", "route", "add", "2001:db8::/64", "dev", testTUN},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v\n%s", args, err, out)
		}
	}
}

func TestTUNTCPAndUDP(t *testing.T) {
	setupTUN(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		n, _ := io.Copy(io.Discard, c)
		c.Write([]byte("n=" + strconv.FormatInt(n, 10)))
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	c, err := net.DialTimeout("tcp4", net.JoinHostPort("198.18.0.1", strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(make([]byte, 1<<20))
	c.(*net.TCPConn).CloseWrite()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, _ := io.ReadAll(c)
	if string(got) != "n=1048576" {
		t.Fatalf("tcp got %q", got)
	}

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		n, from, err := pc.ReadFrom(buf)
		if err == nil {
			pc.WriteTo(buf[:n], from)
		}
	}()
	uc, err := net.Dial("udp4", net.JoinHostPort("198.18.0.1", strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.Write([]byte("udp"))
	uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	if n, err := uc.Read(buf); err != nil || string(buf[:n]) != "udp" {
		t.Fatalf("udp got %q, %v", buf[:n], err)
	}
}

func TestTUNPing(t *testing.T) {
	setupTUN(t)
	for _, tc := range []struct {
		dst   string
		reply bool
	}{
		{"198.18.0.1", true},   // delivered to 127.0.0.1
		{"198.18.0.2", false},  // not delivered: no reply, never a fake one
		{"2001:db8::1", true},  // delivered to ::1
		{"2001:db8::2", false}, // not delivered
	} {
		got := kernelPing(t, netip.MustParseAddr(tc.dst))
		if got != tc.reply {
			t.Errorf("ping %s: reply %v, want %v", tc.dst, got, tc.reply)
		}
	}
}

// kernelPing sends one echo through the host's routing table and reports
// whether a reply arrived within a second.
func kernelPing(t *testing.T, dst netip.Addr) bool {
	t.Helper()
	family, proto, typ := unix.AF_INET, unix.IPPROTO_ICMP, byte(8)
	var sa unix.Sockaddr = &unix.SockaddrInet4{Addr: dst.As4()}
	if dst.Is6() {
		family, proto, typ = unix.AF_INET6, unix.IPPROTO_ICMPV6, 128
		sa = &unix.SockaddrInet6{Addr: dst.As16()}
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	tv := unix.NsecToTimeval(int64(time.Second))
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	if err := unix.Sendto(fd, []byte{typ, 0, 0, 0, 0, 0, 0, 1, 'x'}, 0, sa); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	return err == nil && n >= 8
}
