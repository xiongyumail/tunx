#!/usr/bin/env python3
"""Reachability probe for simulation scenarios (stdlib only).

  probe.py serve --tcp 443,8080 --udp 53     answer each TCP connection and UDP
                                             datagram with "peer <addr> <port>"
  probe.py tcp HOST PORT                     connect, print the answer, exit 0
  probe.py udp HOST PORT                     send a datagram, print the answer

Clients exit 1 when nothing answers in time, so scenarios can check both
reachability and the source address the server saw (NAT, source preservation).
"""
import argparse
import socket
import socketserver
import sys
import threading


def _peer(addr):
    host, port = addr[0], addr[1]
    if host.startswith("::ffff:"):
        host = host[7:]
    return f"peer {host} {port}\n".encode()


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(_peer(self.client_address))
        except OSError:
            pass


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        _, sock = self.request
        sock.sendto(_peer(self.client_address), self.client_address)


def _server(base, bind, port, handler):
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET

    class Server(base):
        address_family = family
        allow_reuse_address = True
        daemon_threads = True

        def server_bind(self):
            if family == socket.AF_INET6:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            super().server_bind()

    return Server((bind, port), handler)


def _ports(s):
    return [int(p) for p in (s or "").split(",") if p.strip()]


def serve(args):
    servers = []
    for proto, ports in (("tcp", _ports(args.tcp)), ("udp", _ports(args.udp))):
        base = socketserver.ThreadingTCPServer if proto == "tcp" else socketserver.ThreadingUDPServer
        h = _TCPHandler if proto == "tcp" else _UDPHandler
        for port in ports:
            srv = _server(base, args.bind, port, h)
            servers.append(srv)
            print(f"listening {proto} {args.bind} {srv.server_address[1]}", flush=True)
    if not servers:
        print("nothing to serve: give --tcp and/or --udp", file=sys.stderr)
        return 2
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for t in threads:
        t.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    return 0


def tcp(args):
    try:
        with socket.create_connection((args.host, args.port), timeout=args.timeout) as s:
            s.settimeout(args.timeout)
            data = s.recv(256)
    except OSError as e:
        print(f"tcp {args.host}:{args.port}: {e}", file=sys.stderr)
        return 1
    sys.stdout.write(data.decode(errors="replace"))
    return 0 if data else 1


def udp(args):
    try:
        info = socket.getaddrinfo(args.host, args.port, type=socket.SOCK_DGRAM)[0]
    except OSError as e:
        print(f"udp {args.host}:{args.port}: {e}", file=sys.stderr)
        return 1
    with socket.socket(info[0], socket.SOCK_DGRAM) as s:
        s.settimeout(args.timeout / args.tries)
        for _ in range(args.tries):
            try:
                s.sendto(b"probe\n", info[4])
                data = s.recv(256)
            except socket.timeout:
                continue
            except OSError as e:
                print(f"udp {args.host}:{args.port}: {e}", file=sys.stderr)
                return 1
            sys.stdout.write(data.decode(errors="replace"))
            return 0
    print(f"udp {args.host}:{args.port}: no answer within {args.timeout}s", file=sys.stderr)
    return 1


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("serve")
    sp.add_argument("--tcp", help="comma-separated TCP ports")
    sp.add_argument("--udp", help="comma-separated UDP ports")
    sp.add_argument("--bind", default="::", help="address to bind (default :: for IPv4 and IPv6)")
    sp.set_defaults(func=serve)
    for name, fn in (("tcp", tcp), ("udp", udp)):
        sp = sub.add_parser(name)
        sp.add_argument("host")
        sp.add_argument("port", type=int)
        sp.add_argument("--timeout", type=float, default=3.0)
        if name == "udp":
            sp.add_argument("--tries", type=int, default=3)
        sp.set_defaults(func=fn)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
