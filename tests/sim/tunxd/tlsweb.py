#!/usr/bin/env python3
"""A small HTTPS server with a self-signed certificate (stdlib + openssl CLI).

The simulation has no real website for VLESS + Reality to borrow, so the web
node runs this server and Reality's target (dest) points at it:

  tlsweb.py --port 443 --name www.example.test

The certificate and key are created in the current directory on first start.
"""
import argparse
import http.server
import os
import socket
import ssl
import subprocess
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        # The handshake runs here, in the connection's thread, so a slow
        # client cannot block the accept loop.
        self.request.settimeout(10)
        self.request.do_handshake()
        super().setup()

    def do_GET(self):
        body = b"<html><body>example</body></html>\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

    def handle_error(self, request, client_address):
        pass  # failed handshakes and resets are routine for a Reality target


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--name", default="www.example.test", help="certificate subject and SAN")
    args = p.parse_args()
    if not os.path.exists("tls.key"):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "30", "-subj", f"/CN={args.name}",
                        "-addext", f"subjectAltName=DNS:{args.name}",
                        "-keyout", "tls.key", "-out", "tls.crt"], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["http/1.1"])
    ctx.load_cert_chain("tls.crt", "tls.key")
    srv = Server(("::", args.port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    print(f"listening https :{args.port} as {args.name}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
