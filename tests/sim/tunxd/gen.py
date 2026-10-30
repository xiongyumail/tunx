#!/usr/bin/env python3
"""Write the tunxd and Xray configs for topologies/two-sites-tunxd.yaml.

  gen.py --mode plain|xray --tunxd BIN [--xray BIN] [--premade NODE]... [--congestion CC]

Runs as root in the test VM, after `sim.py up`, and writes into each node
directory (RUNDIR/nodes/NODE/):

  tunxd.json     node config; keys are generated with `tunxd keygen`
  xray.json      Xray config (xray mode); keys with `xray x25519` / `xray uuid`
  start.sh       host setup that must precede tunxd, Xray, then tunxd in the
                 foreground; prints "tunxd exited rc=N" when tunxd ends
  setup-tun.sh   applies the `ip` commands printed by `tunxd check`
  preserve.nft   (gw-b) the socket-transparent recipe of docs/tunxd.md

Links. plain: tunxd dials the peer's tunxd directly on TCP 4430. xray: tunxd
dials a local Xray inbound (127.0.0.1:10800 for the first peer, 10801 for
the second) whose outbound carries the connection to the peer's Xray, which
hands it to the peer's tunxd on 127.0.0.1:7700. Links to hub and exit use
VLESS + Reality on TCP 443 (gw-b's cross the censor); term-a's link to gw-a
stays on the LAN and uses plain VLESS on 8443 (Xray allows plain VLESS only
to private addresses). Reality's target is the HTTPS server on the web node
(tlsweb.py), and the client's serverName is that server's name.

--congestion sets the congestion control of the sockets that cross the
network: tunxd's link sockets in plain mode (peers[].congestion,
listen[].congestion), Xray's in xray mode (sockopt.tcpcongestion).

Overlay nodes: hub and exit relay between the sites (exit has priority 1)
and deliver 203.0.113.0/24 (internet exit); gw-a and gw-b are the site
gateways; term-a is a terminal behind gw-a. gw-a and gw-b also capture
203.0.113.0/24, which contains their link peers, so their link sockets are
bound: gw-a by mark 0x74 and a policy route, gw-b by interface eth0.
"""
import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys

SIM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SIM)

from simnet import model  # noqa: E402

NODES = ["hub", "exit", "gw-a", "gw-b", "term-a"]
OVERLAY4, OVERLAY6 = "10.200.0", "fd74:756e:7800:"
OVERLAY_ID = {"hub": 1, "gw-a": 2, "gw-b": 3, "term-a": 4}
LINK_PORT = 4430          # plain mode: tunxd listens here
TUNXD_LOCAL = "127.0.0.1:7700"   # xray mode: tunxd listens here behind Xray
REALITY_PORT, VLESS_PORT = 443, 8443
SERVER_NAME = "www.example.test"
MARK = 0x74               # gw-a: link sockets carry this mark
PRESERVE_MARK = 0x7478    # gw-b: recipe of docs/tunxd.md
PRESERVE_TABLE = 7478
STATUS = "127.0.0.1:7790"
BIN_ROOT = "/var/tmp/tunx-sim"   # removed by run-tunxd.sh


def run(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def keygen(tunxd):
    return json.loads(run([tunxd, "keygen"]))


def x25519(xray):
    out = run([xray, "x25519"])
    priv = re.search(r"Private\s*key:\s*(\S+)", out, re.I)
    pub = re.search(r"(?:Public\s*key|Password)[^:]*:\s*(\S+)", out, re.I)
    if not priv or not pub:
        raise SystemExit(f"cannot parse `xray x25519` output:\n{out}")
    return priv.group(1), pub.group(1)


def ov4(n):
    return f"{OVERLAY4}.{OVERLAY_ID[n]}"


def ov6(n):
    return f"{OVERLAY6}:{OVERLAY_ID[n]}"


def route(prefix, *ads):
    return {"prefix": prefix, "advertisers": list(ads)}


def ad(node, **kw):
    return dict({"node": node}, **kw)


class Gen:
    def __init__(self, args):
        self.a = args
        self.t = model.load(args.topo, prefix=args.prefix, rundir=args.rundir)
        self.keys = {n: keygen(args.tunxd) for n in NODES}
        self.r = self.t.resolve
        if args.mode == "xray":
            self.reality = {n: x25519(args.xray) for n in ("hub", "exit")}
            self.uuid = {n: run([args.xray, "uuid"]).strip() for n in ("gw-a", "gw-b", "term-a")}

    def dir(self, node):
        return self.t.node(node).dir

    def write(self, node, name, content, mode=0o644):
        path = os.path.join(self.dir(node), name)
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, mode)

    def peer(self, name, dial=None, **kw):
        p = {"name": name, "public_key": self.keys[name]["public_key"]}
        if dial:
            p["dial"] = dial
            if self.a.mode == "plain" and self.a.congestion:
                p["congestion"] = self.a.congestion
        p.update(kw)
        return p

    def dial(self, peer, index):
        """Where tunxd dials peer: the peer itself, or local Xray inbound number index."""
        if self.a.mode == "xray":
            return f"127.0.0.1:{10800 + index}"
        return f"{self.r(peer + '.eth0')}:{LINK_PORT}"

    def listen(self, node):
        if self.a.mode == "xray":
            return [{"address": TUNXD_LOCAL}]
        ln = {"address": f"{self.r(node + '.eth0')}:{LINK_PORT}"}
        if self.a.congestion:
            ln["congestion"] = self.a.congestion
        return [ln]

    def base(self, node):
        c = {"node": node, "network": "sim", "private_key": self.keys[node]["private_key"],
             "status": STATUS, "log_level": "debug"}
        if node in OVERLAY_ID:
            c["addresses"] = [ov4(node), ov6(node)]
        return c

    def tun(self, node, capture):
        return {"name": "tunx0", "mtu": 1400,
                "addresses": [f"{ov4(node)}/24", f"{ov6(node)}/64"], "capture": capture}

    # Node configs.

    def relay(self, node):
        """hub and exit: relays between the sites and internet exit."""
        c = self.base(node)
        if node == "hub":  # exit has no TUN and no overlay address
            c["tun"] = self.tun(node, ["10.0.1.0/24", "10.0.2.0/24", "fd00:a::/64", "fd00:b::/64"])
        c["listen"] = self.listen(node)
        c["peers"] = [self.peer("gw-a", relay_for=["term-a"]), self.peer("gw-b")]
        c["routes"] = [
            route("10.0.1.0/24", ad("gw-a")), route("fd00:a::/64", ad("gw-a")),
            route("10.0.2.0/24", ad("gw-b")), route("fd00:b::/64", ad("gw-b")),
            route(f"{ov4('gw-a')}/32", ad("gw-a")), route(f"{ov6('gw-a')}/128", ad("gw-a")),
            route(f"{ov4('gw-b')}/32", ad("gw-b")), route(f"{ov6('gw-b')}/128", ad("gw-b")),
            route(f"{ov4('term-a')}/32", ad("term-a", via=["gw-a"])),
            route(f"{ov6('term-a')}/128", ad("term-a", via=["gw-a"])),
            # Internet exit, from this node's own address.
            route("203.0.113.0/24", ad(node)), route("2001:db8:113::/64", ad(node)),
        ]
        c["policy"] = [{"action": "allow", "identity": ["hub", "exit", "gw-a", "gw-b", "term-a"]}]
        return c

    def gw_a(self):
        c = self.base("gw-a")
        c["tun"] = self.tun("gw-a", ["10.0.2.0/24", "fd00:b::/64", "203.0.113.0/24"])
        c["listen"] = self.listen("gw-a")
        bind = {} if self.a.mode == "xray" else {"mark": MARK}  # in xray mode Xray marks
        c["peers"] = [
            self.peer("hub", self.dial("hub", 0), relay_for=["gw-b"], **bind),
            self.peer("exit", self.dial("exit", 1), relay_for=["gw-b"], priority=1, **bind),
            self.peer("term-a"),
        ]
        c["routes"] = [
            route("10.0.1.0/24", ad("gw-a")), route("fd00:a::/64", ad("gw-a")),
            route("10.0.2.0/24", ad("gw-b", via=["hub", "exit"])),
            route("fd00:b::/64", ad("gw-b", via=["hub", "exit"])),
            route("10.200.0.0/24", ad("hub")), route("fd74:756e:7800::/64", ad("hub")),
            route(f"{ov4('term-a')}/32", ad("term-a")), route(f"{ov6('term-a')}/128", ad("term-a")),
            route("203.0.113.0/24", ad("hub"), ad("exit", priority=1)),
        ]
        c["policy"] = [
            {"action": "allow", "identity": ["gw-a"]},
            {"action": "allow", "identity": ["hub", "exit", "gw-b", "term-a"],
             "dst": ["10.0.1.0/24", "fd00:a::/64", f"{ov4('gw-a')}/32", f"{ov6('gw-a')}/128"]},
            {"action": "deny"},
        ]
        return c

    def gw_b(self):
        c = self.base("gw-b")
        c["tun"] = self.tun("gw-b", ["10.0.1.0/24", "fd00:a::/64", "203.0.113.0/24", "2001:db8:113::/64"])
        bind = {} if self.a.mode == "xray" else {"interface": "eth0"}  # in xray mode Xray binds
        c["peers"] = [
            self.peer("hub", self.dial("hub", 0), relay_for=["gw-a", "term-a"], **bind),
            self.peer("exit", self.dial("exit", 1), relay_for=["gw-a", "term-a"], priority=1, **bind),
        ]
        c["routes"] = [
            # Delivered with the original source; router-b routes site A and
            # the overlay back to gw-b.
            route("10.0.2.0/24", ad("gw-b", source="preserve")),
            route("fd00:b::/64", ad("gw-b", source="preserve")),
            route("10.0.1.0/24", ad("gw-a", via=["hub", "exit"])),
            route("fd00:a::/64", ad("gw-a", via=["hub", "exit"])),
            route("10.200.0.0/24", ad("hub")), route("fd74:756e:7800::/64", ad("hub")),
            route("203.0.113.0/24", ad("hub"), ad("exit", priority=1)),
            route("2001:db8:113::/64", ad("hub"), ad("exit", priority=1)),
        ]
        lan_b = ["10.0.2.0/24", "fd00:b::/64", f"{ov4('gw-b')}/32", f"{ov6('gw-b')}/128"]
        c["policy"] = [
            # TCP 25 on LAN B is closed to the overlay: denied at delivery.
            {"action": "deny", "dst": ["10.0.2.0/24", "fd00:b::/64"], "proto": ["tcp"], "ports": [25]},
            {"action": "allow", "identity": ["gw-b"]},
            {"action": "allow", "identity": ["gw-a", "term-a", "hub", "exit"], "dst": lan_b},
            {"action": "deny"},
        ]
        return c

    def term_a(self):
        c = self.base("term-a")
        c["tun"] = self.tun("term-a", ["10.0.2.0/24", "fd00:b::/64"])
        c["peers"] = [self.peer("gw-a", self.dial("gw-a", 0), relay_for=["hub", "exit", "gw-b"])]
        c["routes"] = [
            route("10.0.2.0/24", ad("gw-a")), route("fd00:b::/64", ad("gw-a")),
            route("10.200.0.0/24", ad("gw-a")), route("fd74:756e:7800::/64", ad("gw-a")),
        ]
        c["policy"] = [
            {"action": "allow", "identity": ["term-a"]},
            {"action": "allow", "identity": ["hub", "gw-a", "gw-b"],
             "dst": [f"{ov4('term-a')}/32", f"{ov6('term-a')}/128"]},
            {"action": "deny"},
        ]
        return c

    # Xray.

    def to_tunxd(self):
        # Freedom refuses private and loopback targets unless a final rule
        # allows them.
        host, port = TUNXD_LOCAL.split(":")
        return {"tag": "tunxd", "protocol": "freedom",
                "settings": {"redirect": TUNXD_LOCAL,
                             "finalRules": [{"action": "allow", "ip": [host], "port": port}]}}

    def xray_server(self, node, inbounds):
        return {"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": [self.to_tunxd()]}

    def vless_in(self, node, port, clients, reality=False):
        stream = {"network": "tcp"}
        if self.a.congestion:
            stream["sockopt"] = {"tcpcongestion": self.a.congestion}
        if reality:
            priv, _ = self.reality[node]
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "target": f"{self.r('web.eth0')}:443",
                "serverNames": [SERVER_NAME],
                "privateKey": priv,
                "shortIds": [""],
            }
        return {"tag": f"vless-{port}", "listen": self.r(node + ".eth0"), "port": port, "protocol": "vless",
                "settings": {"clients": [{"id": self.uuid[c], "email": c} for c in clients], "decryption": "none"},
                "streamSettings": stream}

    def vless_out(self, client, server, sockopt=None):
        reality = server in ("hub", "exit")
        stream = {"network": "tcp"}
        if reality:
            _, pub = self.reality[server]
            stream["security"] = "reality"
            stream["realitySettings"] = {"serverName": SERVER_NAME, "fingerprint": "chrome",
                                         "publicKey": pub, "shortId": ""}
        sockopt = dict(sockopt or {})
        if self.a.congestion:
            sockopt["tcpcongestion"] = self.a.congestion
        if sockopt:
            stream["sockopt"] = sockopt
        port = REALITY_PORT if reality else VLESS_PORT
        return {"tag": f"to-{server}", "protocol": "vless",
                "settings": {"vnext": [{"address": self.r(server + ".eth0"), "port": port,
                                        "users": [{"id": self.uuid[client], "encryption": "none"}]}]},
                "streamSettings": stream}

    def xray_client(self, client, servers, sockopt=None, extra_in=()):
        inbounds, rules = [], []
        for k, s in enumerate(servers):
            inbounds.append({"tag": f"in-{s}", "listen": "127.0.0.1", "port": 10800 + k,
                             "protocol": "dokodemo-door",
                             "settings": {"address": "127.0.0.1", "port": 7700, "network": "tcp"}})
            rules.append({"type": "field", "inboundTag": [f"in-{s}"], "outboundTag": f"to-{s}"})
        outbounds = [self.vless_out(client, s, sockopt) for s in servers]
        for ib in extra_in:
            inbounds.append(ib)
            rules.append({"type": "field", "inboundTag": [ib["tag"]], "outboundTag": "tunxd"})
            outbounds.append(self.to_tunxd())
        return {"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": outbounds,
                "routing": {"rules": rules}}

    def xray(self, node):
        if node in ("hub", "exit"):
            return self.xray_server(node, [self.vless_in(node, REALITY_PORT, ["gw-a", "gw-b"], reality=True)])
        if node == "gw-a":
            return self.xray_client("gw-a", ["hub", "exit"], {"mark": MARK},
                                    [self.vless_in("gw-a", VLESS_PORT, ["term-a"])])
        if node == "gw-b":
            return self.xray_client("gw-b", ["hub", "exit"], {"interface": "eth0"})
        return self.xray_client("term-a", ["gw-a"])

    # Scripts.

    def start_sh(self, node):
        pre = []
        if node == "gw-a":
            # Link sockets carry MARK and leave by the LAN, never by the TUN.
            pre += [f"ip rule add fwmark {MARK} lookup {MARK}",
                    f"ip route add default via {self.r('router-a.lan0')} dev eth0 table {MARK}"]
        if node == "gw-b":
            pre += ["nft -f preserve.nft",
                    f"ip rule add fwmark {PRESERVE_MARK:#x} lookup {PRESERVE_TABLE}",
                    f"ip route add local 0.0.0.0/0 dev lo table {PRESERVE_TABLE}",
                    f"ip -6 rule add fwmark {PRESERVE_MARK:#x} lookup {PRESERVE_TABLE}",
                    f"ip -6 route add local ::/0 dev lo table {PRESERVE_TABLE}"]
        if node in self.a.premade:
            pre.append("ip tuntap add dev tunx0 mode tun")
        runas = ""
        if node == "hub":
            # Unprivileged: CAP_NET_ADMIN for the TUN only; ping through
            # ping sockets (net.ipv4.ping_group_range).
            runas = "setpriv --reuid=nobody --regid=nogroup --clear-groups --inh-caps=+net_admin --ambient-caps=+net_admin -- "
        lines = ["#!/bin/sh", f"# Generated by gen.py ({self.a.mode} mode): start {node}.", "set -e",
                 'cd "$(dirname "$0")"', *pre]
        if self.a.mode == "xray":
            lines.append(f"{shlex.quote(self.a.xray)} run -c xray.json >xray.log 2>&1 &")
        lines += ["set +e",
                  f"{runas}{shlex.quote(self.a.tunxd)} run -c tunxd.json 2>tunxd.log &",
                  "pid=$!", "echo $pid >tunxd.pid", "wait $pid", 'echo "tunxd exited rc=$?"', ""]
        return "\n".join(lines)

    def setup_tun_sh(self):
        return "\n".join([
            "#!/bin/sh", "# Generated by gen.py: apply the TUN setup printed by `tunxd check`.", "set -e",
            'cd "$(dirname "$0")"',
            f"{shlex.quote(self.a.tunxd)} check -c tunxd.json >check.txt",
            "grep '^ip ' check.txt | while read -r cmd; do echo \"+ $cmd\"; $cmd; done",
            "ip -br addr show dev tunx0", "ip route show dev tunx0", "ip -6 route show dev tunx0", ""])

    def preserve_nft(self):
        # Replies to transparent sockets (TCP, UDP), and echo replies to the
        # ping sockets bound to a preserved source (the remote sites and the
        # overlay), are delivered locally instead of being routed into the TUN.
        m = f"{PRESERVE_MARK:#x}"
        v4 = "10.0.1.0/24, 10.200.0.0/24"
        v6 = "fd00:a::/64, fd74:756e:7800::/64"
        return "\n".join([
            "table ip tunx {", "  chain pre {",
            "    type filter hook prerouting priority mangle; policy accept;",
            f"    socket transparent 1 meta mark set {m}",
            f'    iifname != "tunx0" ip daddr {{ {v4} }} icmp type echo-reply meta mark set {m}',
            "  }", "}",
            "table ip6 tunx {", "  chain pre {",
            "    type filter hook prerouting priority mangle; policy accept;",
            f"    socket transparent 1 meta mark set {m}",
            f'    iifname != "tunx0" ip6 daddr {{ {v6} }} icmpv6 type echo-reply meta mark set {m}',
            "  }", "}", ""])

    def install(self):
        """Copy the binaries where the unprivileged hub process can execute
        them (the run directory is usually on a noexec /run)."""
        bindir = os.path.join(BIN_ROOT, self.t.prefix)
        os.makedirs(bindir, mode=0o755, exist_ok=True)
        os.chmod(BIN_ROOT, 0o755)
        for name in ("tunxd", "xray"):
            src = getattr(self.a, name)
            if src:
                dst = os.path.join(bindir, name)
                shutil.copyfile(src, dst + ".new")
                os.chmod(dst + ".new", 0o755)
                os.replace(dst + ".new", dst)
                setattr(self.a, name, dst)

    def all(self):
        self.install()
        cfgs = {"hub": self.relay("hub"), "exit": self.relay("exit"), "gw-a": self.gw_a(),
                "gw-b": self.gw_b(), "term-a": self.term_a()}
        for node, cfg in cfgs.items():
            self.write(node, "tunxd.json", json.dumps(cfg, indent=2) + "\n")
            if self.a.mode == "xray":
                self.write(node, "xray.json", json.dumps(self.xray(node), indent=2) + "\n")
            elif os.path.exists(os.path.join(self.dir(node), "xray.json")):
                os.remove(os.path.join(self.dir(node), "xray.json"))
            self.write(node, "start.sh", self.start_sh(node), 0o755)
            self.write(node, "setup-tun.sh", self.setup_tun_sh(), 0o755)
        self.write("gw-b", "preserve.nft", self.preserve_nft())
        for node in cfgs:
            print(f"{node}: {self.dir(node)}/tunxd.json" + (" + xray.json" if self.a.mode == "xray" else ""))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--topo", default=os.path.join(SIM, "topologies", "two-sites-tunxd.yaml"))
    p.add_argument("--prefix", help="namespace prefix (default from the topology)")
    p.add_argument("--rundir", help="run directory of the topology (default from the topology)")
    p.add_argument("--mode", choices=("plain", "xray"), required=True)
    p.add_argument("--tunxd", required=True, help="tunxd binary")
    p.add_argument("--xray", help="xray binary (xray mode)")
    p.add_argument("--premade", action="append", default=[], help="create this node's TUN before tunxd starts")
    p.add_argument("--congestion", default="", help="TCP congestion control of the link sockets "
                   "(tunxd's in plain mode, Xray's in xray mode); default: the system's")
    args = p.parse_args()
    if args.mode == "xray" and not args.xray:
        p.error("--xray is required in xray mode")
    args.tunxd = os.path.abspath(args.tunxd)
    if args.xray:
        args.xray = os.path.abspath(args.xray)
    Gen(args).all()
    return 0


if __name__ == "__main__":
    sys.exit(main())
