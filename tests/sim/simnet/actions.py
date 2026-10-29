"""Turn a topology into an ordered list of actions (the plan) for up, down and runtime changes."""
import json
import os
import shlex
from dataclasses import dataclass, field

from . import netem as netem_mod
from .model import BRIDGE


@dataclass
class Cmd:
    argv: list
    check: bool = True

    def shell(self):
        return shlex.join(self.argv) + ("" if self.check else "  # errors ignored")


@dataclass
class Mkdir:
    path: str

    def shell(self):
        return f"mkdir -p {shlex.quote(self.path)}"


@dataclass
class Write:
    path: str
    content: bytes
    mode: int = 0o644

    def shell(self):
        text = self.content.decode(errors="replace")
        if text and not text.endswith("\n"):
            text += "\n"
        q = shlex.quote(self.path)
        return f"cat > {q} <<'EOF'\n{text}EOF\nchmod {self.mode:o} {q}"


@dataclass
class Spawn:
    """Start a long-running command inside a namespace, output to a log file."""
    ns: str
    cmd: str
    log: str
    cwd: str
    pidfile: str
    env: dict = field(default_factory=dict)

    def shell(self):
        env = " ".join(f"{k}={shlex.quote(v)}" for k, v in self.env.items())
        inner = f"ip netns exec {self.ns} {'env ' + env + ' ' if env else ''}sh -c {shlex.quote(self.cmd)}"
        pid = f"  # pid -> {self.pidfile}" if self.pidfile else ""
        return f"(cd {shlex.quote(self.cwd)} && {inner}) >>{shlex.quote(self.log)} 2>&1 &{pid}"


@dataclass
class KillNs:
    """Kill every process inside a namespace (TERM, then KILL)."""
    ns: str

    def shell(self):
        return f"ip netns pids {self.ns} | xargs -r kill -TERM  # then KILL after 3 s"


@dataclass
class DelNs:
    ns: str

    def shell(self):
        return f"ip netns del {self.ns}"


@dataclass
class Remove:
    path: str

    def shell(self):
        return f"rm -f {shlex.quote(self.path)}"


def ip(ns, *args):
    return Cmd(["ip", "-n", ns, *args])


def nsexec(ns, *args, check=True):
    return Cmd(["ip", "netns", "exec", ns, *args], check)


def netem_cmd(ns, dev, params):
    if not params:
        return Cmd(["tc", "-n", ns, "qdisc", "del", "dev", dev, "root"], check=False)
    return Cmd(["tc", "-n", ns, "qdisc", "replace", "dev", dev, "root", "netem", *netem_mod.tc_args(params)])


def nft_rules(node):
    """nftables text for a node's NAT and firewall helpers, or '' if none."""
    out = []
    masq = [i.name for i in node.ifaces.values() if i.nat == "masquerade"]
    if masq:
        out += ["table ip sim_nat", "delete table ip sim_nat", "table ip sim_nat {",
                "  chain postrouting {",
                "    type nat hook postrouting priority srcnat; policy accept;"]
        out += [f'    oifname "{m}" masquerade' for m in masq]
        out += ["  }", "}"]
    if node.firewall:
        chains = {"forward": [], "input": [], "output": []}
        for fw in node.firewall:
            match = " ".join(x for x in (f'iifname "{fw.iif}"' if fw.iif else "",
                                         f'oifname "{fw.oif}"' if fw.oif else "") if x)
            targets = ["forward"]
            if fw.local:
                if fw.iif and not fw.oif:
                    targets.append("input")
                if fw.oif and not fw.iif:
                    targets.append("output")
            for c in targets:
                if c == "input":
                    m = f'iifname "{fw.iif}"'
                elif c == "output":
                    m = f'oifname "{fw.oif}"'
                else:
                    m = match
                for r in fw.allow:
                    chains[c].append(f"    {m} {_rule_expr(r)} accept".replace("  accept", " accept"))
                if fw.default != "accept":
                    chains[c].append(f"    {m} {fw.default}")
        out += ["table inet sim_fw", "delete table inet sim_fw", "table inet sim_fw {"]
        for c, rules in chains.items():
            if not rules:
                continue
            out += [f"  chain {c} {{",
                    f"    type filter hook {c} priority filter; policy accept;",
                    "    ct state established,related accept"] + rules + ["  }"]
        out.append("}")
    return "\n".join(out) + ("\n" if out else "")


def _rule_expr(r):
    parts = []
    for word, net in (("saddr", r.src), ("daddr", r.dst)):
        if net is not None:
            fam = "ip" if net.version == 4 else "ip6"
            val = str(net.network_address) if net.num_addresses == 1 else str(net)
            parts.append(f"{fam} {word} {val}")
    version = (r.src or r.dst).version if (r.src or r.dst) else None
    if r.proto in ("tcp", "udp"):
        parts.append(f"{r.proto} dport {{ {', '.join(r.ports)} }}" if r.ports else f"meta l4proto {r.proto}")
    elif r.proto == "icmp":
        parts.append({4: "meta l4proto icmp", 6: "meta l4proto ipv6-icmp"}.get(version,
                                                                            "meta l4proto { icmp, ipv6-icmp }"))
    return " ".join(parts)


def addr_cmds(node, iface):
    out = []
    for a in iface.addrs:
        extra = ["nodad"] if a.version == 6 else []
        out.append(ip(node.ns, "addr", "replace", str(a), "dev", iface.name, *extra))
    return out


def route_cmds(node, only_iface=None):
    out = []
    for i in node.ifaces.values():
        if only_iface and i.name != only_iface:
            continue
        if i.gateway:
            out.append(ip(node.ns, "route", "replace", "default", "via", str(i.gateway), "dev", i.name))
        if i.gateway6:
            out.append(ip(node.ns, "-6", "route", "replace", "default", "via", str(i.gateway6), "dev", i.name))
    for r in node.routes:
        if only_iface and r.iface != only_iface:
            continue
        fam = ["-6"] if r.version == 6 else []
        out.append(ip(node.ns, *fam, "route", "replace", *r.args))
    return out


def up_actions(t):
    """Everything `up` does, in order. Namespaces are created fresh (down runs first)."""
    A = [Mkdir(t.rundir), Mkdir(t.logdir)] + [Mkdir(n.dir) for n in t.nodes.values()]

    for s in t.segments.values():
        A += [Cmd(["ip", "netns", "add", s.ns]),
              ip(s.ns, "link", "set", "lo", "up"),
              # The switch is pure L2: no link-local addresses, no ND/MLD chatter of its own.
              nsexec(s.ns, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1",
                     "net.ipv6.conf.default.disable_ipv6=1"),
              ip(s.ns, "link", "add", BRIDGE, "type", "bridge", "stp_state", "0", "forward_delay", "0",
                 "mcast_snooping", "0"),
              ip(s.ns, "link", "set", BRIDGE, "up")]
    for n in t.nodes.values():
        A += [Cmd(["ip", "netns", "add", n.ns]), ip(n.ns, "link", "set", "lo", "up")]

    for n in t.nodes.values():
        for i in n.ifaces.values():
            s = t.segments[i.segment]
            A.append(ip(s.ns, "link", "add", i.port, "type", "veth", "peer", "name", i.name, "netns", n.ns))
            if i.mtu:
                A += [ip(s.ns, "link", "set", i.port, "mtu", str(i.mtu)),
                      ip(n.ns, "link", "set", i.name, "mtu", str(i.mtu))]
            if i.mac:
                A.append(ip(n.ns, "link", "set", i.name, "address", i.mac))
            A += [ip(s.ns, "link", "set", i.port, "master", BRIDGE, "up"),
                  ip(n.ns, "link", "set", i.name, "up")]
            if not t.offload:
                # Segment in the sender like a real NIC so netem drops single packets, not
                # 64 KB super-packets. Best effort: ethtool may be missing.
                A.append(nsexec(n.ns, "ethtool", "-K", i.name, "tso", "off", "gso", "off", "gro", "off",
                                check=False))

    for n in t.nodes.values():
        for k, v in n.sysctl.items():
            A.append(nsexec(n.ns, "sysctl", "-qw", f"{k}={v}"))
        for i in n.ifaces.values():
            A += addr_cmds(n, i)

    for ns, dev, params in t.netem_devices().values():
        if params:
            A.append(netem_cmd(ns, dev, params))

    for n in t.nodes.values():
        A += route_cmds(n)

    for n in t.nodes.values():
        rules = nft_rules(n)
        if rules:
            path = os.path.join(n.dir, "sim-rules.nft")
            A += [Write(path, rules.encode()), nsexec(n.ns, "nft", "-f", path)]
        for f in n.nftables:
            A.append(nsexec(n.ns, "nft", "-f", f))

    for n in t.nodes.values():
        for rel, (content, mode) in n.files.items():
            path = os.path.join(n.dir, rel)
            if os.path.dirname(rel):
                A.append(Mkdir(os.path.dirname(path)))
            A.append(Write(path, content, mode))
        for k, c in enumerate(n.start):
            A.append(Spawn(n.ns, c, os.path.join(t.logdir, f"{n.name}.log"), n.dir,
                           os.path.join(n.dir, f"start{k}.pid"), sim_env(t, n)))
    return A


def sim_env(t, n):
    return {"SIM_NODE": n.name, "SIM_PREFIX": t.prefix, "SIM_RUN": t.rundir}


def down_actions(t, extra_ns=()):
    """Teardown. Deleting a namespace removes its veths and bridge; processes are killed first."""
    names = t.namespaces() + [ns for ns in extra_ns if ns not in t.namespaces()]
    return [KillNs(ns) for ns in names] + [DelNs(ns) for ns in names] + [Remove(t.state_file)]


def state_json(t, netem_state, fingerprint):
    return json.dumps({"name": t.name, "prefix": t.prefix, "vars": t.vars, "fingerprint": fingerprint,
                       "netem": netem_state}, indent=2).encode()


def plan_text(actions):
    return "\n".join(a.shell() for a in actions) + "\n"


def link_actions(t, node, ifname, state, admin=False):
    """Cut or restore a link. Default: bridge port (cable pulled, node sees no carrier)."""
    n = t.node(node)
    i = t.iface(node, ifname)
    s = t.segments[i.segment]
    if not admin:
        return [ip(s.ns, "link", "set", i.port, state)]
    A = [ip(n.ns, "link", "set", i.name, state)]
    if state == "up":
        # Taking a link down flushes its routes (and IPv6 addresses); put them back.
        A += addr_cmds(n, i) + route_cmds(n, only_iface=i.name)
    return A


def netem_targets(t, node=None, ifname=None, segment=None, direction="out"):
    """Keys of netem_devices() addressed by a runtime change."""
    if segment:
        seg = t.segment(segment)
        return [f"{i.node}/{i.name}/in" for i in seg.ports]
    t.iface(node, ifname)
    dirs = {"out": ["out"], "in": ["in"], "both": ["out", "in"]}[direction]
    return [f"{node}/{ifname}/{d}" for d in dirs]
