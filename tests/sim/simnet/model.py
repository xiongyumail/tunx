"""Topology model: load YAML, expand variables, validate, resolve names."""
import ipaddress
import os
import re
from dataclasses import dataclass, field

import yaml

from . import SchemaError
from . import netem as netem_mod
from .util import as_list, check_map, subst, suggest, type_name

SIM_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
IFNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,14}$")
PREFIX_RE = re.compile(r"^[a-z][a-z0-9]{0,7}$")
VARNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SYSCTL_RE = re.compile(r"^[a-z0-9_]+(\.[A-Za-z0-9_.-]+)+$")
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)

TOP_KEYS = {"name", "prefix", "rundir", "vars", "offload", "segments", "nodes"}
SEG_KEYS = {"subnet", "netem", "mtu"}
NODE_KEYS = {"interfaces", "forward", "routes", "sysctl", "nftables", "firewall", "files", "start"}
IF_KEYS = {"segment", "addr", "gateway", "gateway6", "netem", "netem_in", "nat", "mtu", "mac"}
ROUTE_KEYS = {"to", "via", "dev", "metric", "onlink"}
FW_KEYS = {"iif", "oif", "allow", "default", "local"}
RULE_KEYS = {"proto", "to", "from", "ports"}
FILE_KEYS = {"content", "src", "mode"}
BRIDGE = "br0"
DEFAULT_RUNROOT = "/run/tunx-sim"


@dataclass
class Segment:
    name: str
    ns: str
    subnets: list
    netem: dict
    mtu: int = None
    ports: list = field(default_factory=list)  # Iface objects attached here


@dataclass
class Iface:
    node: str
    name: str
    segment: str
    port: str  # bridge-side veth name inside the segment namespace
    addrs: list
    gateway: object = None
    gateway6: object = None
    netem: dict = field(default_factory=dict)      # node egress
    netem_in: dict = None                          # node ingress (bridge port egress); None = segment's
    nat: str = None
    mtu: int = None
    mac: str = None

    def first(self, version):
        for a in self.addrs:
            if a.version == version:
                return a
        return None


@dataclass
class Route:
    version: int
    args: list  # after 'ip route replace'
    iface: str  # interface the route leaves through (for re-applying after a link comes back)

    @property
    def text(self):
        return " ".join(self.args)


@dataclass
class FwRule:
    proto: str
    src: object
    dst: object
    ports: list


@dataclass
class Firewall:
    iif: str
    oif: str
    allow: list
    default: str
    local: bool


@dataclass
class Node:
    name: str
    ns: str
    dir: str
    ifaces: dict
    sysctl: dict
    routes: list
    nftables: list
    firewall: list
    files: dict   # relative path -> (content bytes, mode)
    start: list


@dataclass
class Topology:
    name: str
    path: str
    prefix: str
    rundir: str
    vars: dict
    segments: dict
    nodes: dict
    offload: bool = False  # keep TSO/GSO/GRO on veths (faster, but netem loss hits 64 KB super-packets)

    @property
    def topo_dir(self):
        return os.path.dirname(self.path)

    @property
    def logdir(self):
        return os.path.join(self.rundir, "logs")

    @property
    def state_file(self):
        return os.path.join(self.rundir, "state.json")

    def namespaces(self):
        return [s.ns for s in self.segments.values()] + [n.ns for n in self.nodes.values()]

    def node(self, name):
        if name not in self.nodes:
            raise SchemaError(f"unknown node '{name}'" + suggest(name, self.nodes))
        return self.nodes[name]

    def iface(self, node, name):
        n = self.node(node)
        if name not in n.ifaces:
            raise SchemaError(f"node '{node}' has no interface '{name}'" + suggest(name, n.ifaces))
        return n.ifaces[name]

    def segment(self, name):
        if name not in self.segments:
            raise SchemaError(f"unknown segment '{name}'" + suggest(name, self.segments))
        return self.segments[name]

    def netem_devices(self):
        """Every qdisc the topology manages: key -> (ns, dev, base params)."""
        out = {}
        for n in self.nodes.values():
            for i in n.ifaces.values():
                seg = self.segments[i.segment]
                out[f"{n.name}/{i.name}/out"] = (n.ns, i.name, dict(i.netem))
                base_in = seg.netem if i.netem_in is None else i.netem_in
                out[f"{n.name}/{i.name}/in"] = (seg.ns, i.port, dict(base_in))
        return out

    def resolve(self, name, extra=None):
        """Variable lookup shared by topology and scenario files."""
        if extra and name in extra:
            return extra[name]
        return _resolver(self.vars, self.prefix, self.rundir, self.topo_dir,
                         {n: {i: f.addrs for i, f in node.ifaces.items()} for n, node in self.nodes.items()})(name)


def _addr_ref(table, prefix, rundir, name):
    """${node.if}, ${node.if.v6}, ${node.ns}, ${node.dir}, ${node} (first IPv4)."""
    parts = name.split(".")
    node = parts[0]
    if node not in table:
        return None
    if len(parts) == 1:
        for addrs in table[node].values():
            for a in addrs:
                if a.version == 4:
                    return str(a.ip)
        return None
    if len(parts) == 2 and parts[1] == "ns":
        return f"{prefix}-{node}"
    if len(parts) == 2 and parts[1] == "dir":
        return os.path.join(rundir, "nodes", node)
    ifname = parts[1]
    if ifname not in table[node] or len(parts) > 3:
        return None
    kind = parts[2] if len(parts) == 3 else "v4"
    want = {"v4": 4, "v6": 6, "cidr": 4, "cidr6": 6}.get(kind)
    for a in table[node][ifname]:
        if a.version == want:
            return str(a) if kind.startswith("cidr") else str(a.ip)
    return None


def _resolver(vars_, prefix, rundir, topo_dir, table):
    builtins = {"sim": SIM_DIR, "run": rundir, "prefix": prefix, "topo": topo_dir}

    def resolve(name):
        if name in vars_:
            return vars_[name]
        if name in builtins:
            return builtins[name]
        if name.startswith("env."):
            return os.environ.get(name[4:])
        if table is not None:
            return _addr_ref(table, prefix, rundir, name)
        return None
    return resolve


def _net(v, path, strict=True):
    try:
        return ipaddress.ip_network(str(v), strict=strict)
    except ValueError as e:
        raise SchemaError(f"{path}: invalid network '{v}' ({e})") from None


def _ip(v, path):
    try:
        return ipaddress.ip_address(str(v))
    except ValueError:
        raise SchemaError(f"{path}: invalid IP address '{v}'") from None


def _mtu(v, path):
    if v is None:
        return None
    if not isinstance(v, int) or isinstance(v, bool) or not 576 <= v <= 65535:
        raise SchemaError(f"{path}: mtu must be a number between 576 and 65535, got {v!r}")
    return v


def _port_name(node, ifname, used):
    name = f"{node}-{ifname}"
    k = 0
    while len(name) > 15 or name in used:
        k += 1
        name = f"{node[:10]}-p{k}"
    used.add(name)
    return name


def load(path, overrides=None, prefix=None, rundir=None):
    """Load and validate a topology file. `overrides` replaces declared vars."""
    path = os.path.abspath(path)
    try:
        with open(path) as f:
            raw = yaml.safe_load(f)
    except OSError as e:
        raise SchemaError(f"{path}: cannot read ({e.strerror})") from None
    except yaml.YAMLError as e:
        raise SchemaError(f"{path}: YAML syntax error: {e}") from None
    return build(raw, path, overrides, prefix, rundir)


def build(raw, path, overrides=None, prefix=None, rundir=None):
    if raw is None:
        raw = {}
    check_map(raw, "topology", TOP_KEYS, required=("nodes",))
    name = str(raw.get("name") or os.path.splitext(os.path.basename(path))[0])

    vars_ = raw.get("vars") or {}
    check_map(vars_, "vars", vars_.keys())
    for k, v in vars_.items():
        if not VARNAME_RE.match(str(k)):
            raise SchemaError(f"vars.{k}: variable names use letters, digits and '_'")
        if isinstance(v, (dict, list)):
            raise SchemaError(f"vars.{k}: expected a scalar value, got {type_name(v)}")
    vars_ = {k: "" if v is None else str(v) for k, v in vars_.items()}
    for k, v in (overrides or {}).items():
        if k not in vars_:
            raise SchemaError(f"--set {k}: not a variable of this topology" + suggest(k, vars_))
        vars_[k] = str(v)

    prefix = prefix or os.environ.get("SIM_PREFIX") or raw.get("prefix") or re.sub(r"[^a-z0-9]", "", name.lower())[:8]
    if not PREFIX_RE.match(str(prefix)):
        raise SchemaError(f"prefix: '{prefix}' must be 1-8 lowercase letters/digits starting with a letter")
    rundir = rundir or os.environ.get("SIM_RUNDIR") or raw.get("rundir") or os.path.join(DEFAULT_RUNROOT, prefix)
    rundir = os.path.abspath(str(rundir))
    topo_dir = os.path.dirname(path)

    vars_ = {k: subst(v, _resolver({}, prefix, rundir, topo_dir, None), f"vars.{k}") for k, v in vars_.items()}
    early = _resolver(vars_, prefix, rundir, topo_dir, None)

    # Segments.
    segs_raw = raw.get("segments") or {}
    check_map(segs_raw, "segments", segs_raw.keys())
    segments = {}
    for sname, s in segs_raw.items():
        p = f"segments.{sname}"
        if not NAME_RE.match(str(sname)):
            raise SchemaError(f"{p}: names use lowercase letters, digits and '-', start with a letter, max 24 chars")
        s = subst(s or {}, early, p)
        check_map(s, p, SEG_KEYS)
        subnets = [_net(n, f"{p}.subnet") for n in as_list(s.get("subnet"))]
        if len({n.version for n in subnets}) != len(subnets):
            raise SchemaError(f"{p}.subnet: at most one IPv4 and one IPv6 subnet")
        segments[sname] = Segment(sname, f"{prefix}-sw-{sname}", subnets,
                                  netem_mod.normalize(s.get("netem"), f"{p}.netem"),
                                  _mtu(s.get("mtu"), f"{p}.mtu"))

    # Nodes, pass 1: names and addresses (needed by ${node.if} references).
    nodes_raw = raw["nodes"]
    check_map(nodes_raw, "nodes", nodes_raw.keys() if isinstance(nodes_raw, dict) else ())
    if not nodes_raw:
        raise SchemaError("nodes: at least one node is required")
    table = {}
    for nname, n in nodes_raw.items():
        p = f"nodes.{nname}"
        if not NAME_RE.match(str(nname)):
            raise SchemaError(f"{p}: names use lowercase letters, digits and '-', start with a letter, max 24 chars")
        if str(nname).startswith("sw-"):
            raise SchemaError(f"{p}: node names may not start with 'sw-' (reserved for segments)")
        check_map(n or {}, p, NODE_KEYS, required=("interfaces",))
        ifs = n["interfaces"]
        check_map(ifs, f"{p}.interfaces", ifs.keys() if isinstance(ifs, dict) else ())
        if not ifs:
            raise SchemaError(f"{p}.interfaces: at least one interface is required")
        table[nname] = {}
        for ifname, i in ifs.items():
            ip_ = f"{p}.interfaces.{ifname}"
            if not IFNAME_RE.match(str(ifname)) or ifname == "lo":
                raise SchemaError(f"{ip_}: interface names are 1-15 chars [A-Za-z0-9_.-], start with a letter, not 'lo'")
            check_map(i, ip_, IF_KEYS, required=("segment",))
            seg = str(i["segment"])
            if seg not in segments:
                raise SchemaError(f"{ip_}.segment: unknown segment '{seg}'" + suggest(seg, segments))
            table[nname][ifname] = _addrs(subst(i.get("addr"), early, f"{ip_}.addr"), segments[seg], f"{ip_}.addr")

    full = _resolver(vars_, prefix, rundir, topo_dir, table)

    # Nodes, pass 2: everything else.
    nodes = {}
    seen_addr = {}
    used_ports = {s: set() for s in segments}
    for nname, n in nodes_raw.items():
        p = f"nodes.{nname}"
        n = subst(n, full, p)
        ns = f"{prefix}-{nname}"
        ifaces = {}
        for ifname, i in n["interfaces"].items():
            ip_ = f"{p}.interfaces.{ifname}"
            seg = segments[i["segment"]]
            addrs = table[nname][ifname]
            for a in addrs:
                key = (seg.name, a.ip)
                if key in seen_addr:
                    raise SchemaError(f"{ip_}.addr: {a.ip} is already used by {seen_addr[key]} on segment {seg.name}")
                seen_addr[key] = f"{nname}.{ifname}"
            gw = _gateway(i.get("gateway"), 4, addrs, f"{ip_}.gateway")
            gw6 = _gateway(i.get("gateway6"), 6, addrs, f"{ip_}.gateway6")
            nat = i.get("nat")
            if nat not in (None, "masquerade"):
                raise SchemaError(f"{ip_}.nat: only 'masquerade' is supported, got {nat!r}")
            mac = i.get("mac")
            if mac is not None and not MAC_RE.match(str(mac)):
                raise SchemaError(f"{ip_}.mac: invalid MAC address '{mac}'")
            iface = Iface(nname, ifname, seg.name, _port_name(nname, ifname, used_ports[seg.name]), addrs,
                          gw, gw6, netem_mod.normalize(i.get("netem"), f"{ip_}.netem"),
                          netem_mod.normalize(i["netem_in"], f"{ip_}.netem_in") if "netem_in" in i else None,
                          nat, _mtu(i.get("mtu"), f"{ip_}.mtu") or seg.mtu, mac)
            seg.ports.append(iface)
            ifaces[ifname] = iface
        if len({i.gateway for i in ifaces.values() if i.gateway}) > 1:
            raise SchemaError(f"{p}: more than one interface sets 'gateway'; use routes with a metric instead")
        if len({i.gateway6 for i in ifaces.values() if i.gateway6}) > 1:
            raise SchemaError(f"{p}: more than one interface sets 'gateway6'; use routes with a metric instead")

        sysctl = {}
        if n.get("forward"):
            sysctl["net.ipv4.ip_forward"] = "1"
            sysctl["net.ipv6.conf.all.forwarding"] = "1"
        sc = n.get("sysctl") or {}
        check_map(sc, f"{p}.sysctl", sc.keys())
        for k, v in sc.items():
            if not SYSCTL_RE.match(str(k)):
                raise SchemaError(f"{p}.sysctl: invalid key '{k}'")
            if isinstance(v, (dict, list)) or v is None:
                raise SchemaError(f"{p}.sysctl.{k}: expected a scalar value")
            sysctl[str(k)] = str(int(v) if isinstance(v, bool) else v)

        routes = [_route(r, ifaces, f"{p}.routes[{k}]") for k, r in enumerate(as_list(n.get("routes")))]
        fws = [_firewall(fw, ifaces, f"{p}.firewall[{k}]") for k, fw in enumerate(as_list(n.get("firewall")))]
        nft = []
        for k, f in enumerate(as_list(n.get("nftables"))):
            fp = os.path.join(topo_dir, str(f))
            if not os.path.isfile(fp):
                raise SchemaError(f"{p}.nftables[{k}]: file not found: {fp}")
            nft.append(fp)
        files = _files(n.get("files"), topo_dir, f"{p}.files")
        start = as_list(n.get("start"))
        for k, c in enumerate(start):
            if not isinstance(c, str) or not c.strip():
                raise SchemaError(f"{p}.start[{k}]: expected a shell command string")
        nodes[nname] = Node(nname, ns, os.path.join(rundir, "nodes", nname), ifaces, sysctl, routes,
                            nft, fws, files, start)

    offload = raw.get("offload", False)
    if not isinstance(offload, bool):
        raise SchemaError(f"offload: expected true or false, got {offload!r}")
    return Topology(name, path, prefix, rundir, vars_, segments, nodes, offload)


def _addrs(v, seg, path):
    out = []
    for k, a in enumerate(as_list(v)):
        p = f"{path}[{k}]" if isinstance(v, list) else path
        s = str(a)
        if "/" not in s:
            ip = _ip(s, p)
            net = next((n for n in seg.subnets if n.version == ip.version), None)
            if net is None:
                raise SchemaError(f"{p}: '{s}' needs a prefix length (segment {seg.name} has no IPv{ip.version} subnet)")
            s = f"{s}/{net.prefixlen}"
        try:
            ifa = ipaddress.ip_interface(s)
        except ValueError:
            raise SchemaError(f"{p}: invalid address '{a}' (expected e.g. 10.0.1.1/24)") from None
        for net in seg.subnets:
            if net.version == ifa.version and ifa.ip not in net:
                raise SchemaError(f"{p}: {ifa.ip} is outside segment {seg.name} subnet {net}")
        if ifa.ip == ifa.network.network_address and ifa.network.prefixlen < ifa.max_prefixlen - 1:
            raise SchemaError(f"{p}: {ifa} is the network address")
        out.append(ifa)
    return out


def _gateway(v, version, addrs, path):
    if v is None:
        return None
    ip = _ip(v, path)
    if ip.version != version:
        raise SchemaError(f"{path}: expected an IPv{version} address, got {ip}")
    if not any(a.version == version and ip in a.network for a in addrs):
        raise SchemaError(f"{path}: {ip} is not on this interface's subnets "
                          f"({', '.join(str(a.network) for a in addrs) or 'no addresses'})")
    return ip


def _route(r, ifaces, path):
    if isinstance(r, str):
        tokens = r.split()
        if not tokens:
            raise SchemaError(f"{path}: empty route")
        to, opts = tokens[0], tokens[1:]
        kv, flags, k = {}, [], 0
        while k < len(opts):
            if opts[k] == "onlink":
                flags.append("onlink")
                k += 1
                continue
            if k + 1 >= len(opts):
                raise SchemaError(f"{path}: '{opts[k]}' needs a value in route '{r}'")
            kv[opts[k]] = opts[k + 1]
            k += 2
        for key in kv:
            if key not in ("via", "dev", "metric", "src", "table", "mtu", "proto"):
                raise SchemaError(f"{path}: unsupported route option '{key}' in '{r}'")
    elif isinstance(r, dict):
        check_map(r, path, ROUTE_KEYS, required=("to",))
        to = str(r["to"])
        kv = {k: str(r[k]) for k in ("via", "dev", "metric") if k in r}
        flags = ["onlink"] if r.get("onlink") else []
    else:
        raise SchemaError(f"{path}: expected a string like '10.0.2.0/24 via 10.0.1.2' or a mapping, got {type_name(r)}")

    version = None
    if to not in ("default", "default6"):
        version = _net(to, f"{path}.to").version
    via = _ip(kv["via"], f"{path}.via") if "via" in kv else None
    if via:
        if version and via.version != version:
            raise SchemaError(f"{path}: destination {to} and gateway {via} are different IP versions")
        version = via.version
    if to == "default6":
        to, version = "default", 6
    version = version or 4
    dev = kv.get("dev")
    if dev and dev not in ifaces:
        raise SchemaError(f"{path}.dev: unknown interface '{dev}'" + suggest(dev, ifaces))
    if via and "onlink" not in flags:
        hits = [i.name for i in ifaces.values() if any(a.version == via.version and via in a.network for a in i.addrs)]
        if not hits:
            raise SchemaError(f"{path}: gateway {via} is not on any connected subnet of this node "
                              f"(add 'onlink' if that is intended)")
        dev = dev or hits[0]
    if not via and not dev:
        raise SchemaError(f"{path}: a route needs 'via' or 'dev'")
    if "onlink" in flags and not kv.get("dev"):
        raise SchemaError(f"{path}: an 'onlink' route needs 'dev'")
    args = [to] + [x for k, v in kv.items() for x in (k, v)] + flags
    return Route(version, args, dev)


def _ports(v, path):
    out = []
    for p in as_list(v):
        for part in str(p).split(","):
            part = part.strip()
            m = re.match(r"^(\d+)(?:-(\d+))?$", part)
            if not m or not all(0 < int(x) < 65536 for x in m.groups() if x):
                raise SchemaError(f"{path}: invalid port '{part}' (expected e.g. 443, '1000-2000')")
            out.append(part)
    return out


def _firewall(fw, ifaces, path):
    check_map(fw, path, FW_KEYS)
    for k in ("iif", "oif"):
        if k in fw and fw[k] not in ifaces:
            raise SchemaError(f"{path}.{k}: unknown interface '{fw[k]}'" + suggest(fw[k], ifaces))
    if not fw.get("iif") and not fw.get("oif"):
        raise SchemaError(f"{path}: set 'iif' and/or 'oif' to say which traffic is filtered")
    default = fw.get("default", "drop")
    if default not in ("drop", "reject", "accept"):
        raise SchemaError(f"{path}.default: expected drop, reject or accept, got {default!r}")
    rules = []
    for k, r in enumerate(as_list(fw.get("allow"))):
        rp = f"{path}.allow[{k}]"
        check_map(r, rp, RULE_KEYS)
        proto = str(r.get("proto", "any"))
        if proto not in ("tcp", "udp", "icmp", "any"):
            raise SchemaError(f"{rp}.proto: expected tcp, udp, icmp or any, got '{proto}'")
        ports = _ports(r.get("ports"), f"{rp}.ports")
        if ports and proto not in ("tcp", "udp"):
            raise SchemaError(f"{rp}.ports: ports need proto tcp or udp")
        src = _net(r["from"], f"{rp}.from", strict=False) if "from" in r else None
        dst = _net(r["to"], f"{rp}.to", strict=False) if "to" in r else None
        if src and dst and src.version != dst.version:
            raise SchemaError(f"{rp}: 'from' and 'to' are different IP versions")
        rules.append(FwRule(proto, src, dst, ports))
    return Firewall(fw.get("iif"), fw.get("oif"), rules, default, bool(fw.get("local", False)))


def _files(v, topo_dir, path):
    out = {}
    if v is None:
        return out
    check_map(v, path, v.keys())
    for rel, spec in v.items():
        p = f"{path}.{rel}"
        rel = str(rel)
        norm = os.path.normpath(rel)
        if os.path.isabs(rel) or norm.startswith(".."):
            raise SchemaError(f"{p}: file paths are relative to the node directory and may not leave it")
        mode = 0o644
        if isinstance(spec, str):
            content = spec.encode()
        else:
            check_map(spec, p, FILE_KEYS)
            if ("content" in spec) == ("src" in spec):
                raise SchemaError(f"{p}: set exactly one of 'content' or 'src'")
            if "src" in spec:
                src = os.path.join(topo_dir, str(spec["src"]))
                try:
                    with open(src, "rb") as f:
                        content = f.read()
                except OSError as e:
                    raise SchemaError(f"{p}.src: cannot read {src} ({e.strerror})") from None
            else:
                content = str(spec["content"]).encode()
            if "mode" in spec:
                m = spec["mode"]
                try:
                    mode = int(str(m), 8) if isinstance(m, str) else int(m)
                except ValueError:
                    raise SchemaError(f"{p}.mode: expected an octal mode like '0755'") from None
        out[norm] = (content, mode)
    return out
