#!/usr/bin/env python3
"""Self-test for the simulator. Needs no root: it only parses files and checks plans."""
import contextlib
import copy
import hashlib
import io
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import tarfile
import time
import unittest
import zipfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import sim  # noqa: E402
from simnet import SchemaError, model, netem, scenario  # noqa: E402
from simnet import runner as runner_mod  # noqa: E402
from simnet.actions import nft_rules, plan_text, up_actions  # noqa: E402

TOPO = os.path.join(HERE, "topologies", "two-sites.yaml")
SMOKE = os.path.join(HERE, "scenarios", "smoke.yaml")


def _forbid(*a, **k):
    raise AssertionError(f"a dry run tried to execute something: {a}")


@contextlib.contextmanager
def no_exec():
    """Fail the test if anything would really be executed."""
    with mock.patch.object(runner_mod.subprocess, "run", _forbid), \
            mock.patch.object(runner_mod.subprocess, "Popen", _forbid), \
            mock.patch.object(runner_mod.os, "makedirs", _forbid):
        yield


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with no_exec(), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = sim.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


def base():
    """A small valid topology as a dict, for mutation in error tests."""
    return {
        "name": "t", "prefix": "t",
        "segments": {"lan": {"subnet": "10.9.0.0/24"}, "wan": {"subnet": ["192.0.2.0/24", "2001:db8::/64"]}},
        "nodes": {
            "r": {"forward": True, "interfaces": {
                "wan0": {"segment": "wan", "addr": ["192.0.2.1", "2001:db8::1"], "nat": "masquerade"},
                "lan0": {"segment": "lan", "addr": "10.9.0.1"}}},
            "h": {"interfaces": {"eth0": {"segment": "lan", "addr": "10.9.0.2", "gateway": "10.9.0.1"}},
                  "routes": ["10.8.0.0/16 via 10.9.0.1"]},
        },
    }


def build(raw, **kw):
    return model.build(raw, "/nonexistent/t.yaml", **kw)


class TestTopology(unittest.TestCase):
    def test_two_sites_loads(self):
        t = model.load(TOPO)
        self.assertEqual(t.prefix, "ts")
        self.assertEqual(set(t.segments), {"internet", "mobile", "lan-a", "lan-b"})
        self.assertEqual(set(t.nodes), {"hub", "exit", "phone", "web", "router-a", "gw-a", "term-a",
                                        "carrier", "router-b", "gw-b", "host-b"})
        hub = t.iface("hub", "eth0")
        self.assertEqual([str(a) for a in hub.addrs], ["203.0.113.10/24", "2001:db8:113::10/64"])
        self.assertEqual(t.nodes["router-a"].routes[0].iface, "lan0")
        self.assertEqual(t.segments["mobile"].netem, {"delay": "40ms", "loss": "0%"})
        self.assertEqual(str(t.nodes["carrier"].firewall[0].allow[0].dst), "203.0.113.10/32")

    def test_vars_override_and_refs(self):
        t = model.load(TOPO, {"mobile_loss": "3%"}, prefix="xy", rundir="/tmp/x")
        self.assertEqual(t.segments["mobile"].netem["loss"], "3%")
        self.assertEqual(t.resolve("hub.eth0"), "203.0.113.10")
        self.assertEqual(t.resolve("hub.eth0.v6"), "2001:db8:113::10")
        self.assertEqual(t.resolve("hub.eth0.cidr"), "203.0.113.10/24")
        self.assertEqual(t.resolve("gw-b"), "10.0.2.2")
        self.assertEqual(t.resolve("hub.ns"), "xy-hub")
        self.assertEqual(t.resolve("run"), "/tmp/x")
        self.assertIsNone(t.resolve("hub.eth9"))

    def test_minimal_ok(self):
        t = build(base())
        self.assertEqual(t.nodes["h"].routes[0].iface, "eth0")
        self.assertEqual(t.nodes["r"].sysctl["net.ipv4.ip_forward"], "1")


class TestSchemaErrors(unittest.TestCase):
    def check(self, mutate, pattern, **kw):
        raw = copy.deepcopy(base())
        mutate(raw)
        with self.assertRaises(SchemaError) as cm:
            build(raw, **kw)
        self.assertRegex(str(cm.exception), pattern)

    def test_unknown_top_key_suggests(self):
        self.check(lambda r: r.update(segmnts={}), r"topology: unknown key 'segmnts' \(did you mean 'segments'\?\)")

    def test_unknown_iface_key(self):
        self.check(lambda r: r["nodes"]["h"]["interfaces"]["eth0"].update(adr="1.2.3.4"),
                   r"nodes\.h\.interfaces\.eth0: unknown key 'adr' \(did you mean 'addr'\?\)")

    def test_unknown_segment(self):
        self.check(lambda r: r["nodes"]["h"]["interfaces"]["eth0"].update(segment="lna"),
                   r"segment: unknown segment 'lna' \(did you mean 'lan'\?\)")

    def test_bad_address(self):
        self.check(lambda r: r["nodes"]["h"]["interfaces"]["eth0"].update(addr="10.9.0.300"),
                   r"nodes\.h\.interfaces\.eth0\.addr: invalid IP address '10\.9\.0\.300'")

    def test_address_outside_subnet(self):
        self.check(lambda r: r["nodes"]["h"]["interfaces"]["eth0"].update(addr="10.7.0.2/24"),
                   r"10\.7\.0\.2 is outside segment lan subnet 10\.9\.0\.0/24")

    def test_duplicate_address(self):
        self.check(lambda r: r["nodes"]["h"]["interfaces"]["eth0"].update(addr="10.9.0.1"),
                   r"10\.9\.0\.1 is already used by r\.lan0 on segment lan")

    def test_gateway_off_link(self):
        self.check(lambda r: r["nodes"]["h"]["interfaces"]["eth0"].update(gateway="10.1.1.1"),
                   r"gateway: 10\.1\.1\.1 is not on this interface's subnets \(10\.9\.0\.0/24\)")

    def test_route_via_off_link(self):
        self.check(lambda r: r["nodes"]["h"].update(routes=["10.8.0.0/16 via 172.16.0.1"]),
                   r"routes\[0\]: gateway 172\.16\.0\.1 is not on any connected subnet")

    def test_route_host_bits(self):
        self.check(lambda r: r["nodes"]["h"].update(routes=["10.8.0.1/16 via 10.9.0.1"]),
                   r"routes\[0\]\.to: invalid network '10\.8\.0\.1/16'")

    def test_bad_netem(self):
        self.check(lambda r: r["segments"]["lan"].update(netem={"delay": "40 ms"}),
                   r"segments\.lan\.netem\.delay: bad value '40 ms' \(expected something like '40ms'\)")
        self.check(lambda r: r["segments"]["lan"].update(netem={"los": "1%"}),
                   r"unknown netem key 'los' \(did you mean 'loss'\?\)")
        self.check(lambda r: r["segments"]["lan"].update(netem={"reorder": "10%"}),
                   r"'reorder' needs 'delay'")

    def test_ifname_too_long(self):
        def m(r):
            r["nodes"]["h"]["interfaces"]["averyveryverylongname"] = {"segment": "lan"}
        self.check(m, r"interface names are 1-15 chars")

    def test_bad_prefix(self):
        self.check(lambda r: r.update(prefix="Bad-Prefix"), r"prefix: 'Bad-Prefix' must be")

    def test_unknown_set(self):
        self.check(lambda r: r.update(vars={"loss": "0%"}), r"--set los: not a variable.*did you mean 'loss'",
                   overrides={"los": "1%"})

    def test_unknown_variable(self):
        self.check(lambda r: r["nodes"]["h"].update(start=["run ${nope}"]), r"nodes\.h.*unknown variable '\$\{nope\}'")

    def test_nat_value(self):
        self.check(lambda r: r["nodes"]["r"]["interfaces"]["wan0"].update(nat="snat"), r"only 'masquerade'")

    def test_firewall(self):
        self.check(lambda r: r["nodes"]["r"].update(firewall=[{"iif": "wan1"}]),
                   r"firewall\[0\]\.iif: unknown interface 'wan1' \(did you mean 'wan0'\?\)")
        self.check(lambda r: r["nodes"]["r"].update(firewall=[{"iif": "lan0", "allow": [{"proto": "icmp", "ports": 1}]}]),
                   r"ports need proto tcp or udp")

    def test_onlink_needs_dev(self):
        self.check(lambda r: r["nodes"]["h"].update(routes=["10.8.0.0/16 via 172.16.0.1 onlink"]),
                   r"routes\[0\]: an 'onlink' route needs 'dev'")

    def test_files_escape(self):
        self.check(lambda r: r["nodes"]["h"].update(files={"../x": "y"}), r"may not leave it")

    def test_node_name(self):
        def m(r):
            r["nodes"]["Bad_Name"] = r["nodes"].pop("h")
        self.check(m, r"nodes\.Bad_Name: names use lowercase")

    def test_yaml_syntax(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("nodes: [unclosed\n")
        try:
            with self.assertRaisesRegex(SchemaError, "YAML syntax error"):
                model.load(f.name)
        finally:
            os.unlink(f.name)


class TestPlan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rc, cls.out, err = run_cli("plan", TOPO)
        assert rc == 0, err
        cls.lines = cls.out.splitlines()

    def has(self, line):
        self.assertIn(line, self.lines)

    def test_namespaces_and_bridges(self):
        for n in ("hub", "exit", "phone", "router-a", "gw-a", "term-a", "router-b", "gw-b", "host-b", "carrier"):
            self.has(f"ip netns add ts-{n}")
            self.has(f"ip netns del ts-{n}")
        for s in ("internet", "mobile", "lan-a", "lan-b"):
            self.has(f"ip netns add ts-sw-{s}")
            self.has(f"ip -n ts-sw-{s} link add br0 type bridge stp_state 0 forward_delay 0 mcast_snooping 0")

    def test_veths(self):
        self.has("ip -n ts-sw-lan-a link add term-a-eth0 type veth peer name eth0 netns ts-term-a")
        self.has("ip -n ts-sw-lan-a link set term-a-eth0 master br0 up")
        self.has("ip -n ts-sw-mobile link add router-b-wan0 type veth peer name wan0 netns ts-router-b")
        self.has("ip -n ts-term-a link set eth0 up")

    def test_addresses_routes_sysctl(self):
        self.has("ip -n ts-hub addr replace 203.0.113.10/24 dev eth0")
        self.has("ip -n ts-hub addr replace 2001:db8:113::10/64 dev eth0 nodad")
        self.has("ip -n ts-term-a route replace default via 10.0.1.1 dev eth0")
        self.has("ip -n ts-router-a route replace 10.0.2.0/24 via 10.0.1.2")
        self.has("ip -n ts-router-b route replace 10.0.1.0/24 via 10.0.2.2")
        self.has("ip -n ts-router-b route replace default via 100.64.0.1 dev wan0")
        self.has("ip netns exec ts-router-a sysctl -qw net.ipv4.ip_forward=1")

    def test_nat_and_firewall(self):
        self.has('    oifname "wan0" masquerade')
        self.has("ip netns exec ts-router-a nft -f /run/tunx-sim/ts/nodes/router-a/sim-rules.nft")
        self.has("ip netns exec ts-carrier nft -f /run/tunx-sim/ts/nodes/carrier/sim-rules.nft")
        self.has('    iifname "mob0" ip daddr 203.0.113.10 tcp dport { 443, 4430 } accept')
        self.has('    iifname "mob0" drop')

    def test_netem(self):
        self.has("tc -n ts-sw-mobile qdisc replace dev router-b-wan0 root netem limit 10000 delay 40ms loss 0%")
        self.has("tc -n ts-sw-mobile qdisc replace dev carrier-mob0 root netem limit 10000 delay 40ms loss 0%")
        self.assertEqual(sum("netem" in l for l in self.lines), 2)

    def test_daemons(self):
        self.assertTrue(any(l.startswith("(cd /run/tunx-sim/ts/nodes/hub && ip netns exec ts-hub ") and
                            "probe.py serve --tcp 443,8080" in l and ">>/run/tunx-sim/ts/logs/hub.log 2>&1 &" in l
                            for l in self.lines))

    def test_teardown_order(self):
        down = self.lines[self.lines.index("### down"):]
        kills = [i for i, l in enumerate(down) if l.startswith("ip netns pids")]
        dels = [i for i, l in enumerate(down) if l.startswith("ip netns del")]
        self.assertEqual(len(kills), 15)
        self.assertEqual(len(dels), 15)
        self.assertLess(max(kills), min(dels))
        self.assertIn("rm -f /run/tunx-sim/ts/state.json", down)

    def test_no_unexpanded_vars(self):
        self.assertNotIn("${", self.out)

    def test_set_and_prefix(self):
        rc, out, _ = run_cli("plan", TOPO, "--set", "mobile_loss=3%", "--prefix", "zz", "--rundir", "/tmp/zz")
        self.assertEqual(rc, 0)
        self.assertIn("tc -n zz-sw-mobile qdisc replace dev router-b-wan0 root netem limit 10000 delay 40ms loss 3%",
                      out)
        # Every namespace referenced carries the prefix; nothing touches the host namespace.
        names = set(re.findall(r"(?:ip netns (?:add|del|exec|pids)|-n|netns) (\S+)", out))
        self.assertTrue(names)
        self.assertTrue(all(n.startswith("zz-") for n in names), names)
        for line in out.splitlines():
            if line.startswith(("ip ", "tc ")):
                self.assertRegex(line, r"^(ip netns |ip -n zz-|tc -n zz-)", line)

    def test_interface_names_fit(self):
        for m in re.finditer(r"link add (\S+) type veth peer name (\S+)", self.out):
            self.assertLessEqual(len(m.group(1)), 15)
            self.assertLessEqual(len(m.group(2)), 15)

    def test_long_names_get_short_ports(self):
        raw = base()
        raw["nodes"]["averylongnodename"] = {"interfaces": {"wan0": {"segment": "wan", "addr": "192.0.2.9"}}}
        t = build(raw)
        self.assertLessEqual(len(t.iface("averylongnodename", "wan0").port), 15)

    def test_feature_plan(self):
        raw = base()
        raw["offload"] = True
        r = raw["nodes"]["r"]
        r["sysctl"] = {"net.ipv4.conf.all.rp_filter": 0}
        r["interfaces"]["wan0"].update(netem={"loss": 1}, netem_in={"delay": "10ms"}, mac="02:00:00:00:00:01", mtu=1400)
        r["routes"] = ["default6 via 2001:db8::2", {"to": "2001:db8:5::/48", "via": "2001:db8::2", "metric": 10},
                       "10.8.0.0/16 via 192.0.2.99 dev wan0 onlink"]
        r["firewall"] = [{"oif": "wan0", "allow": [{"proto": "udp", "ports": "53,1000-2000"}], "default": "reject",
                          "local": True}]
        r["files"] = {"etc/a.conf": "x=${r.wan0} y=$${HOME}", "run.sh": {"content": "echo hi", "mode": "0755"}}
        r["start"] = ["exec ./run.sh"]
        t = build(raw)
        text = plan_text(up_actions(t))
        for line in ("ip netns exec t-r sysctl -qw net.ipv4.conf.all.rp_filter=0",
                     "ip -n t-r link set wan0 address 02:00:00:00:00:01",
                     "ip -n t-r link set wan0 mtu 1400",
                     "tc -n t-r qdisc replace dev wan0 root netem limit 10000 loss 1%",
                     "tc -n t-sw-wan qdisc replace dev r-wan0 root netem limit 10000 delay 10ms",
                     "ip -n t-r -6 route replace default via 2001:db8::2",
                     "ip -n t-r -6 route replace 2001:db8:5::/48 via 2001:db8::2 metric 10",
                     "ip -n t-r route replace 10.8.0.0/16 via 192.0.2.99 dev wan0 onlink",
                     '    oifname "wan0" udp dport { 53, 1000-2000 } accept',
                     '    oifname "wan0" reject',
                     "  chain output {",
                     "x=192.0.2.1 y=${HOME}",
                     "chmod 755 /run/tunx-sim/t/nodes/r/run.sh"):
            self.assertIn(line, text.splitlines())
        self.assertNotIn("ethtool", text)

    def test_plan_is_deterministic(self):
        rc, out, _ = run_cli("plan", TOPO)
        self.assertEqual(out, self.out)


class TestRuntime(unittest.TestCase):
    def setUp(self):
        self.t = model.load(TOPO)

    def test_netem_parse_merge(self):
        mode, upd = netem.parse_update(["loss", "3%", "rate=10mbit"], "x")
        self.assertEqual((mode, upd), ("set", {"loss": "3%", "rate": "10mbit"}))
        cur = netem.merge({"delay": "40ms", "loss": "0%"}, upd, "x")
        self.assertEqual(netem.tc_args(cur), ["limit", "10000", "delay", "40ms", "loss", "3%", "rate", "10mbit"])
        self.assertEqual(netem.merge(cur, {"loss": None}, "x"), {"delay": "40ms", "rate": "10mbit"})
        self.assertEqual(netem.parse_update("reset", "x"), ("reset", {}))
        with self.assertRaisesRegex(SchemaError, "unknown netem key 'los'"):
            netem.parse_update(["los", "3%"], "x")
        with self.assertRaisesRegex(SchemaError, "key/value pairs"):
            netem.parse_update(["loss"], "x")
        with self.assertRaisesRegex(SchemaError, "'jitter' needs 'delay'"):
            netem.merge({}, {"jitter": "5ms"}, "x")

    def test_netem_cli(self):
        rc, out, _ = run_cli("-n", "netem", TOPO, "router-b", "wan0", "loss", "3%", "--dir", "both")
        self.assertEqual(rc, 0)
        self.assertIn("tc -n ts-router-b qdisc replace dev wan0 root netem limit 10000 loss 3%", out)
        self.assertIn("tc -n ts-sw-mobile qdisc replace dev router-b-wan0 root netem limit 10000 delay 40ms loss 3%",
                      out)
        rc, out, _ = run_cli("-n", "netem", TOPO, "--segment", "mobile", "clear")
        self.assertIn("tc -n ts-sw-mobile qdisc del dev carrier-mob0 root  # errors ignored", out)

    def test_link_cli(self):
        rc, out, _ = run_cli("-n", "link", TOPO, "router-b", "wan0", "down")
        self.assertEqual(out.strip(), "ip -n ts-sw-mobile link set router-b-wan0 down")
        rc, out, _ = run_cli("-n", "link", TOPO, "router-a", "lan0", "up", "--admin")
        self.assertIn("ip -n ts-router-a link set lan0 up", out)
        self.assertIn("ip -n ts-router-a addr replace 10.0.1.1/24 dev lan0", out)
        self.assertIn("ip -n ts-router-a route replace 10.0.2.0/24 via 10.0.1.2", out)

    def test_exec_cli(self):
        rc, out, _ = run_cli("-n", "exec", TOPO, "term-a", "--", "ping", "-c1", "10.0.1.1")
        self.assertEqual(out.strip(), "ip netns exec ts-term-a ping -c1 10.0.1.1")

    def test_unknown_node_message(self):
        rc, _, err = run_cli("-n", "link", TOPO, "router-c", "wan0", "down")
        self.assertEqual(rc, 2)
        self.assertRegex(err, r"unknown node 'router-c' \(did you mean 'router-[ab]'\?\)")

    @unittest.skipIf(os.geteuid() == 0, "running as root would really bring the topology up")
    def test_root_guard(self):
        rc, _, err = run_cli("up", TOPO)
        self.assertEqual(rc, 1)
        self.assertIn("needs root", err)

    def test_nft_text(self):
        text = nft_rules(self.t.nodes["carrier"])
        self.assertIn("type nat hook postrouting priority srcnat; policy accept;", text)
        self.assertIn("type filter hook forward priority filter; policy accept;", text)
        self.assertIn("ct state established,related accept", text)
        self.assertEqual(nft_rules(self.t.nodes["hub"]), "")


class TestScenario(unittest.TestCase):
    def setUp(self):
        self.t = model.load(TOPO)

    def test_smoke_loads(self):
        s = scenario.load(SMOKE, self.t)
        self.assertGreater(len(s.steps), 20)
        acts = {st.action for st in s.steps}
        self.assertTrue({"exec", "wait_until", "measure", "netem", "link"} <= acts)
        nat = next(st for st in s.steps if st.name == "term-a reaches the hub through NAT")
        self.assertEqual(nat.value.split()[-3:], ["tcp", "203.0.113.10", "443"])
        self.assertEqual(nat.args["match"], "^peer 203.0.113.11 ")

    def test_smoke_dry_run(self):
        rc, out, err = run_cli("-n", "run", TOPO, SMOKE, "--set", "mobile_loss=1%")
        self.assertEqual(rc, 0, err)
        self.assertIn("dry run: 25 steps checked", out)
        self.assertNotIn("${", out)
        self.assertIn("ip netns exec ts-gw-b sh -c 'iperf3 -c 203.0.113.10 -p 4430 -t 5 -J --connect-timeout 3000'",
                      out)
        self.assertIn("loss 1%", out)

    def scen_error(self, text, pattern):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(text)
        try:
            with self.assertRaises(SchemaError) as cm:
                scenario.load(f.name, self.t)
            self.assertRegex(str(cm.exception), pattern)
        finally:
            os.unlink(f.name)

    def test_errors(self):
        self.scen_error("steps: []\n", r"steps: expected a non-empty list")
        self.scen_error("steps:\n  - exce: ls\n    node: hub\n", r"steps\[0\]: a step needs exactly one action.*did you mean 'exec'")
        self.scen_error("steps:\n  - exec: ls\n", r"steps\[0\] \(exec\): missing 'node'")
        self.scen_error("steps:\n  - exec: ls\n    node: hubb\n", r"steps\[0\] \(exec\)\.node: unknown node 'hubb' \(did you mean 'hub'\?\)")
        self.scen_error("steps:\n  - exec: ls\n    node: hub\n    timout: 3\n", r"unknown key 'timout' \(did you mean 'timeout'\?\)")
        self.scen_error("steps:\n  - exec: ls\n    node: hub\n    rc: maybe\n", r"\.rc: expected a number")
        self.scen_error("steps:\n  - link: sideways\n    node: hub\n    if: eth0\n", r"expected 'up' or 'down'")
        self.scen_error("steps:\n  - link: down\n    node: hub\n    if: eth1\n", r"steps\[0\] \(link\): node 'hub' has no interface 'eth1'")
        self.scen_error("steps:\n  - netem: {los: 1%}\n    segment: mobile\n", r"unknown netem key 'los'")
        self.scen_error("steps:\n  - netem: {loss: 1%}\n    segment: mobil\n", r"unknown segment 'mobil' \(did you mean 'mobile'\?\)")
        self.scen_error("steps:\n  - measure: ping\n    from: hub\n", r"missing 'to'")
        self.scen_error("steps:\n  - measure: iperf3\n    from: hub\n    server: exit\n    expect: {mbps: 1}\n",
                        r"expect: unknown key 'mbps' \(did you mean 'mbps_min'\?\)")
        self.scen_error("steps:\n  - exec: ls ${nothere}\n    node: hub\n", r"unknown variable '\$\{nothere\}'")
        self.scen_error("steps:\n  - exec: ls\n    node: hub\n    match: '('\n", r"invalid regex")

    def test_rc_and_match(self):
        self.assertTrue(scenario._rc_ok(1, "nonzero"))
        self.assertFalse(scenario._rc_ok(0, "nonzero"))
        self.assertTrue(scenario._rc_ok(2, [1, 2]))
        self.assertIsNone(scenario._check_output("peer 1.2.3.4 5", {"match": "^peer 1"}))
        self.assertIsNotNone(scenario._check_output("x", {"not_match": "x"}))


FAKE_IP = """#!/bin/sh
# Stand-in for ip/tc: logs the call and keeps a list of namespaces.
d="$FAKE_DIR"
echo "$(basename "$0") $*" >> "$d/log"
if [ "$(basename "$0")" = ip ] && [ "$1" = netns ]; then
  case "$2" in
    add) echo "$3" >> "$d/ns" ;;
    del) grep -vx "$3" "$d/ns" > "$d/ns.tmp"; mv "$d/ns.tmp" "$d/ns" ;;
    list) [ -f "$d/ns" ] && cat "$d/ns" ;;
  esac
fi
exit 0
"""

FAKE_SCEN = """
name: fake
steps:
  - exec: "true"
    node: hub
  - wait_until: "true"
    node: gw-b
  - netem: {loss: 3%}
    segment: mobile
  - netem: {rate: 5mbit}
    node: router-b
    if: wan0
    dir: both
  - link: down
    node: router-b
    if: wan0
  - link: up
    node: router-b
    if: wan0
    admin: true
  - background: exec sleep 1
    node: host-b
"""


class TestFakeRoot(unittest.TestCase):
    """Real (non-dry) code paths against stand-in ip/tc binaries; nothing touches the host network."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        bindir = os.path.join(self.dir, "bin")
        os.mkdir(bindir)
        for name in ("ip", "tc"):
            path = os.path.join(bindir, name)
            with open(path, "w") as f:
                f.write(FAKE_IP)
            os.chmod(path, 0o755)
        self.rundir = os.path.join(self.dir, "run")
        env = {"PATH": bindir + os.pathsep + os.environ["PATH"], "FAKE_DIR": self.dir}
        self.patches = [mock.patch.dict(os.environ, env), mock.patch.object(sim.ops.os, "geteuid", lambda: 0)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = sim.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def calls(self):
        with open(os.path.join(self.dir, "log")) as f:
            return f.read().splitlines()

    def ns(self):
        try:
            with open(os.path.join(self.dir, "ns")) as f:
                return f.read().split()
        except FileNotFoundError:
            return []

    def test_up_status_netem_link_down(self):
        rd = ["--rundir", self.rundir]
        rc, out, err = self.cli("up", TOPO, *rd)
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self.ns()), 15)
        self.assertTrue(os.path.exists(os.path.join(self.rundir, "state.json")))
        self.assertTrue(os.path.exists(os.path.join(self.rundir, "nodes", "carrier", "sim-rules.nft")))
        self.assertTrue(os.path.exists(os.path.join(self.rundir, "nodes", "hub", "start0.pid")))
        rc, out, _ = self.cli("up", TOPO, *rd)
        self.assertIn("already up", out)
        rc, out, _ = self.cli("status", TOPO, *rd)
        self.assertEqual(rc, 0, out)

        rc, out, err = self.cli("netem", TOPO, *rd, "--segment", "mobile", "loss", "3%")
        self.assertEqual(rc, 0, err)
        rc, out, err = self.cli("netem", TOPO, *rd, "--segment", "mobile", "rate", "10mbit")
        self.assertIn("tc -n ts-sw-mobile qdisc replace dev router-b-wan0 root netem limit 10000 delay 40ms "
                      "loss 3% rate 10mbit", self.calls())
        rc, out, _ = self.cli("status", TOPO, *rd)
        self.assertIn("netem router-b/wan0/in: delay=40ms loss=3% rate=10mbit", out)

        rc, out, err = self.cli("link", TOPO, *rd, "router-b", "wan0", "down")
        self.assertEqual(rc, 0, err)
        self.assertIn("ip -n ts-sw-mobile link set router-b-wan0 down", self.calls())

        rc, out, err = self.cli("down", TOPO, *rd)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.ns(), [])
        self.assertFalse(os.path.exists(os.path.join(self.rundir, "state.json")))
        rc, out, err = self.cli("down", TOPO, *rd)  # idempotent
        self.assertEqual(rc, 0, err)

    def test_down_after_partial_up_and_by_prefix(self):
        with open(os.path.join(self.dir, "ns"), "w") as f:
            f.write("ts-hub\nts-old-node\nother-ns\n")
        rc, out, err = self.cli("down", "--prefix", "ts")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.ns(), ["other-ns"])
        with open(os.path.join(self.dir, "ns"), "w") as f:
            f.write("ts-hub\nts-stale\n")
        rc, out, err = self.cli("down", TOPO, "--rundir", self.rundir)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.ns(), [])

    def test_run(self):
        scen = os.path.join(self.dir, "fake.yaml")
        with open(scen, "w") as f:
            f.write(FAKE_SCEN)
        results = os.path.join(self.dir, "results.json")
        rc, out, err = self.cli("run", TOPO, scen, "--rundir", self.rundir, "--results", results,
                                "--set", "mobile_loss=1%")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("result: 7 passed, 0 failed, 0 skipped -> PASS", out)
        with open(results) as f:
            doc = json.load(f)
        self.assertTrue(doc["passed"])
        self.assertEqual([st["status"] for st in doc["steps"]], ["pass"] * 7)
        self.assertEqual(doc["vars"]["mobile_loss"], "1%")
        calls = self.calls()
        self.assertIn("tc -n ts-sw-mobile qdisc replace dev carrier-mob0 root netem limit 10000 delay 40ms loss 1%",
                      calls)
        self.assertIn("tc -n ts-sw-mobile qdisc replace dev carrier-mob0 root netem limit 10000 delay 40ms loss 3%",
                      calls)
        self.assertIn("tc -n ts-router-b qdisc replace dev wan0 root netem limit 10000 rate 5mbit", calls)
        k = calls.index("ip -n ts-router-b link set wan0 up", calls.index("ip -n ts-sw-mobile link set router-b-wan0 down"))
        self.assertEqual(calls[k + 1:k + 3], ["ip -n ts-router-b addr replace 100.64.0.2/24 dev wan0",
                                              "ip -n ts-router-b route replace default via 100.64.0.1 dev wan0"])
        self.assertEqual(self.ns(), [])  # torn down afterwards


class TestTunxdBench(unittest.TestCase):
    def setUp(self):
        from tunxd import bench
        self.b = bench

    @staticmethod
    def interval(begin, end, omitted=False, size=1500000, seconds=None):
        return {"start": begin, "end": end, "seconds": end - begin if seconds is None else seconds,
                "bytes": size, "omitted": omitted}

    @staticmethod
    def ping_output(sent, received):
        return "\n".join(["64 bytes: time=10.1 ms"] * received +
                         [f"{sent} packets transmitted, {received} received, 0% packet loss"])

    def document(self, intervals, duration=30):
        return "\n".join(json.dumps(event) for event in [
            {"event": "start", "data": {"test_start": {"omit": 3, "duration": duration, "interval": 1}}},
            *[{"event": "interval", "data": {"sum": value}} for value in intervals],
            {"event": "end", "data": {"sum_received": {"bits_per_second": 12000000, "seconds": duration}}}])

    def sample(self, intervals=None):
        if intervals is None:
            intervals = [self.interval(x, x + 1, True) for x in range(3)] + [self.interval(x, x + 1) for x in range(30)]
        _, warnings = self.b.normalize_intervals(intervals)
        timing = {"warmup_s": 3, "launched_s": 100, "test_start_s": 101, "transfer_evidence_s": 102,
                  "ping_start_s": 105, "ping_end_s": 116, "exit_s": 135,
                  "transfer_index": 0, "transfer_interval": intervals[0]}
        schedule = self.b.ping_schedule(timing, 30, 1, timing["ping_start_s"])
        count = schedule["count"]
        ping = self.ping_output(count, count)
        return {"overlapped": True, "iperf_rc": 0, "iperf_stdout": self.document(intervals),
                "ping_rc": 0, "ping_stdout": ping, "ping_expected": count,
                "mbps": 12, "loaded": self.b.ping_result(0, ping, count, 20), "intervals": intervals,
                "interval_warnings": warnings, "timings": timing, "schedule": schedule}

    def fixture(self):
        sample = self.sample()
        ping = self.ping_output(30, 30)
        cell = {"idle": {"rc": 0, "stdout": ping, "expected": 30, "summary": self.b.ping_result(0, ping, 30)},
                "up": {"median_mbps": 12, "runs": [sample]},
                "down": {"median_mbps": 12, "runs": [copy.deepcopy(sample)]}}
        return {"complete": True, "repeat": 1, "duration_s": 30, "report_interval_s": 1,
                "expected_losses": ["0%"], "expected_kinds": ["overlay"], "loss": {"0%": {"overlay": cell}}}

    def test_default_tunxd_scenarios_load(self):
        t = model.load(os.path.join(HERE, "topologies", "two-sites-tunxd.yaml"))
        for name in ("tunxd-plain", "tunxd-xray", "tunxd-bench"):
            s = scenario.load(os.path.join(HERE, "scenarios", name + ".yaml"), t)
            self.assertTrue(s.steps)
        self.assertEqual(s.vars["label"], "plain")

    def test_default_duration_and_explicit_duration(self):
        for extra, duration in (([], 30), (["--duration", "15"], 15)):
            with mock.patch.object(sys, "argv", ["bench.py", "--label", "test", *extra]), \
                    mock.patch.object(self.b, "Bench") as bench:
                bench.return_value.run.return_value = 0
                self.assertEqual(self.b.main(), 0)
                self.assertEqual(bench.call_args.args[0].duration, duration)

    def test_iperf_rejects_failure_and_missing_receiver(self):
        valid = self.sample()["iperf_stdout"]
        self.assertEqual(self.b.throughput(0, valid), 12)
        for rc, doc in ((1, valid), (0, '{}'), (0, '{"error":"failed"}'),
                        (0, valid.replace('12000000', 'NaN')), (0, 'garbage ' + valid)):
            with self.subTest(rc=rc, doc=doc), self.assertRaises((ValueError, KeyError)):
                self.b.throughput(rc, doc)

    def test_ping_requires_rtt_and_packet_counts(self):
        ping = "64 bytes: time=10.1 ms\n64 bytes: time=12.2 ms\n2 packets transmitted, 2 received, 0% packet loss"
        summary = self.b.ping_result(0, ping, 2)
        self.assertEqual(summary["p95_ms"], 12.2)
        self.assertEqual(summary["loss_pct"], 0)
        for rc, text, count in ((2, ping, 2), (0, ping, 3), (0, "2 packets transmitted, 0 received", 2)):
            with self.assertRaises(ValueError):
                self.b.ping_result(rc, text, count)

    def test_matrix_rejects_incomplete_failed_or_nonconcurrent_runs(self):
        self.b.validate(self.fixture())
        mutations = [lambda d: d.update(complete=False), lambda d: d["loss"].clear(),
                     lambda d: d["loss"]["0%"].clear(),
                     lambda d: d["loss"]["0%"]["overlay"]["up"].update(runs=[]),
                     lambda d: d["loss"]["0%"]["overlay"]["up"].update(median_mbps=None),
                     lambda d: d["loss"]["0%"]["overlay"]["up"]["runs"][0].update(iperf_rc=1),
                     lambda d: d["loss"]["0%"]["overlay"]["up"]["runs"][0].update(overlapped=False)]
        for mutate in mutations:
            d = self.fixture()
            mutate(d)
            with self.assertRaises(ValueError):
                self.b.validate(d)

    def test_preserved_reversed_and_inconsistent_boundary_with_later_coverage(self):
        for boundary, reason in ((self.interval(3.0001, 0.0002, seconds=0.001), "reversed or empty interval"),
                                 (self.interval(0.0002, 1.0002, seconds=0.0002), "duration inconsistent with timestamps"),
                                 (self.interval(0, 0, seconds=0), "reversed or empty interval")):
            intervals = self.sample()["intervals"]
            intervals[3] = boundary
            original = copy.deepcopy(intervals)
            sample = self.sample(intervals)
            self.assertEqual(sample["interval_warnings"], [{"index": 3, "reason": reason}])
            self.assertEqual(sample["intervals"], original)
            self.assertEqual(self.b.iperf_document(sample["iperf_stdout"])["intervals"][3]["sum"], boundary)
            self.assertTrue(self.b.loaded_overlap(sample))

    def test_negative_timestamps_are_fatal_before_boundary_exclusion(self):
        for index in (0, 3, 10):
            for key in ("start", "end"):
                with self.subTest(index=index, key=key):
                    intervals = self.sample()["intervals"]
                    intervals[index][key] = -.25
                    warnings = []
                    with self.assertRaisesRegex(ValueError, "negative interval timestamp"):
                        self.b.normalize_intervals(intervals, warnings)
                    self.assertEqual(warnings, [])

    def test_persisted_complete_matrix_rejects_negative_boundary_timestamps(self):
        cases = [(self.interval(-.25, .75), []),
                 (self.interval(0, -.25, seconds=.01),
                  [{"index": 3, "reason": "reversed or empty interval"}])]
        for direction in ("up", "down"):
            for boundary, warnings in cases:
                with self.subTest(direction=direction, boundary=boundary), tempfile.TemporaryDirectory() as directory:
                    matrix = self.fixture()
                    sample = matrix["loss"]["0%"]["overlay"][direction]["runs"][0]
                    sample["intervals"][3] = boundary
                    sample["interval_warnings"] = warnings
                    sample["iperf_stdout"] = self.document(sample["intervals"])
                    path = os.path.join(directory, "bench.json")
                    with open(path, "w") as f:
                        json.dump(matrix, f)
                    with open(path) as f:
                        persisted = json.load(f)
                    self.assertTrue(persisted["complete"])
                    with self.assertRaisesRegex(ValueError, "negative interval timestamp"):
                        self.b.validate(persisted)

    def test_malformed_interior_repeated_exclusion_and_order_fail(self):
        cases = []
        base = self.sample()["intervals"]
        for index, key, value in ((10, "seconds", .01), (10, "bytes", -1), (10, "omitted", "false"),
                                  (3, "start", float("nan")), (3, "seconds", float("inf"))):
            intervals = copy.deepcopy(base)
            intervals[index][key] = value
            cases.append(intervals)
        repeated = copy.deepcopy(base)
        repeated[3] = self.interval(3, 0, seconds=.01)
        repeated[4] = self.interval(1, 2, seconds=.01)
        cases.append(repeated)
        overlap = copy.deepcopy(base)
        overlap[10] = self.interval(6.5, 7.5)
        cases.append(overlap)
        reorder = copy.deepcopy(base)
        reorder[10], reorder[11] = reorder[11], reorder[10]
        cases.append(reorder)
        for intervals in cases:
            with self.subTest(intervals=intervals), self.assertRaises(ValueError):
                self.b.normalize_intervals(intervals)

    def test_duration_tolerance(self):
        self.b.normalize_intervals([self.interval(0, 1, seconds=1.0009)])
        self.b.normalize_intervals([self.interval(0, 5, seconds=5.0049)])
        for interval in (self.interval(0, 1, seconds=1.0011), self.interval(0, 5, seconds=5.0051)):
            with self.assertRaises(ValueError):
                self.b.normalize_intervals([interval])

    def test_complete_ping_window_and_sufficient_measurement_coverage(self):
        base = self.sample()["intervals"]
        for intervals in (base[:3] + [self.interval(0, 30)], base[:-3], base[:13] + base[14:]):
            self.assertFalse(self.b.loaded_overlap(self.sample(intervals)))
        for gap, expected in ((.0005, True), (.002, False)):
            intervals = copy.deepcopy(base)
            intervals[10] = self.interval(7 + gap, 8)
            self.assertEqual(self.b.loaded_overlap(self.sample(intervals)), expected)
        intervals = copy.deepcopy(base)
        for interval in intervals:
            if not interval["omitted"] and interval["start"] < 12:
                interval["bytes"] = 0
        self.assertFalse(self.b.loaded_overlap(self.sample(intervals)))

    def test_schedule_delayed_evidence_and_insufficient_budget(self):
        timing = self.sample()["timings"]
        full = self.b.ping_schedule(timing, 30, 1, 105)
        self.assertEqual(full["count"], 55)
        timing["transfer_evidence_s"] = 118
        delayed = self.b.ping_schedule(timing, 30, 1, 121)
        self.assertEqual(delayed["count"], 23)
        self.assertEqual(delayed["budget_s"], 13)
        timing["transfer_evidence_s"] = 125
        with self.assertRaisesRegex(ValueError, "insufficient loaded-ping budget"):
            self.b.ping_schedule(timing, 30, 1, 128)
        with self.assertRaisesRegex(ValueError, "insufficient loaded-ping budget"):
            self.b.ping_schedule(self.sample()["timings"], 10, 1, 105)

    def test_late_replies_low_rtt_count_and_schedule_tampering_fail(self):
        for end in (105.5, 123.81, 135):
            sample = self.sample()
            sample["timings"]["ping_end_s"] = end
            self.assertFalse(self.b.loaded_overlap(sample))
        sample = self.sample()
        sample["schedule"]["reply_margin_s"] = 1
        self.assertFalse(self.b.loaded_overlap(sample))
        d = self.fixture()
        sample = d["loss"]["0%"]["overlay"]["up"]["runs"][0]
        sample["ping_stdout"] = self.ping_output(55, 19)
        sample["loaded"] = self.b.ping_result(1, sample["ping_stdout"], 55)
        sample["ping_rc"] = 1
        with self.assertRaisesRegex(ValueError, "required RTT samples"):
            self.b.validate(d)

    def test_failed_samples_are_retained(self):
        b = self.b.Bench.__new__(self.b.Bench)
        b.a = mock.Mock(repeat=2)
        b.iperf = mock.Mock(side_effect=[{"mbps": 10}, {"error": "iperf3 exited 1"}])
        r = b.median()
        self.assertIsNone(r["median_mbps"])
        self.assertEqual(len(r["runs"]), 2)

    def test_loaded_ping_runs_after_evidence_and_warmup(self):
        b = self.b.Bench.__new__(self.b.Bench)
        b.a = mock.Mock(duration=30)
        b.command = lambda node, *args: [node, *args]
        b.sh = mock.Mock(return_value=mock.Mock(returncode=0))
        sample = self.sample()
        server = mock.Mock()
        server.poll.return_value = None
        server.communicate.return_value = ("server", "")
        load = mock.Mock(returncode=0)
        load.poll.return_value = None
        load.communicate.return_value = (sample["iperf_stdout"].encode(), b"")
        clock = [100.0]
        def evidence(process, prefix):
            clock[0] = 102.0
            return {k: sample["timings"][k] for k in ("test_start_s", "transfer_evidence_s", "transfer_index", "transfer_interval")}
        def sleep(seconds):
            clock[0] += seconds
        def ping(node, to, count):
            self.assertGreaterEqual(clock[0], 105.0)
            self.assertEqual(count, 55)
            clock[0] += 11
            self.assertFalse(load.communicate.called)
            return mock.Mock(returncode=0, stdout=sample["ping_stdout"], stderr="")
        b.ping = ping
        with mock.patch.object(self.b.subprocess, "Popen", side_effect=[server, load]), \
                mock.patch.object(self.b.time, "sleep", side_effect=sleep), \
                mock.patch.object(self.b.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(self.b, "wait_transfer", side_effect=evidence):
            result = b.iperf("client", "server", "10.0.0.1", "10.0.0.2", 5201, False)
        self.assertNotIn("error", result)
        self.assertTrue(result["overlapped"])
        self.assertEqual(result["mbps"], 12)

    def test_failed_budget_retains_scheduling_inputs_without_pinging(self):
        b = self.b.Bench.__new__(self.b.Bench)
        b.a = mock.Mock(duration=5)
        b.command = lambda node, *args: [node, *args]
        b.sh = mock.Mock(return_value=mock.Mock(returncode=0))
        b.ping = mock.Mock()
        sample = self.sample()
        server, load = mock.Mock(), mock.Mock(returncode=0)
        server.poll.return_value = load.poll.return_value = None
        server.communicate.return_value = ("server", "")
        load.communicate.return_value = (sample["iperf_stdout"].encode(), b"")
        evidence = {k: sample["timings"][k] for k in ("test_start_s", "transfer_evidence_s", "transfer_index", "transfer_interval")}
        with mock.patch.object(self.b.subprocess, "Popen", side_effect=[server, load]), \
                mock.patch.object(self.b, "wait_transfer", return_value=evidence), \
                mock.patch.object(self.b.time, "sleep"), \
                mock.patch.object(self.b.time, "monotonic", side_effect=[100, 102, 105]):
            result = b.iperf("client", "server", "10.0.0.1", "10.0.0.2", 5201, False)
        self.assertIn("insufficient loaded-ping budget", result["error"])
        self.assertEqual(result["schedule"]["duration_s"], 5)
        self.assertEqual(result["schedule"]["reply_margin_s"], 8)
        self.assertEqual(result["schedule"]["guard_s"], .5)
        self.assertLess(result["schedule"]["count"], 21)
        b.ping.assert_not_called()

    def test_boundary_warning_survives_later_invalid_interval(self):
        intervals = self.sample()["intervals"]
        intervals[3] = self.interval(3, 0, seconds=.001)
        intervals[10]["seconds"] = .01
        warnings = []
        with self.assertRaisesRegex(ValueError, r"intervals\[10\]"):
            self.b.normalize_intervals(intervals, warnings)
        self.assertEqual(warnings, [{"index": 3, "reason": "reversed or empty interval"}])

    def test_wait_transfer_ignores_excluded_boundary_until_delayed_valid_data(self):
        start = {"event": "start", "data": {"test_start": {"omit": 3}}}
        for boundary in (self.interval(3, 0, seconds=.001), self.interval(0, 1, seconds=.001)):
            events = [start, {"event": "interval", "data": {"sum": self.interval(0, 1, True, size=0)}},
                      {"event": "interval", "data": {"sum": boundary}}]
            later = {"event": "interval", "data": {"sum": self.interval(1, 2)}}
            script = "import time; print(%r, flush=True); time.sleep(0.3); print(%r, flush=True)" % (
                "\n".join(json.dumps(e) for e in events), json.dumps(later))
            process = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            before = time.monotonic()
            prefix = bytearray()
            try:
                evidence = self.b.wait_transfer(process, prefix)
                self.assertGreaterEqual(evidence["transfer_evidence_s"] - before, .25)
                self.assertEqual(evidence["transfer_index"], 2)
                self.assertEqual(evidence["transfer_interval"], later["data"]["sum"])
                self.assertIn(json.dumps(boundary), prefix.decode())
            finally:
                process.communicate(timeout=3)

    def test_failed_run_writes_incomplete_artifact_and_resets_owned_topology(self):
        b = self.b.Bench.__new__(self.b.Bench)
        b.a = mock.Mock(label="test", duration=5, repeat=1, no_overlay=False, raw=False, loss=["0"])
        with tempfile.TemporaryDirectory() as tmp:
            b.t = mock.Mock(rundir=tmp)
            b.netem = mock.Mock()
            b.idle = mock.Mock(side_effect=ValueError("no ping samples"))
            with mock.patch.object(self.b.time, "sleep"):
                self.assertEqual(b.run(), 1)
            with open(os.path.join(tmp, "results", "bench-test.json")) as f:
                d = json.load(f)
            self.assertFalse(d["complete"])
            self.assertEqual(d["error"], "no ping samples")
            self.assertEqual(b.netem.call_args_list[-1], mock.call(None))


class TestTunxdJob(unittest.TestCase):
    def command(self, action, directory, *args):
        return [sys.executable, os.path.join(HERE, "tunxd", "job.py"), action, "--jobdir", directory, *args]

    def test_stop_is_idempotent_and_prevents_queued_job_start(self):
        with tempfile.TemporaryDirectory() as directory:
            for _ in range(2):
                stopped = subprocess.run(self.command("stop", directory), capture_output=True, text=True, timeout=5)
                self.assertEqual(stopped.returncode, 0, stopped.stderr)
            marker = os.path.join(directory, "unexpected")
            script = "from pathlib import Path; Path(%r).touch()" % marker
            run = subprocess.run(self.command("run", directory, "--", sys.executable, "-c", script),
                                 capture_output=True, text=True, timeout=5)
            self.assertEqual(run.returncode, 143, run.stderr)
            self.assertFalse(os.path.exists(marker))

    def test_stop_acknowledges_only_after_child_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            started = os.path.join(directory, "started")
            finished = os.path.join(directory, "finished")
            script = """import signal,time,sys
from pathlib import Path
def stop(signum, frame):
    time.sleep(.2)
    Path(%r).touch()
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
Path(%r).touch()
while True:
    time.sleep(.05)
""" % (finished, started)
            run = subprocess.Popen(self.command("run", directory, "--", sys.executable, "-c", script),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 5
                while not os.path.exists(started):
                    if run.poll() is not None or time.monotonic() >= deadline:
                        self.fail("owned child did not start")
                    time.sleep(.02)
                stop = subprocess.run(self.command("stop", directory), capture_output=True, text=True, timeout=5)
                self.assertEqual(stop.returncode, 0, stop.stderr)
                self.assertTrue(os.path.exists(finished))
                _, stderr = run.communicate(timeout=5)
                self.assertEqual(run.returncode, 143, stderr)
            finally:
                if run.poll() is None:
                    subprocess.run(self.command("stop", directory), capture_output=True, timeout=6)
                    run.communicate(timeout=6)


class TestTunxdWrapper(unittest.TestCase):
    def wrapper(self, *, remote_rc=0, copy_rc=0, bad_json=False, sigterm=False, stop_rc=0,
                checksum_ok=True, transfer_rc=0, transfer_target="xray", xray_version="v1"):
        with tempfile.TemporaryDirectory() as tmp:
            bindir = os.path.join(tmp, "bin")
            os.mkdir(bindir)
            fixture = os.path.join(tmp, "fixture")
            for directory in ("results", "logs", "nodes"):
                os.makedirs(os.path.join(fixture, directory))
            t = model.load(os.path.join(HERE, "topologies", "two-sites-tunxd.yaml"))
            s = scenario.load(os.path.join(HERE, "scenarios", "tunxd-plain.yaml"), t)
            with open(os.path.join(fixture, "results", "tunxd-plain.json"), "w") as f:
                if bad_json:
                    f.write("{bad json")
                else:
                    json.dump({"passed": True, "steps": [{"status": "pass"} for _ in s.steps]}, f)
            archive = os.path.join(tmp, "evidence.tar")
            with tarfile.open(archive, "w") as tar:
                for directory in ("results", "logs", "nodes"):
                    tar.add(os.path.join(fixture, directory), arcname=directory)
            xray_archive = os.path.join(tmp, "Xray-linux-64.zip")
            with zipfile.ZipFile(xray_archive, "w") as z:
                z.writestr("xray", b"verified executable fixture\n")
            with open(xray_archive, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            xray_digest = os.path.join(tmp, "Xray-linux-64.zip.dgst")
            with open(xray_digest, "w") as f:
                f.write("SHA2-256= " + (digest if checksum_ok else "0" * 64) + "\n")
            scripts = {
                "go": "import pathlib,sys; pathlib.Path(sys.argv[sys.argv.index('-o')+1]).touch()",
                "curl": """import json,os,shutil,sys
from pathlib import Path
root = Path(os.environ['FIXTURE_ROOT'])
with (root / 'calls').open('a') as f:
    f.write(json.dumps({'kind': 'curl', 'argv': sys.argv[1:]}) + '\\n')
target = sys.argv[sys.argv.index('-o') + 1]
url = sys.argv[-1]
if url.endswith('/releases/latest'):
    Path(target).write_text(json.dumps({'tag_name': 'v9.8.7'}))
elif url.endswith('.zip.dgst'):
    shutil.copyfile(os.environ['FIXTURE_XRAY_DIGEST'], target)
elif url.endswith('.zip'):
    shutil.copyfile(os.environ['FIXTURE_XRAY_ARCHIVE'], target)
else:
    sys.exit('unexpected curl URL: ' + url)
""",
                "ssh": """import json,os,sys,time
from pathlib import Path
root = Path(os.environ['FIXTURE_ROOT'])
def record(value):
    with (root / 'events').open('a') as f:
        f.write(value + '\\n')
cmd = sys.argv[-1]
script = sys.stdin.read() if cmd.startswith('sh -s -- ') else ''
with (root / 'calls').open('a') as f:
    f.write(json.dumps({'kind': 'ssh', 'command': cmd, 'script': script}) + '\\n')
if cmd.startswith('sh -s -- tunx-e2e '):
    print('/tmp/tunx-wrapper-fixture')
elif cmd.startswith('cat >') and '/bin/xray' in cmd:
    target = 'xray.version' if '/bin/xray.version' in cmd else 'xray'
    data = sys.stdin.buffer.read()
    if target == os.environ['FIXTURE_TRANSFER_TARGET'] and int(os.environ['FIXTURE_TRANSFER_RC']):
        sys.exit(int(os.environ['FIXTURE_TRANSFER_RC']))
    (root / ('transferred-' + target)).write_bytes(data)
elif 'python3 sim.py run' in cmd:
    if os.environ['FIXTURE_SIGNAL'] == '1':
        record('job-start')
        (root / 'running').touch()
        while not (root / 'stop').exists():
            time.sleep(.02)
        time.sleep(.3)
        (root / 'running').unlink()
        record('job-stopped')
        (root / 'stopped').touch()
        sys.exit(143)
    print('result: all passed -> PASS')
    sys.exit(int(os.environ['FIXTURE_REMOTE_RC']))
elif 'job.py' in cmd and ' stop --jobdir ' in cmd:
    if os.environ['FIXTURE_SIGNAL'] == '1':
        record('stop-request')
        if int(os.environ['FIXTURE_STOP_RC']):
            sys.exit(int(os.environ['FIXTURE_STOP_RC']))
        (root / 'stop').touch()
        while not (root / 'stopped').exists():
            time.sleep(.02)
        record('stop-ack')
elif cmd.startswith('sh -s -- /tmp/tunx-wrapper-fixture '):
    if os.environ['FIXTURE_SIGNAL'] == '1':
        if (root / 'running').exists():
            record('premature-cleanup')
            sys.exit(1)
        record('cleanup')
        record('lock-release')
elif 'sudo tar -C' in cmd:
    if int(os.environ['FIXTURE_COPY_RC']):
        sys.exit(int(os.environ['FIXTURE_COPY_RC']))
    with open(os.environ['FIXTURE_ARCHIVE'], 'rb') as f:
        sys.stdout.buffer.write(f.read())
"""}
            for name, script in scripts.items():
                path = os.path.join(bindir, name)
                with open(path, "w") as f:
                    f.write("#!/usr/bin/env python3\n" + script + "\n")
                os.chmod(path, 0o755)
            env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"],
                       TUNX_SIM_OUT=os.path.join(tmp, "out"), TUNX_SIM_HOST="fixture",
                       TUNX_SIM_DIR="tunx-e2e", SIM_SET="", XRAY_PROXY="", XRAY_VERSION=xray_version,
                       FIXTURE_REMOTE_RC=str(remote_rc), FIXTURE_COPY_RC=str(copy_rc), FIXTURE_ARCHIVE=archive,
                       FIXTURE_ROOT=tmp, FIXTURE_SIGNAL="1" if sigterm else "0", FIXTURE_STOP_RC=str(stop_rc),
                       FIXTURE_XRAY_ARCHIVE=xray_archive, FIXTURE_XRAY_DIGEST=xray_digest,
                       FIXTURE_TRANSFER_RC=str(transfer_rc), FIXTURE_TRANSFER_TARGET=transfer_target,
                       PYTHONDONTWRITEBYTECODE="1")
            command = ["sh", os.path.join(HERE, "run-tunxd.sh"), "tunxd-plain"]
            if not sigterm:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30, env=env)
                with open(os.path.join(tmp, "calls")) as f:
                    result.calls = [json.loads(line) for line in f]
                runs = os.listdir(env["TUNX_SIM_OUT"])
                evidence = os.path.join(env["TUNX_SIM_OUT"], runs[0], "xray")
                result.xray_files = {}
                for name in os.listdir(evidence):
                    with open(os.path.join(evidence, name), "rb") as f:
                        result.xray_files[name] = f.read()
                result.transferred = {}
                for name in ("xray", "xray.version"):
                    path = os.path.join(tmp, "transferred-" + name)
                    if os.path.exists(path):
                        with open(path, "rb") as f:
                            result.transferred[name] = f.read()
                return result
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
            try:
                deadline = time.monotonic() + 15
                while not os.path.exists(os.path.join(tmp, "running")):
                    if process.poll() is not None or time.monotonic() >= deadline:
                        self.fail("mock remote job did not start")
                    time.sleep(.02)
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 143, stdout + stderr)
                with open(os.path.join(tmp, "events")) as f:
                    events = f.read().splitlines()
                if stop_rc:
                    self.assertEqual(events, ["job-start", "stop-request"])
                    self.assertIn("remote job stop unconfirmed; lock and evidence retained", stderr)
                else:
                    self.assertEqual(events, ["job-start", "stop-request", "job-stopped", "stop-ack", "cleanup", "lock-release"])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()


    def test_local_xray_download_retains_verified_evidence_and_pin(self):
        for version, tag in (("v1", "v1"), ("", "v9.8.7")):
            with self.subTest(version=version):
                result = self.wrapper(xray_version=version)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                evidence = result.xray_files
                digest = hashlib.sha256(evidence["Xray-linux-64.zip"]).hexdigest()
                self.assertEqual(evidence["Xray-linux-64.zip.dgst"].decode().strip(), "SHA2-256= " + digest)
                self.assertEqual(evidence["SHA256SUMS"].decode().strip(), digest + "  Xray-linux-64.zip")
                self.assertEqual(evidence["xray.version"].decode().strip(), tag)
                self.assertIn("/download/" + tag + "/", evidence["source.txt"].decode())
                self.assertEqual(result.transferred["xray"], b"verified executable fixture\n")
                self.assertEqual(result.transferred["xray.version"], (tag + "\n").encode())
                self.assertEqual("release.json" in evidence, not version)

    def test_xray_checksum_failure_stops_before_remote_work(self):
        result = self.wrapper(checksum_ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("xray: checksum mismatch", result.stderr)
        self.assertTrue(all(call["kind"] == "curl" for call in result.calls))
        self.assertIn("Xray-linux-64.zip", result.xray_files)
        self.assertIn("Xray-linux-64.zip.dgst", result.xray_files)
        self.assertNotIn("xray", result.xray_files)

    def test_xray_transfer_failures_are_fatal_and_cleanup_safe(self):
        for target in ("xray", "xray.version"):
            with self.subTest(target=target):
                result = self.wrapper(transfer_rc=42, transfer_target=target)
                self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
                remote = [call for call in result.calls if call["kind"] == "ssh"]
                self.assertIn('rmdir "$4"', remote[-1]["script"])
                self.assertFalse(any("python3 sim.py run" in call["command"] for call in remote))

    def test_remote_commands_do_not_download_xray(self):
        result = self.wrapper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        first_remote = next(i for i, call in enumerate(result.calls) if call["kind"] == "ssh")
        self.assertEqual([call["kind"] for call in result.calls[:first_remote]], ["curl", "curl"])
        for call in result.calls[first_remote:]:
            self.assertEqual(call["kind"], "ssh")
            content = call["command"] + call["script"]
            self.assertNotIn("curl", content)
            self.assertNotIn("github.com", content)
            self.assertNotIn("zipfile", content)

    def test_sigterm_stops_and_waits_for_job_before_cleanup_releases_lock(self):
        self.wrapper(sigterm=True)

    def test_unconfirmed_stop_retains_lock_and_signal_status(self):
        self.wrapper(sigterm=True, stop_rc=42)

    def test_valid_artifacts_and_successful_ssh_pass(self):
        result = self.wrapper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL PASS", result.stdout)

    def test_pass_text_does_not_override_ssh_failure(self):
        result = self.wrapper(remote_rc=42)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("-> PASS", result.stdout)
        self.assertIn("FAILED", result.stdout)

    def test_copy_failure_cannot_pass(self):
        result = self.wrapper(copy_rc=42)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("evidence copy failed", result.stderr)

    def test_invalid_scenario_json_cannot_pass(self):
        result = self.wrapper(bad_json=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED", result.stdout)


class TestProbe(unittest.TestCase):
    """The probe helper over loopback (unprivileged)."""

    def test_tcp_and_udp(self):
        probe = os.path.join(HERE, "probe.py")
        srv = subprocess.Popen([sys.executable, probe, "serve", "--bind", "127.0.0.1", "--tcp", "0", "--udp", "0"],
                               stdout=subprocess.PIPE, text=True)
        try:
            ports = {}
            for _ in range(2):
                parts = srv.stdout.readline().split()
                ports[parts[1]] = parts[3]
            r = subprocess.run([sys.executable, probe, "tcp", "127.0.0.1", ports["tcp"]], capture_output=True,
                               text=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertRegex(r.stdout, r"^peer 127\.0\.0\.1 \d+")
            r = subprocess.run([sys.executable, probe, "udp", "127.0.0.1", ports["udp"]], capture_output=True,
                               text=True, timeout=10)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertRegex(r.stdout, r"^peer 127\.0\.0\.1 \d+")
        finally:
            srv.kill()
            srv.wait()
            srv.stdout.close()

    def test_closed_port_fails(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        probe = os.path.join(HERE, "probe.py")
        t0 = time.monotonic()
        r = subprocess.run([sys.executable, probe, "tcp", "127.0.0.1", str(port), "--timeout", "1"],
                           capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 1)
        self.assertLess(time.monotonic() - t0, 5)


if __name__ == "__main__":
    unittest.main(verbosity=1)
