#!/usr/bin/env python3
"""Self-test for the simulator. Needs no root: it only parses files and checks plans."""
import contextlib
import copy
import io
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest
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
