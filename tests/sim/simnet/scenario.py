"""Scenario files: ordered steps run against a topology that is up."""
import json
import os
import re
import shlex
import signal
import time
from dataclasses import dataclass, field

import yaml

from . import SchemaError, SimError
from . import netem as netem_mod
from . import ops
from .actions import Spawn, sim_env
from .util import check_map, subst, suggest, type_name

COMMON = {"name", "continue"}
ACTIONS = {
    "exec": {"node", "rc", "match", "not_match", "timeout"},
    "background": {"node"},
    "wait_until": {"node", "timeout", "interval", "match"},
    "sleep": set(),
    "netem": {"node", "if", "segment", "dir"},
    "link": {"node", "if", "admin"},
    "measure": {"from", "to", "server", "count", "interval", "port", "proto", "duration", "bitrate",
                "reverse", "parallel", "timeout", "expect"},
}
EXPECT_KEYS = {"ping": {"avg_rtt_min_ms", "avg_rtt_max_ms", "loss_max_pct"},
               "iperf3": {"mbps_min", "loss_max_pct"}}
TOP_KEYS = {"name", "description", "vars", "keep_going", "steps"}


@dataclass
class Step:
    index: int
    action: str
    value: object
    args: dict
    name: str
    cont: bool = False


@dataclass
class Scenario:
    name: str
    path: str
    steps: list
    vars: dict = field(default_factory=dict)
    keep_going: bool = False


def read_raw(path):
    try:
        with open(path) as f:
            raw = yaml.safe_load(f)
    except OSError as e:
        raise SchemaError(f"{path}: cannot read ({e.strerror})") from None
    except yaml.YAMLError as e:
        raise SchemaError(f"{path}: YAML syntax error: {e}") from None
    check_map(raw if raw is not None else {}, "scenario", TOP_KEYS, required=("steps",))
    return raw


def scenario_vars(raw):
    v = raw.get("vars") or {}
    check_map(v, "vars", v.keys())
    return {str(k): "" if x is None else str(x) for k, x in v.items()}


def load(path, topo, overrides=None):
    """Load a scenario and check it against a loaded topology."""
    path = os.path.abspath(path)
    raw = read_raw(path)
    vars_ = scenario_vars(raw)
    for k, v in (overrides or {}).items():
        vars_[k] = str(v)
    vars_ = {k: subst(v, topo.resolve, f"vars.{k}") for k, v in vars_.items()}
    steps_raw = raw["steps"]
    if not isinstance(steps_raw, list) or not steps_raw:
        raise SchemaError("steps: expected a non-empty list of steps")
    steps = []
    for k, s in enumerate(steps_raw):
        p = f"steps[{k}]"
        if not isinstance(s, dict):
            raise SchemaError(f"{p}: expected a mapping like {{exec: 'ping -c1 10.0.1.1', node: term-a}}, "
                              f"got {type_name(s)}")
        acts = [a for a in s if a in ACTIONS]
        if len(acts) != 1:
            unknown = [a for a in s if a not in COMMON and not any(a in ACTIONS[x] for x in ACTIONS)]
            hint = suggest(unknown[0], ACTIONS) if unknown else f" (one of: {', '.join(ACTIONS)})"
            raise SchemaError(f"{p}: a step needs exactly one action, found {acts or 'none'}" + hint)
        act = acts[0]
        p = f"{p} ({act})"
        check_map(s, p, ACTIONS[act] | COMMON | {act})
        s = subst(s, lambda n: topo.resolve(n, vars_), p)
        try:
            steps.append(_check_step(k + 1, act, s, topo, p))
        except SchemaError as e:
            if str(e).startswith(p):
                raise
            raise SchemaError(f"{p}: {e}") from None
    return Scenario(str(raw.get("name") or os.path.splitext(os.path.basename(path))[0]), path, steps,
                    vars_, bool(raw.get("keep_going", False)))


def _num(v, path, default, lo=0):
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v < lo:
        raise SchemaError(f"{path}: expected a number >= {lo}, got {v!r}")
    return v


def _need_node(s, key, topo, p):
    if key not in s:
        raise SchemaError(f"{p}: missing '{key}' (which node to run in)")
    n = str(s[key])
    if n not in topo.nodes:
        raise SchemaError(f"{p}.{key}: unknown node '{n}'" + suggest(n, topo.nodes))
    return n


def _check_step(index, act, s, topo, p):
    v = s[act]
    args = {k: x for k, x in s.items() if k not in COMMON and k != act}
    name = s.get("name")
    if act in ("exec", "background", "wait_until"):
        if not isinstance(v, str) or not v.strip():
            raise SchemaError(f"{p}: expected a shell command string")
        _need_node(s, "node", topo, p)
        args["timeout"] = _num(s.get("timeout"), f"{p}.timeout", 30 if act != "wait_until" else 60)
        args["interval"] = _num(s.get("interval"), f"{p}.interval", 1)
        for key in ("match", "not_match"):
            if key in s:
                try:
                    re.compile(str(s[key]))
                except re.error as e:
                    raise SchemaError(f"{p}.{key}: invalid regex ({e})") from None
        rc = s.get("rc", 0)
        if not (rc in ("any", "nonzero") or isinstance(rc, int) and not isinstance(rc, bool)
                or isinstance(rc, list) and all(isinstance(x, int) for x in rc)):
            raise SchemaError(f"{p}.rc: expected a number, a list of numbers, 'nonzero' or 'any'")
        args["rc"] = rc
        name = name or f"{s['node']}: {v}"
    elif act == "sleep":
        _num(v, p, 0)
        name = name or f"sleep {v}s"
    elif act == "netem":
        if "segment" in s:
            topo.segment(str(s["segment"]))
            target = f"segment {s['segment']}"
        else:
            if "node" not in s or "if" not in s:
                raise SchemaError(f"{p}: set 'segment', or 'node' and 'if'")
            topo.iface(str(s["node"]), str(s["if"]))
            target = f"{s['node']}/{s['if']} {s.get('dir', 'out')}"
        netem_mod.parse_update(v, p)
        if s.get("dir", "out") not in ("out", "in", "both"):
            raise SchemaError(f"{p}.dir: expected out, in or both")
        shown = " ".join(f"{k2}={x}" for k2, x in v.items()) if isinstance(v, dict) else v
        name = name or f"netem {target}: {shown}"
    elif act == "link":
        if v not in ("up", "down"):
            raise SchemaError(f"{p}: expected 'up' or 'down', got {v!r}")
        if "node" not in s or "if" not in s:
            raise SchemaError(f"{p}: set 'node' and 'if'")
        topo.iface(str(s["node"]), str(s["if"]))
        name = name or f"link {s['node']}/{s['if']} {v}"
    elif act == "measure":
        if v not in EXPECT_KEYS:
            raise SchemaError(f"{p}: expected 'ping' or 'iperf3', got {v!r}")
        _need_node(s, "from", topo, p)
        if v == "ping" and "to" not in s:
            raise SchemaError(f"{p}: missing 'to' (address to ping)")
        if v == "iperf3":
            _need_node(s, "server", topo, p)
            if "to" not in s:
                args["to"] = topo.resolve(s["server"])
                if args["to"] is None:
                    raise SchemaError(f"{p}: server '{s['server']}' has no IPv4 address; set 'to'")
            if s.get("proto", "tcp") not in ("tcp", "udp"):
                raise SchemaError(f"{p}.proto: expected tcp or udp")
        exp = s.get("expect") or {}
        check_map(exp, f"{p}.expect", EXPECT_KEYS[v])
        for k2, x in exp.items():
            _num(x, f"{p}.expect.{k2}", 0)
        for k2 in ("count", "interval", "port", "duration", "parallel", "timeout"):
            if k2 in s:
                _num(s[k2], f"{p}.{k2}", 0)
        name = name or f"measure {v} {s['from']} -> {args.get('to')}"
    return Step(index, act, v, args, str(name), bool(s.get("continue", False)))


# Running.

def _rc_ok(rc, want):
    if want == "any":
        return True
    if want == "nonzero":
        return rc != 0
    return rc in (want if isinstance(want, list) else [want])


def _check_output(out, args):
    if "match" in args and not re.search(str(args["match"]), out, re.M):
        return f"output does not match /{args['match']}/"
    if "not_match" in args and re.search(str(args["not_match"]), out, re.M):
        return f"output matches /{args['not_match']}/"
    return None


class Run:
    def __init__(self, topo, scen, runner):
        self.t, self.s, self.r = topo, scen, runner
        self.measurements = {}

    def ns(self, node):
        return self.t.node(node).ns

    def step(self, st):
        """Returns (status, detail, output, result)."""
        a, v = st.args, st.value
        if st.action == "exec":
            rc, out, timed_out, _ = self.r.capture(self.ns(a["node"]), v, a["timeout"])
            if self.r.dry:
                return "dry", "", "", None
            if timed_out:
                return "fail", f"timed out after {a['timeout']}s", out, None
            if not _rc_ok(rc, a["rc"]):
                return "fail", f"exit {rc}, expected {a['rc']}", out, None
            bad = _check_output(out, a)
            return ("fail", bad, out, None) if bad else ("pass", f"exit {rc}", out, None)
        if st.action == "background":
            n = self.t.node(a["node"])
            sp = Spawn(n.ns, v, os.path.join(self.t.logdir, f"{n.name}.log"), n.dir, "", sim_env(self.t, n))
            if self.r.dry:
                self.r.do(sp)
                return "dry", "", "", None
            self.r.spawn(sp)
            return "pass", f"started, log {sp.log}", "", None
        if st.action == "wait_until":
            return self.wait_until(st)
        if st.action == "sleep":
            if self.r.dry:
                self.r.say(f"  sleep {v}")
                return "dry", "", "", None
            time.sleep(v)
            return "pass", "", "", None
        if st.action == "netem":
            ops.netem_change(self.t, self.r, v, a.get("node"), a.get("if"), a.get("segment"),
                             a.get("dir", "out"), path=st.name)
            return ("dry" if self.r.dry else "pass"), "", "", None
        if st.action == "link":
            ops.link_change(self.t, self.r, a["node"], a["if"], v, bool(a.get("admin", False)))
            return ("dry" if self.r.dry else "pass"), "", "", None
        if st.action == "measure":
            return self.ping(st) if v == "ping" else self.iperf3(st)
        raise AssertionError(st.action)

    def wait_until(self, st):
        a = st.args
        deadline = time.monotonic() + a["timeout"]
        tries, out = 0, ""
        while True:
            tries += 1
            left = max(1.0, deadline - time.monotonic())
            rc, out, timed_out, _ = self.r.capture(self.ns(a["node"]), st.value, min(left, max(5.0, a["interval"])))
            if self.r.dry:
                self.r.say(f"  (repeat every {a['interval']}s until exit 0, up to {a['timeout']}s)")
                return "dry", "", "", None
            if rc == 0 and not timed_out and not _check_output(out, a):
                return "pass", f"after {tries} attempt(s)", out, None
            if time.monotonic() + a["interval"] > deadline:
                return "fail", f"not true within {a['timeout']}s ({tries} attempts, last exit {rc})", out, None
            time.sleep(a["interval"])

    def ping(self, st):
        a = st.args
        count, interval = int(a.get("count", 10)), a.get("interval", 0.2)
        cmd = f"ping -n -q -c {count} -i {interval} -W 2 {shlex.quote(str(a['to']))}"
        rc, out, timed_out, _ = self.r.capture(self.ns(a["from"]), cmd, a.get("timeout", count * interval + 15))
        if self.r.dry:
            return "dry", "", "", None
        res = {"type": "ping", "from": a["from"], "to": a["to"], "count": count}
        m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received.*?([\d.]+)% packet loss", out)
        if not m:
            return "fail", "could not parse ping output" + (" (timed out)" if timed_out else ""), out, res
        res.update(sent=int(m.group(1)), received=int(m.group(2)), loss_pct=float(m.group(3)))
        m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
        if m:
            res.update(rtt_min_ms=float(m.group(1)), rtt_avg_ms=float(m.group(2)),
                       rtt_max_ms=float(m.group(3)), rtt_mdev_ms=float(m.group(4)))
        if not res["received"]:
            return "fail", "no replies", out, res
        return self._expect(st, res, out, {
            "avg_rtt_min_ms": lambda x: res["rtt_avg_ms"] >= x,
            "avg_rtt_max_ms": lambda x: res["rtt_avg_ms"] <= x,
            "loss_max_pct": lambda x: res["loss_pct"] <= x,
        }, f"avg {res.get('rtt_avg_ms')} ms, loss {res['loss_pct']}%")

    def iperf3(self, st):
        a = st.args
        port, dur = int(a.get("port", 5201)), a.get("duration", 5)
        proto = a.get("proto", "tcp")
        server = self.t.node(a["server"])
        cmd = ["iperf3", "-c", str(a["to"]), "-p", str(port), "-t", str(dur), "-J", "--connect-timeout", "3000"]
        if proto == "udp":
            cmd += ["-u", "-b", str(a.get("bitrate", "10M"))]
        if a.get("reverse"):
            cmd.append("-R")
        if a.get("parallel"):
            cmd += ["-P", str(int(a["parallel"]))]
        sp = Spawn(server.ns, f"exec iperf3 -s -1 -p {port}", os.path.join(self.t.logdir, f"{server.name}.iperf3.log"),
                   server.dir, "", {})
        if self.r.dry:
            self.r.do(sp)
            self.r.capture(self.ns(a["from"]), shlex.join(cmd), 0)
            return "dry", "", "", None
        p = self.r.spawn(sp)
        try:
            ready = False
            for _ in range(50):
                rc, _, _, _ = self.r.capture(server.ns, f"ss -Hltn 'sport = :{port}' | grep -q .", 3)
                if rc == 0:
                    ready = True
                    break
                time.sleep(0.1)
            if not ready:
                return "fail", f"iperf3 server on {server.name}:{port} did not start (see {sp.log})", "", None
            rc, out, timed_out, _ = self.r.capture(self.ns(a["from"]), shlex.join(cmd), a.get("timeout", dur + 20))
        finally:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            p.wait()
        res = {"type": "iperf3", "proto": proto, "from": a["from"], "to": a["to"], "port": port,
               "duration_s": dur, "reverse": bool(a.get("reverse"))}
        try:
            data = json.loads(out[out.index("{"):out.rindex("}") + 1])
        except ValueError:
            return "fail", "no JSON from iperf3" + (" (timed out)" if timed_out else f" (exit {rc})"), out, res
        if data.get("error"):
            return "fail", f"iperf3: {data['error']}", out[-500:], res
        end = data.get("end", {})
        if proto == "tcp":
            s = end.get("sum_received", {})
            res.update(mbps=round(s.get("bits_per_second", 0) / 1e6, 3),
                       retransmits=end.get("sum_sent", {}).get("retransmits"))
        else:
            s = end.get("sum", {})
            res.update(mbps=round(s.get("bits_per_second", 0) / 1e6, 3), loss_pct=s.get("lost_percent"),
                       jitter_ms=s.get("jitter_ms"))
        return self._expect(st, res, "", {
            "mbps_min": lambda x: res["mbps"] >= x,
            "loss_max_pct": lambda x: (res.get("loss_pct") or 0) <= x,
        }, f"{res['mbps']} Mbit/s" + (f", loss {res.get('loss_pct')}%" if proto == "udp" else
                                      f", {res.get('retransmits')} retransmits"))

    def _expect(self, st, res, out, checks, summary):
        self.measurements[st.name] = res
        for k, x in (st.args.get("expect") or {}).items():
            if not checks[k](x):
                return "fail", f"{summary}: expect {k} {x} not met", out, res
        return "pass", summary, out, res


def run(topo, scen, runner, results_path=None):
    """Run every step; returns True when all passed. Writes a JSON results file (not in dry runs)."""
    r = Run(topo, scen, runner)
    out_steps, stop, failed = [], False, 0
    started = time.time()
    total = len(scen.steps)
    runner.say(f"scenario {scen.name} on {topo.name} (prefix {topo.prefix}) vars {dict(topo.vars, **scen.vars)}")
    for st in scen.steps:
        rec = {"index": st.index, "name": st.name, "action": st.action}
        if stop:
            rec["status"] = "skip"
            out_steps.append(rec)
            continue
        if runner.dry:
            runner.say(f"[{st.index:>2}/{total}] {st.name}")
        t0 = time.monotonic()
        try:
            status, detail, output, result = r.step(st)
        except (SimError, SchemaError) as e:
            status, detail, output, result = "fail", str(e), "", None
        rec.update(status=status, seconds=round(time.monotonic() - t0, 3), detail=detail)
        if output:
            rec["output"] = output[-2000:]
        if result:
            rec["result"] = result
        out_steps.append(rec)
        if not runner.dry:
            runner.say(f"[{st.index:>2}/{total}] {status.upper():4}  {rec['seconds']:6.1f}s  {st.name}"
                       + (f"  -- {detail}" if detail else ""))
            if status == "fail" and output:
                runner.say("\n".join("        | " + line for line in output.strip().splitlines()[-15:]))
        if status == "fail":
            failed += 1
            if not (st.cont or scen.keep_going):
                stop = True
    counts = {k: sum(1 for s in out_steps if s.get("status") == k) for k in ("pass", "fail", "skip", "dry")}
    passed = failed == 0
    if runner.dry:
        runner.say(f"dry run: {total} steps checked")
        return True
    if r.measurements:
        runner.say("measurements:")
        for name, m in r.measurements.items():
            runner.say(f"  {name}: " + ", ".join(f"{k}={v}" for k, v in m.items() if k not in ("from", "to", "type")))
    doc = {"scenario": scen.name, "topology": topo.name, "prefix": topo.prefix,
           "vars": dict(topo.vars, **scen.vars), "started": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(started)),
           "seconds": round(time.time() - started, 3), "passed": passed, "counts": counts,
           "measurements": r.measurements, "steps": out_steps}
    results_path = results_path or os.path.join(topo.rundir, "results", f"{scen.name}.json")
    os.makedirs(os.path.dirname(os.path.abspath(results_path)), exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(doc, f, indent=2)
    runner.say(f"result: {counts['pass']} passed, {counts['fail']} failed, {counts['skip']} skipped -> "
               f"{'PASS' if passed else 'FAIL'}\nresults: {results_path}")
    return passed
