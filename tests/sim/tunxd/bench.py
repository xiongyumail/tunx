#!/usr/bin/env python3
"""Measure receiver throughput and concurrent loaded ping in each direction.

Run in a disposable simulation VM. Every required sample must succeed.
Raw command output, failures, idle RTT, and per-run loaded RTT/loss are kept
in RUNDIR/results/bench-LABEL.json. --table FILE... validates these artifacts
and prints a Markdown table without requiring root.
"""
import argparse
import json
import math
import os
import re
import select
import statistics
import subprocess
import sys
import time

SIM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SIM)
from simnet import model  # noqa: E402

RAW_PORT, OVERLAY_PORT = 5201, 5202
WARMUP = 3
REPORT_INTERVAL = 1
PROBE_INTERVAL = 0.2
REPLY_MARGIN = 8
GUARD = 0.5
MIN_PROBES, MAX_PROBES, MIN_REPLIES = 21, 55, 20


def positive(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0


def iperf_document(stdout):
    """Read either a complete iperf JSON document or its flushed event stream."""
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        events = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        if any(e.get("event") == "error" for e in events):
            raise ValueError("iperf3 reported a stream error")
        starts = [e["data"] for e in events if e.get("event") == "start"]
        ends = [e["data"] for e in events if e.get("event") == "end"]
        if len(starts) != 1 or len(ends) != 1:
            raise ValueError("incomplete iperf3 event stream")
        return {"start": starts[0], "end": ends[0],
                "intervals": [e["data"] for e in events if e.get("event") == "interval"]}


def finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def normalize_intervals(raw, warnings=None):
    """Keep reported timestamps; exclude only one malformed omit-boundary row."""
    valid = []
    warnings = [] if warnings is None else warnings
    saw_omitted = measurement = False
    previous = None
    for index, interval in enumerate(raw):
        where = f"intervals[{index}]"
        if any(not finite(interval.get(key)) for key in ("start", "end", "seconds", "bytes")):
            raise ValueError(f"{where}: non-finite or missing interval fields")
        if interval["start"] < 0 or interval["end"] < 0:
            raise ValueError(f"{where}: negative interval timestamp")
        if interval["bytes"] < 0 or not isinstance(interval.get("omitted"), bool):
            raise ValueError(f"{where}: invalid bytes or omitted flag")
        omitted = interval["omitted"]
        boundary = not omitted and not measurement and saw_omitted
        if omitted and measurement:
            raise ValueError(f"{where}: omitted interval after measurement")
        if not omitted:
            measurement = True
        begin, end, seconds = (interval[key] for key in ("start", "end", "seconds"))
        reason = None
        if begin >= end:
            reason = "reversed or empty interval"
        elif seconds <= 0 or abs(seconds - (end - begin)) > max(0.001, (end - begin) * 0.001):
            reason = "duration inconsistent with timestamps"
        if reason:
            if boundary:
                warnings.append({"index": index, "reason": reason})
                continue
            raise ValueError(f"{where}: {reason}")
        if previous is not None and previous["omitted"] == omitted and begin < previous["end"]:
            raise ValueError(f"{where}: reordered or overlapping interval")
        valid.append({"index": index, "raw": interval})
        previous = interval
        saw_omitted |= omitted
    return valid, warnings


def wait_transfer(load, prefix, timeout=15):
    """Gate warm-up on a valid positive-byte interval; skip excluded boundaries."""
    deadline = time.monotonic() + timeout
    pending = bytearray()
    started = None
    intervals = []
    while time.monotonic() < deadline:
        ready, _, _ = select.select([load.stdout], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        chunk = os.read(load.stdout.fileno(), 65536)
        if not chunk:
            break
        prefix.extend(chunk)
        pending.extend(chunk)
        while b"\n" in pending:
            line, _, rest = pending.partition(b"\n")
            pending = bytearray(rest)
            event = json.loads(line)
            if event.get("event") == "start":
                started = time.monotonic()
            if event.get("event") == "interval":
                intervals.append(event["data"]["sum"])
                valid, _ = normalize_intervals(intervals)
                index = len(intervals) - 1
                if valid and valid[-1]["index"] == index and positive(intervals[-1]["bytes"]):
                    if started is None:
                        raise ValueError("iperf3 interval preceded start event")
                    return {"test_start_s": started, "transfer_evidence_s": time.monotonic(),
                            "transfer_index": index, "transfer_interval": intervals[-1]}
    raise ValueError("iperf3 produced no transfer-start evidence before timeout")


class BudgetError(ValueError):
    def __init__(self, schedule):
        self.schedule = schedule
        super().__init__(f"insufficient loaded-ping budget: {schedule['budget_s']:g}s permits "
                         f"{schedule['count']} probes; need {MIN_PROBES}")


def ping_schedule(timing, duration, report_interval, now):
    """Reserve reply time against both the planned and evidenced load clocks."""
    if not positive(duration) or not positive(report_interval) or not finite(now):
        raise ValueError("invalid ping scheduling inputs")
    interval = timing["transfer_interval"]
    offset = 0 if interval["omitted"] else WARMUP
    planned_end = timing["test_start_s"] + WARMUP + duration
    evidenced_end = timing["transfer_evidence_s"] + WARMUP + duration - offset - interval["end"]
    deadline = min(planned_end, evidenced_end)
    budget = deadline - now
    count = min(MAX_PROBES, math.floor((budget - REPLY_MARGIN - GUARD) / PROBE_INTERVAL) + 1)
    schedule = {"duration_s": duration, "report_interval_s": report_interval,
                "planned_end_s": planned_end, "evidenced_end_s": evidenced_end,
                "deadline_s": deadline, "budget_s": budget, "reply_margin_s": REPLY_MARGIN,
                "guard_s": GUARD, "probe_interval_s": PROBE_INTERVAL, "count": count}
    if count < MIN_PROBES:
        raise BudgetError(schedule)
    return schedule


def loaded_overlap(sample):
    """Require contiguous measured coverage for the whole ping/reply window."""
    timing, schedule = sample["timings"], sample["schedule"]
    if timing.get("warmup_s") != WARMUP:
        return False
    keys = ("launched_s", "test_start_s", "transfer_evidence_s", "ping_start_s", "ping_end_s", "exit_s")
    if any(not positive(timing[k]) for k in keys):
        return False
    launched, started, evidence, ping_start, ping_end, exited = (timing[k] for k in keys)
    if not launched <= started <= evidence or not evidence + WARMUP <= ping_start < ping_end <= exited:
        return False
    expected = ping_schedule(timing, schedule["duration_s"], schedule["report_interval_s"], ping_start)
    if schedule != expected or sample["ping_expected"] != schedule["count"]:
        return False
    span = (schedule["count"] - 1) * PROBE_INTERVAL
    if span < 4 or ping_end - ping_start < span - 0.001 or ping_end - ping_start > span + REPLY_MARGIN:
        return False
    if ping_end > schedule["deadline_s"] - GUARD:
        return False
    doc = iperf_document(sample["iperf_stdout"])
    intervals = [x["sum"] for x in doc["intervals"]]
    valid, warnings = normalize_intervals(intervals)
    if sample["intervals"] != intervals or sample["interval_warnings"] != warnings:
        return False
    transfer = timing["transfer_index"]
    if not any(x["index"] == transfer and x["raw"] == timing["transfer_interval"] and positive(x["raw"]["bytes"]) for x in valid):
        return False
    config = doc["start"]["test_start"]
    if config["omit"] != WARMUP or config["duration"] != schedule["duration_s"] or config["interval"] != schedule["report_interval_s"]:
        return False
    measured = [x["raw"] for x in valid if not x["raw"]["omitted"]]
    required = max(5, schedule["duration_s"] - 2 * schedule["report_interval_s"])
    if len(measured) < 2 or sum(x["end"] - x["start"] for x in measured) < required - 0.001:
        return False
    cursor, intersection = ping_start, False
    for interval in measured:
        begin, end = (started + WARMUP + interval[key] for key in ("start", "end"))
        if end <= ping_start or begin >= ping_end:
            continue
        if begin > cursor + 0.001:
            return False
        intersection |= positive(interval["bytes"])
        cursor = max(cursor, end)
    return intersection and cursor >= ping_end - 0.001


def throughput(rc, stdout):
    if rc != 0:
        raise ValueError(f"iperf3 exited {rc}")
    d = iperf_document(stdout)
    if d.get("error"):
        raise ValueError(f"iperf3: {d['error']}")
    rate = d["end"]["sum_received"]["bits_per_second"]
    seconds = d["end"]["sum_received"]["seconds"]
    if not positive(rate) or not positive(seconds):
        raise ValueError("iperf3 has no positive receiver measurement")
    return round(rate / 1e6, 2)


def ping_result(rc, stdout, expected, minimum=1):
    summary = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", stdout)
    values = [float(x) for x in re.findall(r"time[=<]([\d.]+)\s*ms", stdout)]
    if rc not in (0, 1) or not summary:
        raise ValueError(f"invalid ping result (exit {rc})")
    sent, received = map(int, summary.groups())
    if sent != expected or received < minimum or received > sent or len(values) != received:
        raise ValueError("ping lacks required RTT samples or packet counts")
    values.sort()
    return {"sent": sent, "received": received, "loss_pct": 100 * (sent - received) / sent,
            "avg_ms": statistics.mean(values), "p50_ms": statistics.median(values),
            "p95_ms": values[math.ceil(0.95 * len(values)) - 1], "max_ms": max(values)}


def validate(res):
    """Reject partial matrices, failed samples and artifacts without evidence."""
    if res.get("complete") is not True or not res.get("expected_losses") or not res.get("expected_kinds"):
        raise ValueError("incomplete benchmark")
    if not isinstance(res.get("repeat"), int) or res["repeat"] < 1:
        raise ValueError("invalid repeat count")
    if set(res["loss"]) != set(res["expected_losses"]):
        raise ValueError("missing loss cells")
    for loss in res["expected_losses"]:
        if set(res["loss"][loss]) != set(res["expected_kinds"]):
            raise ValueError("missing benchmark kinds")
        for cell in res["loss"][loss].values():
            idle = cell["idle"]
            if idle.get("summary") != ping_result(idle["rc"], idle["stdout"], idle["expected"]):
                raise ValueError("incorrect idle RTT summary")
            for direction in ("up", "down"):
                result = cell[direction]
                if len(result["runs"]) != res["repeat"]:
                    raise ValueError("missing repetitions")
                rates = []
                for sample in result["runs"]:
                    if sample.get("error") or sample.get("overlapped") is not True or not loaded_overlap(sample):
                        raise ValueError("failed or non-concurrent sample")
                    if sample["schedule"]["duration_s"] != res["duration_s"] or sample["schedule"]["report_interval_s"] != res["report_interval_s"]:
                        raise ValueError("sample schedule differs from matrix settings")
                    rates.append(throughput(sample["iperf_rc"], sample["iperf_stdout"]))
                    if sample.get("loaded") != ping_result(sample["ping_rc"], sample["ping_stdout"], sample["ping_expected"], MIN_REPLIES):
                        raise ValueError("incorrect loaded RTT summary")
                if result["median_mbps"] != statistics.median(rates):
                    raise ValueError("incorrect throughput aggregate")
    return res


class Bench:
    def __init__(self, a):
        self.a = a
        self.t = model.load(a.topo, prefix=a.prefix, rundir=a.rundir)

    def command(self, node, *args):
        return ["ip", "netns", "exec", self.t.node(node).ns, *args]

    def sh(self, node, cmd, timeout):
        return subprocess.run(self.command(node, "sh", "-c", cmd), capture_output=True, text=True, timeout=timeout)

    def netem(self, loss):
        words = ["reset"] if loss is None else ["loss", f"{loss}%"]
        subprocess.run([sys.executable, os.path.join(SIM, "sim.py"), "netem", self.a.topo,
                        "--segment", "mobile", *words, "--prefix", self.t.prefix,
                        "--rundir", self.t.rundir], check=True, capture_output=True)

    def ping(self, node, to, count):
        return subprocess.run(self.command(node, "ping", "-n", "-c", str(count), "-i", str(PROBE_INTERVAL), "-W", str(REPLY_MARGIN), to),
                              capture_output=True, text=True, timeout=count * 0.2 + 10)

    def idle(self, node, to):
        p = self.ping(node, to, 30)
        r = {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr, "expected": 30}
        try:
            r["summary"] = ping_result(p.returncode, p.stdout, 30)
        except ValueError as e:
            r["error"] = str(e)
        return r

    @staticmethod
    def stop(p):
        if p is None:
            return "", ""
        if p.poll() is None:
            p.terminate()
        try:
            return p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            return p.communicate()

    def iperf(self, client, server, to, ping_to, port, reverse, cc=None):
        sample = {}
        prefix = bytearray()
        srv = load = None
        try:
            srv = subprocess.Popen(self.command(server, "iperf3", "-s", "-1", "-p", str(port)),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(50):
                if srv.poll() is not None:
                    raise ValueError("iperf3 server exited before readiness")
                if self.sh(server, f"ss -Hltn 'sport = :{port}' | grep -q .", 5).returncode == 0:
                    break
                time.sleep(0.1)
            else:
                raise ValueError("iperf3 server readiness timed out")
            cmd = self.command(client, "iperf3", "-c", to, "-p", str(port), "-t", str(self.a.duration),
                               "-O", str(WARMUP), "-i", str(REPORT_INTERVAL), "--json-stream", "--forceflush", "--connect-timeout", "5000")
            if reverse:
                cmd += ["-R"]
            if cc:
                cmd += ["-C", cc]
            sample["timings"] = {"launched_s": time.monotonic(), "warmup_s": WARMUP}
            load = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            evidence = wait_transfer(load, prefix)
            sample["timings"].update(evidence)
            time.sleep(max(0, evidence["transfer_evidence_s"] + WARMUP - time.monotonic()))
            if load.poll() is not None:
                raise ValueError("iperf3 exited before loaded ping")
            sample["timings"]["ping_start_s"] = time.monotonic()
            sample["schedule"] = ping_schedule(sample["timings"], self.a.duration, REPORT_INTERVAL,
                                                sample["timings"]["ping_start_s"])
            count = sample["schedule"]["count"]
            p = self.ping(client, ping_to, count)
            sample["timings"]["ping_end_s"] = time.monotonic()
            sample.update(ping_rc=p.returncode, ping_stdout=p.stdout, ping_stderr=p.stderr,
                          ping_expected=count)
            stdout, stderr = load.communicate(timeout=self.a.duration + 30)
            sample["timings"]["exit_s"] = time.monotonic()
            stdout = (prefix + stdout).decode(errors="replace")
            sample.update(iperf_rc=load.returncode, iperf_stdout=stdout, iperf_stderr=stderr.decode(errors="replace"))
            sample["intervals"] = [x["sum"] for x in iperf_document(stdout)["intervals"]]
            sample["interval_warnings"] = []
            normalize_intervals(sample["intervals"], sample["interval_warnings"])
            sample["overlapped"] = loaded_overlap(sample)
            sample["mbps"] = throughput(load.returncode, stdout)
            sample["loaded"] = ping_result(p.returncode, p.stdout, count, MIN_REPLIES)
            if not sample["overlapped"]:
                raise ValueError("load ended before loaded ping completed")
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as e:
            sample["error"] = str(e)
            if isinstance(e, BudgetError):
                sample["schedule"] = e.schedule
            print(f"iperf sample failed: {e}", file=sys.stderr, flush=True)
        finally:
            if load is not None and "iperf_stdout" not in sample:
                stdout, stderr = self.stop(load)
                sample.update(iperf_rc=load.returncode, iperf_stdout=(prefix + stdout).decode(errors="replace"),
                              iperf_stderr=stderr.decode(errors="replace"))
            stdout, stderr = self.stop(srv)
            sample.update(server_stdout=stdout, server_stderr=stderr)
            time.sleep(2)  # bounded drain; each following run also has a warm-up
        return sample

    def median(self, *args, **kw):
        runs = [self.iperf(*args, **kw) for _ in range(self.a.repeat)]
        valid = all("error" not in r for r in runs)
        return {"median_mbps": statistics.median(r["mbps"] for r in runs) if valid else None, "runs": runs}

    def run(self):
        hub, host_a, carrier = (self.t.resolve(x) for x in ("hub.eth0", "host-a.eth0", "carrier.mob0"))
        kinds = ([] if self.a.no_overlay else ["overlay"]) + (["raw-cubic", "raw-bbr"] if self.a.raw else [])
        res = {"label": self.a.label, "duration_s": self.a.duration, "report_interval_s": REPORT_INTERVAL, "repeat": self.a.repeat,
               "expected_losses": [f"{x}%" for x in self.a.loss], "expected_kinds": kinds,
               "complete": False, "loss": {}}
        try:
            for loss in self.a.loss:
                self.netem(loss)
                time.sleep(1)
                cells = res["loss"][f"{loss}%"] = {}
                for kind in kinds:
                    raw = kind.startswith("raw-")
                    client, server, to, ping_to, port, cc = (("router-b", "hub", hub, carrier, RAW_PORT, kind[4:]) if raw else
                                                           ("host-b", "host-a", host_a, host_a, OVERLAY_PORT, None))
                    cell = cells[kind] = {}
                    cell["idle"] = self.idle(client, ping_to)
                    cell["up"] = self.median(client, server, to, ping_to, port, False, cc)
                    cell["down"] = self.median(client, server, to, ping_to, port, True, cc)
                    print(f"{loss}% loss {kind}: up {cell['up']['median_mbps']} down {cell['down']['median_mbps']} Mbit/s", flush=True)
            res["complete"] = True
            validate(res)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as e:
            res.update(complete=False, error=str(e))
        finally:
            try:
                self.netem(None)
            except (OSError, subprocess.SubprocessError) as e:
                res.update(complete=False, reset_error=str(e))
            out = os.path.join(self.t.rundir, "results", f"bench-{self.a.label}.json")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "w") as f:
                json.dump(res, f, indent=2, allow_nan=False)
            print(f"results: {out}", flush=True)
        return 0 if res["complete"] else 1


def table(paths):
    if not paths:
        raise ValueError("no benchmark artifacts")
    print("| setup | loss | direction | Mbit/s | idle RTT ms | loaded RTT avg ms | loaded RTT p95 ms | loss % |")
    print("|:--|:--|:--|--:|--:|--:|--:|--:|")
    for path in paths:
        with open(path) as f:
            res = validate(json.load(f))
        for loss, cells in res["loss"].items():
            for kind, cell in cells.items():
                for direction in ("up", "down"):
                    r = cell[direction]
                    summaries = [x["loaded"] for x in r["runs"]]
                    values = [statistics.median(s[k] for s in summaries) for k in ("avg_ms", "p95_ms", "loss_pct")]
                    print(f"| {res['label']} {kind} | {loss} | {direction} | {r['median_mbps']:g} | "
                          f"{cell['idle']['summary']['avg_ms']:g} | " + " | ".join(f"{v:g}" for v in values) + " |")
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--table":
        return table(sys.argv[2:])
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--topo", default=os.path.join(SIM, "topologies", "two-sites-tunxd.yaml"))
    p.add_argument("--prefix")
    p.add_argument("--rundir")
    p.add_argument("--label", required=True)
    p.add_argument("--raw", action="store_true")
    p.add_argument("--no-overlay", action="store_true")
    p.add_argument("--loss", default="0,1,3", type=lambda s: [x.strip() for x in s.split(",")])
    p.add_argument("--repeat", type=int, default=3)
    p.add_argument("--duration", type=int, default=30)
    a = p.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", a.label):
        p.error("label must contain only letters, digits, underscore or hyphen")
    if a.repeat < 1 or a.duration < 5 or (a.no_overlay and not a.raw):
        p.error("repeat must be positive, duration >= 5, and at least one path enabled")
    try:
        if len(set(a.loss)) != len(a.loss) or any(not math.isfinite(float(x)) or not 0 <= float(x) <= 100 for x in a.loss):
            raise ValueError()
    except ValueError:
        p.error("loss must be distinct percentages between 0 and 100")
    return Bench(a).run()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"bench: {e}", file=sys.stderr)
        sys.exit(1)
