"""High-level operations shared by the CLI and scenarios."""
import hashlib
import json
import os

from . import SchemaError, SimError
from . import netem as netem_mod
from .actions import (Write, down_actions, link_actions, netem_cmd, netem_targets, plan_text, state_json,
                      up_actions)


def fingerprint(t):
    return hashlib.sha256(plan_text(up_actions(t)).encode()).hexdigest()[:16]


def read_state(t):
    try:
        with open(t.state_file) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def base_netem(t):
    return {k: p for k, (_, _, p) in t.netem_devices().items()}


def up(t, runner, force=False):
    """Bring a topology up. A no-op if the same topology is already fully up; otherwise rebuilt."""
    fp = fingerprint(t)
    if not runner.dry and not force:
        st = read_state(t)
        present = set(runner.list_ns())
        if st and st.get("fingerprint") == fp and all(ns in present for ns in t.namespaces()):
            runner.say(f"{t.name}: already up (prefix {t.prefix}); use --force to rebuild")
            return False
    down(t, runner, quiet=True)
    try:
        runner.do_all(up_actions(t))
        runner.do(Write(t.state_file, state_json(t, base_netem(t), fp)))
    except SimError:
        runner.say(f"{t.name}: up failed; leftovers are removed by: sim.py down {t.path}")
        raise
    if not runner.dry:
        runner.say(f"{t.name}: up ({len(t.nodes)} nodes, {len(t.segments)} segments, prefix {t.prefix}, "
                   f"run dir {t.rundir})")
    return True


def down(t, runner, quiet=False):
    """Remove every namespace of this prefix, including ones left by an older or failed topology."""
    extra = [ns for ns in runner.list_ns() if ns.startswith(t.prefix + "-")]
    runner.do_all(down_actions(t, extra))
    if not quiet and not runner.dry:
        runner.say(f"{t.name}: down (prefix {t.prefix})")


def _netem_state(t, runner):
    st = None if runner.dry else read_state(t)
    if not runner.dry and st is None:
        raise SimError(f"{t.name} is not up (no {t.state_file}); run: sim.py up {t.path}")
    return st, dict(base_netem(t), **((st or {}).get("netem") or {}))


def netem_change(t, runner, update, node=None, ifname=None, segment=None, direction="out", path="netem"):
    """Apply a runtime netem change. Changes merge with the current settings of each qdisc."""
    if direction not in ("out", "in", "both"):
        raise SchemaError(f"{path}: dir must be out, in or both, got '{direction}'")
    if not segment and not (node and ifname):
        raise SchemaError(f"{path}: name a node and interface, or a segment")
    mode, upd = netem_mod.parse_update(update, path)
    keys = netem_targets(t, node, ifname, segment, direction)
    devices = t.netem_devices()
    st, cur = _netem_state(t, runner)
    base = base_netem(t)
    for k in keys:
        if mode == "reset":
            new = base[k]
        elif mode == "clear":
            new = {}
        else:
            new = netem_mod.merge(cur.get(k, {}), upd, path)
        ns, dev, _ = devices[k]
        runner.do(netem_cmd(ns, dev, new))
        cur[k] = new
        if not runner.dry:
            runner.say(f"netem {k}: {netem_mod.describe(new)}")
    if st is not None:
        st["netem"] = cur
        runner.do(Write(t.state_file, json.dumps(st, indent=2).encode()))


def link_change(t, runner, node, ifname, state, admin=False):
    if state not in ("up", "down"):
        raise SchemaError(f"link state must be up or down, got '{state}'")
    runner.do_all(link_actions(t, node, ifname, state, admin))
    if not runner.dry:
        runner.say(f"link {node}/{ifname}: {state}{' (admin)' if admin else ''}")


def status(t, runner):
    present = set(runner.list_ns())
    st = read_state(t)
    lines = [f"{t.name}: prefix {t.prefix}, run dir {t.rundir}, "
             f"{'up' if st else 'not up'}" + (f" (vars {st.get('vars')})" if st and st.get("vars") else "")]
    for ns in t.namespaces():
        if ns in present:
            pids = runner.ns_pids(ns)
            lines.append(f"  {ns:28} present  {len(pids)} process(es)")
        else:
            lines.append(f"  {ns:28} missing")
    stray = sorted(ns for ns in present if ns.startswith(t.prefix + "-") and ns not in t.namespaces())
    for ns in stray:
        lines.append(f"  {ns:28} stray (not in this topology; removed by down)")
    if st and st.get("netem"):
        for k, p in sorted(st["netem"].items()):
            if p:
                lines.append(f"  netem {k}: {netem_mod.describe(p)}")
    runner.say("\n".join(lines))
    return bool(st) and all(ns in present for ns in t.namespaces())


def ensure_root(cmd):
    if os.geteuid() != 0:
        raise SimError(f"'{cmd}' changes network namespaces and needs root (run it in the test VM); "
                       f"use 'plan' or --dry-run to preview the commands")
