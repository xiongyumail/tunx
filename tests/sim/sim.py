#!/usr/bin/env python3
"""Network namespace simulator: bring up a topology from YAML, drive it, run scenarios.

Every command except `plan` changes namespaces and needs root; add --dry-run to
print the commands instead. See README.md for the YAML reference.
"""
import argparse
import os
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from simnet import SchemaError, SimError, model, ops, scenario  # noqa: E402
from simnet.actions import DelNs, KillNs, down_actions, plan_text, up_actions  # noqa: E402
from simnet.runner import Runner  # noqa: E402


def parse_sets(items):
    out = {}
    for item in items or []:
        if "=" not in item:
            raise SchemaError(f"--set {item}: expected NAME=VALUE")
        k, v = item.split("=", 1)
        out[k.strip()] = v
    return out


def load_topo(args, sets=None, from_state=False):
    sets = parse_sets(args.set) if sets is None else sets
    t = model.load(args.topo, sets, args.prefix, args.rundir)
    if from_state and not sets:
        # Reuse the vars the topology was brought up with.
        st = ops.read_state(t)
        if st and st.get("vars") and st["vars"] != t.vars:
            known = {k: v for k, v in st["vars"].items() if k in t.vars}
            t = model.load(args.topo, known, args.prefix, args.rundir)
    return t


def cmd_plan(args, runner):
    t = load_topo(args)
    out = [f"# topology {t.name}: {len(t.nodes)} nodes, {len(t.segments)} segments, prefix {t.prefix}, "
           f"run dir {t.rundir}", f"# vars: {t.vars}"]
    if args.phase in ("up", "all"):
        out += ["", "### up", plan_text(up_actions(t)).rstrip()]
    if args.phase in ("down", "all"):
        out += ["", "### down", plan_text(down_actions(t)).rstrip()]
    runner.say("\n".join(out))
    return 0


def cmd_up(args, runner):
    ops.up(load_topo(args), runner, force=args.force)
    return 0


def cmd_down(args, runner):
    if args.topo:
        ops.down(load_topo(args), runner)
        return 0
    if not args.prefix:
        raise SchemaError("down: give a topology file or --prefix")
    # No topology file: remove whatever namespaces carry this prefix.
    names = [ns for ns in runner.list_ns() if ns.startswith(args.prefix + "-")]
    runner.do_all([KillNs(ns) for ns in names] + [DelNs(ns) for ns in names])
    runner.say(f"prefix {args.prefix}: removed {len(names)} namespace(s)")
    return 0


def cmd_status(args, runner):
    return 0 if ops.status(load_topo(args, from_state=True), runner) else 1


def cmd_exec(args, runner):
    t = load_topo(args, from_state=True)
    ns = t.node(args.node).ns
    cmd = args.cmd[1:] if args.cmd and args.cmd[0] == "--" else args.cmd
    if not cmd:
        cmd = [os.environ.get("SHELL", "/bin/bash")]
    argv = ["ip", "netns", "exec", ns, *cmd]
    if runner.dry:
        runner.say(shlex.join(argv))
        return 0
    os.execvp("ip", argv)


def cmd_netem(args, runner):
    t = load_topo(args, from_state=True)
    words = list(args.words)
    if args.segment:
        node = ifname = None
    else:
        if len(words) < 3:
            raise SchemaError("netem: usage: netem TOPO NODE IF PARAMS... | netem TOPO --segment SEG PARAMS...")
        node, ifname, words = words[0], words[1], words[2:]
    ops.netem_change(t, runner, words, node, ifname, args.segment, args.dir)
    return 0


def cmd_link(args, runner):
    t = load_topo(args, from_state=True)
    ops.link_change(t, runner, args.node, args.iface, args.state, args.admin)
    return 0


def cmd_run(args, runner):
    sets = parse_sets(args.set)
    scen_vars = scenario.scenario_vars(scenario.read_raw(args.scenario))
    topo_raw_vars = set(model.load(args.topo).vars)
    unknown = [k for k in sets if k not in topo_raw_vars and k not in scen_vars]
    if unknown:
        raise SchemaError(f"--set {unknown[0]}: not a variable of the topology or the scenario")
    t = load_topo(args, {k: v for k, v in sets.items() if k in topo_raw_vars}, from_state=args.no_up)
    s = scenario.load(args.scenario, t, {k: v for k, v in sets.items() if k in scen_vars})
    if not args.no_up:
        ops.up(t, runner, force=True)
    try:
        ok = scenario.run(t, s, runner, args.results)
    finally:
        if not args.keep and not args.no_up:
            ops.down(t, runner)
    return 0 if ok else 1


def main(argv=None):
    p = argparse.ArgumentParser(prog="sim.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-n", "--dry-run", action="store_true", help="print commands instead of running them")
    p.add_argument("-v", "--verbose", action="store_true", help="echo each command as it runs")
    sub = p.add_subparsers(dest="cmd", required=True)

    def topo_cmd(name, help_, topo_optional=False):
        sp = sub.add_parser(name, help=help_)
        if topo_optional:
            sp.add_argument("topo", nargs="?", help="topology YAML")
        else:
            sp.add_argument("topo", help="topology YAML")
        sp.add_argument("--prefix", help="namespace prefix (default: from the topology, or $SIM_PREFIX)")
        sp.add_argument("--rundir", help="run directory for logs and state (default /run/tunx-sim/PREFIX)")
        sp.add_argument("--set", action="append", metavar="NAME=VALUE", help="override a variable")
        return sp

    sp = topo_cmd("plan", "print the commands `up` (and `down`) would run; no root needed")
    sp.add_argument("--phase", choices=("up", "down", "all"), default="all")
    sp.set_defaults(func=cmd_plan, needs_root=False)

    sp = topo_cmd("up", "create namespaces, links, addresses, rules and start daemons")
    sp.add_argument("--force", action="store_true", help="rebuild even if already up")
    sp.set_defaults(func=cmd_up)

    sp = topo_cmd("down", "kill processes and delete every namespace with the prefix", topo_optional=True)
    sp.set_defaults(func=cmd_down)

    sp = topo_cmd("status", "show which namespaces exist and current netem settings")
    sp.set_defaults(func=cmd_status, needs_root=False)

    sp = topo_cmd("exec", "run a command (default: a shell) inside a node")
    sp.add_argument("node")
    sp.add_argument("cmd", nargs=argparse.REMAINDER, help="-- command...")
    sp.set_defaults(func=cmd_exec)

    sp = topo_cmd("netem", "change netem at runtime: NODE IF PARAMS... or --segment SEG PARAMS...")
    sp.add_argument("words", nargs="+", metavar="ARG",
                    help="NODE IF then e.g. 'loss 3%%', 'delay 40ms jitter 5ms', 'loss off', 'reset', 'clear'")
    sp.add_argument("--segment", help="apply to every port of this segment (traffic towards its nodes)")
    sp.add_argument("--dir", choices=("out", "in", "both"), default="out",
                    help="out: leaving the node (default); in: towards the node; both")
    sp.set_defaults(func=cmd_netem)

    sp = topo_cmd("link", "cut or restore a link at runtime")
    sp.add_argument("node")
    sp.add_argument("iface")
    sp.add_argument("state", choices=("up", "down"))
    sp.add_argument("--admin", action="store_true",
                    help="set the node's interface admin down/up instead of pulling the cable at the bridge")
    sp.set_defaults(func=cmd_link)

    sp = topo_cmd("run", "bring the topology up fresh, run a scenario, tear down")
    sp.add_argument("scenario", help="scenario YAML")
    sp.add_argument("--keep", action="store_true", help="leave the topology up afterwards")
    sp.add_argument("--no-up", action="store_true", help="use the topology that is already up; do not tear down")
    sp.add_argument("--results", help="results JSON path (default RUNDIR/results/SCENARIO.json)")
    sp.set_defaults(func=cmd_run)

    args = p.parse_args(argv)
    runner = Runner(dry=args.dry_run, verbose=args.verbose)
    try:
        if getattr(args, "needs_root", True) and not args.dry_run:
            ops.ensure_root(args.cmd)
        return args.func(args, runner)
    except SchemaError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except SimError as e:
        print(f"failed: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted; clean up with: sim.py down TOPO", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
