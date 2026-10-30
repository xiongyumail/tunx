#!/usr/bin/env python3
"""Query and check a tunxd status endpoint (stdlib only).

  status.py                              print sessions, selected routes, drops
  status.py --up hub --up exit           exit 0 when sessions to both peers are up
  status.py --down hub                   exit 0 when no session to hub is up
  status.py --route 10.0.2.0/24=peer:hub exit 0 when the route selects that next hop
  status.py --drop denied=1              exit 0 when at least 1 flow was dropped as denied

Checks combine (all must hold). Exit 1 with the reason when one fails, 2 when
the endpoint does not answer.
"""
import argparse
import json
import sys
import urllib.request


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--addr", default="127.0.0.1:7790")
    p.add_argument("--up", action="append", default=[], metavar="PEER")
    p.add_argument("--down", action="append", default=[], metavar="PEER")
    p.add_argument("--route", action="append", default=[], metavar="PREFIX=SELECTED")
    p.add_argument("--drop", action="append", default=[], metavar="REASON=MIN")
    p.add_argument("--json", action="store_true", help="print the whole status")
    args = p.parse_args()
    try:
        with urllib.request.urlopen(f"http://{args.addr}/status", timeout=3) as r:
            st = json.load(r)
    except OSError as e:
        print(f"status {args.addr}: {e}", file=sys.stderr)
        return 2

    peers = sorted({s["peer"] for s in st.get("sessions") or []})
    routes = {r["prefix"]: r["selected"] for r in st.get("routes") or []}
    drops = st.get("stats", {}).get("drops") or {}
    if args.json:
        print(json.dumps(st, indent=2))
    else:
        rtt = ", ".join(f"{s['peer']} {s['rtt_ms']:.1f}ms" for s in st.get("sessions") or [])
        print(f"{st['node']}: sessions [{rtt}] drops {drops}")
        print("routes: " + ", ".join(f"{k}={v or '-'}" for k, v in routes.items()))

    bad = []
    bad += [f"no session to {x}" for x in args.up if x not in peers]
    bad += [f"session to {x} is up" for x in args.down if x in peers]
    for spec in args.route:
        prefix, want = spec.split("=", 1)
        if routes.get(prefix) != want:
            bad.append(f"route {prefix} selects {routes.get(prefix)!r}, want {want!r}")
    for spec in args.drop:
        reason, n = spec.split("=", 1)
        if drops.get(reason, 0) < int(n):
            bad.append(f"drops {reason} = {drops.get(reason, 0)}, want >= {n}")
    for b in bad:
        print("check failed: " + b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
