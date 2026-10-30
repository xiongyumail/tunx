#!/bin/sh
# Build tunxd, copy the simulation to a disposable test VM and run the tunxd
# scenarios there as root. Run from any machine with Go and ssh access to the
# VM; nothing touches the local network configuration.
#
#   tests/sim/run-tunxd.sh [SCENARIO...]     default: tunxd-plain tunxd-xray
#   tests/sim/run-tunxd.sh bench             throughput matrix (about 1 hour):
#       tunxd-bench as plain-cubic (with the raw cubic/bbr baseline),
#       plain-bbr and reality-bbr; results in TUNX_SIM_OUT/run.*/bench-*/
#
# Environment:
#   TUNX_SIM_HOST   ssh destination of the VM (default pvetest); the user
#                   needs passwordless sudo
#   TUNX_SIM_DIR    parent directory on the VM, relative to its home (default tunx-e2e)
#   TUNX_SIM_OUT    local directory for results and logs (default
#                   ${TMPDIR:-/tmp}/tunx-sim-results)
#   XRAY_VERSION    Xray-core release tag to fetch locally (default: latest)
#   XRAY_PROXY      optional local curl fallback proxy for GitHub, e.g.
#                   socks5h://host:1080
#   SIM_SET         extra --set NAME=VALUE arguments for sim.py run
#
# The VM needs iproute2, nftables, python3-yaml, iperf3, tcpdump, ethtool,
# openssl, curl and util-linux (setpriv). The local runner also needs curl and
# sha256sum. Xray is downloaded and verified in the local evidence directory,
# then copied to the unique remote run directory. The scenarios copy binaries to
# /var/tmp/tunx-sim (the run directory under /run is noexec); the topology
# and only this run's executable copy are removed at the end.
set -eu

host=${TUNX_SIM_HOST:-pvetest}
base=${TUNX_SIM_DIR:-tunx-e2e}
outroot=${TUNX_SIM_OUT:-${TMPDIR:-/tmp}/tunx-sim-results}
repo=$(cd "$(dirname "$0")/../.." && pwd)
[ $# -gt 0 ] || set -- tunxd-plain tunxd-xray
quote() { python3 -c 'import shlex,sys; print(shlex.quote(sys.argv[1]))' "$1"; }
# These values enter remote shell commands; reject ambiguous paths and options.
python3 - "$host" "$base" "${XRAY_VERSION:-}" <<'EOF'
import re, sys
host, path, version = sys.argv[1:]
if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]*", host):
    sys.exit("invalid TUNX_SIM_HOST")
if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]*", path) or any(x in ("", ".", "..") for x in path.split("/")):
    sys.exit("TUNX_SIM_DIR must be a safe relative directory")
if version and not re.fullmatch(r"[A-Za-z0-9_.-]+", version):
    sys.exit("invalid XRAY_VERSION")
EOF
for s in "$@"; do
    case "$s" in bench|tunxd-plain|tunxd-xray|tunxd-bench|tunxd-plain.yaml|tunxd-xray.yaml|tunxd-bench.yaml) ;;
        *) echo "unknown scenario: $s" >&2; exit 1;; esac
done
extra=
for a in ${SIM_SET:-}; do
    case "$a" in *[!A-Za-z0-9_./:=,%+-]*|*=) echo "invalid SIM_SET argument" >&2; exit 1;; esac
    case "$a" in *=*) extra="$extra --set $(quote "$a")";; *) echo "SIM_SET requires NAME=VALUE" >&2; exit 1;; esac
done
mkdir -p "$outroot"
out=$(mktemp -d "$outroot/run.XXXXXX")
echo "results and logs: $out"
echo "== build tunxd"
(cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$out/tunxd" ./cmd/tunxd)
# Keep immutable download evidence locally; the VM never contacts GitHub.
echo "== fetch and verify xray locally"
xdir=$out/xray
mkdir "$xdir"
fetch() { curl -fsSL -m 120 "$@" || { [ -n "${XRAY_PROXY:-}" ] && curl -fsSL -m 300 -x "$XRAY_PROXY" "$@"; }; }
tag=${XRAY_VERSION:-}
if [ -z "$tag" ]; then
    fetch -o "$xdir/release.json" https://api.github.com/repos/XTLS/Xray-core/releases/latest
    tag=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tag_name"])' "$xdir/release.json")
fi
python3 - "$tag" <<'EOF'
import re, sys
if not re.fullmatch(r"[A-Za-z0-9_.-]+", sys.argv[1]):
    sys.exit("invalid Xray release tag")
EOF
url=https://github.com/XTLS/Xray-core/releases/download/$tag/Xray-linux-64.zip
printf '%s\n' "$tag" >"$xdir/xray.version"
printf '%s\n%s\n' "$url" "$url.dgst" >"$xdir/source.txt"
fetch -o "$xdir/Xray-linux-64.zip" "$url"
fetch -o "$xdir/Xray-linux-64.zip.dgst" "$url.dgst"
want=$(sed -n 's/^SHA2-256= *//p' "$xdir/Xray-linux-64.zip.dgst")
got=$(sha256sum "$xdir/Xray-linux-64.zip" | cut -d' ' -f1)
printf '%s  Xray-linux-64.zip\n' "$got" >"$xdir/SHA256SUMS"
[ "$want" = "$got" ] || { echo "xray: checksum mismatch ($got, want $want)" >&2; exit 1; }
python3 -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extract("xray", sys.argv[2])' "$xdir/Xray-linux-64.zip" "$xdir"
chmod 755 "$xdir/xray"
echo "xray $tag verified ($got)"
# An exclusive lock protects shared test-host resources; all other paths are
# unique to this invocation. Never remove a lock acquired by another process.
lock=/var/tmp/tunx-sim-wrapper.lock
# Defer an early signal until the acquisition command returns its owned path.
# No scenario is started before the full cleanup handlers are installed.
pending_signal=0
trap 'pending_signal=129' HUP
trap 'pending_signal=130' INT
trap 'pending_signal=143' TERM
rdir=$(ssh "$host" "sh -s -- $(quote "$base") $(quote "$lock")" <<'EOF'
set -eu
mkdir "$2" || { echo "another simulation owns $2" >&2; exit 1; }
if ! mkdir -p "$HOME/$1"; then rmdir "$2"; exit 1; fi
if ! mktemp -d "$HOME/$1/run.XXXXXX"; then rmdir "$2"; exit 1; fi
EOF
)
prefix=$(python3 -c 'import secrets; print("t" + secrets.token_hex(3))')
state=/run/tunx-sim/$prefix
runroot=$state
active_pid=
active_job=
cleaned=0
on_signal() {
    trap '' HUP INT TERM
    exit "$1"
}
cleanup() {
    status=$?
    trap - EXIT
    trap '' HUP INT TERM
    [ "$cleaned" -eq 0 ] || exit "$status"
    cleaned=1
    stopped=1
    if [ -n "$active_job" ]; then
        # A cancellation marker covers the race where SSH has not started the
        # supervisor yet. Stop waits for the supervisor to reap its child.
        if ! ssh "$host" "sudo python3 $(quote "$rdir/tests/sim/tunxd/job.py") stop --jobdir $(quote "$active_job")"; then
            stopped=0
        fi
    fi
    if [ -n "$active_pid" ]; then
        if [ "$stopped" -eq 0 ]; then kill "$active_pid" 2>/dev/null || true; fi
        wait "$active_pid" || true
        active_pid=
    fi
    if [ "$stopped" -eq 0 ]; then
        echo "remote job stop unconfirmed; lock and evidence retained at $rdir and $state" >&2
        [ "$status" -ne 0 ] || status=1
        exit "$status"
    fi
    if ! ssh "$host" "sh -s -- $(quote "$rdir") $(quote "$state") $(quote "$prefix") $(quote "$lock")" <<'EOF'
set -eu
if [ -f "$1/tests/sim/sim.py" ]; then
    cd "$1/tests/sim"
    sudo python3 sim.py down topologies/two-sites-tunxd.yaml --prefix "$3" --rundir "$2"
fi
sudo rm -rf -- "/var/tmp/tunx-sim/$3"
rmdir "$4"
EOF
    then
        echo "cleanup failed; remote evidence retained at $rdir and $state" >&2
        [ "$status" -ne 0 ] || status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
[ "$pending_signal" -eq 0 ] || exit "$pending_signal"
# Transfer archives without a pipeline so producer and ssh failures survive.
(cd "$repo" && git ls-files -co --exclude-standard tests/sim >"$out/files")
(cd "$repo" && tar -cf "$out/sim.tar" -T "$out/files")
ssh "$host" "mkdir -p $(quote "$rdir/bin") && tar -C $(quote "$rdir") -xf -" <"$out/sim.tar"
ssh "$host" "cat >$(quote "$rdir/bin/tunxd") && chmod 755 $(quote "$rdir/bin/tunxd")" <"$out/tunxd"
echo "== copy verified xray $tag"
ssh "$host" "cat >$(quote "$rdir/bin/xray") && chmod 755 $(quote "$rdir/bin/xray")" <"$xdir/xray"
ssh "$host" "cat >$(quote "$rdir/bin/xray.version")" <"$xdir/xray.version"

rc=0
run() {
    name=$1 scen=$2
    state=$runroot/$name
    shift 2
    args=
    for a in "$@"; do args="$args $(quote "$a")"; done
    echo "== $name (log: $out/$name.txt)"
    active_job=$state/job
    ssh "$host" "cd $(quote "$rdir/tests/sim") && sudo python3 tunxd/job.py run --jobdir $(quote "$active_job") -- python3 sim.py run topologies/two-sites-tunxd.yaml scenarios/$scen.yaml $args $extra --prefix $(quote "$prefix") --rundir $(quote "$state") --results $(quote "$state/results/$scen.json")" >"$out/$name.txt" 2>&1 &
    active_pid=$!
    if wait "$active_pid"; then
        remote_rc=0
    else
        remote_rc=$?
        rc=1
    fi
    active_pid=
    if [ "$remote_rc" -eq 0 ]; then active_job=; fi
    cat "$out/$name.txt"
    echo "$remote_rc" >"$out/$name.status"
    mkdir "$out/$name"
    if ! ssh "$host" "sudo tar -C $(quote "$state") -cf - results logs nodes" >"$out/$name.tar"; then
        echo "evidence copy failed: $name" >&2; rc=1; return
    fi
    if ! tar -C "$out/$name" -xf "$out/$name.tar"; then rc=1; return; fi
    if ! python3 - "$out/$name/results/$scen.json" "$repo/tests/sim" "$out/$name/results" "$scen" <<'EOF'
import json, os, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
sys.path.insert(0, sys.argv[2])
from simnet import model, scenario
expected = scenario.load(os.path.join(sys.argv[2], "scenarios", sys.argv[4] + ".yaml"),
                         model.load(os.path.join(sys.argv[2], "topologies", "two-sites-tunxd.yaml")))
steps = d.get("steps")
if not isinstance(steps, list) or len(steps) != len(expected.steps):
    sys.exit("scenario artifact lacks required steps")
if d.get("passed") is not True or not steps or any(s.get("status") != "pass" for s in steps):
    sys.exit("scenario artifact is incomplete or failed")
if sys.argv[4] == "tunxd-bench":
    sys.path.insert(0, sys.argv[2])
    from tunxd.bench import validate
    paths = [os.path.join(sys.argv[3], x) for x in os.listdir(sys.argv[3]) if x.startswith("bench-") and x.endswith(".json")]
    if len(paths) != 1:
        sys.exit("expected exactly one benchmark artifact")
    with open(paths[0]) as f:
        validate(json.load(f))
EOF
    then rc=1; fi
}
for s in "$@"; do
    s=${s%.yaml}
    if [ "$s" = bench ]; then
        # Availability only: loading modules or changing host sysctls requires
        # operator action outside this wrapper.
        ssh "$host" "grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control" || {
            echo "BBR unavailable: ask the test-host operator to enable it before benchmarking" >&2; exit 1;
        }
        run bench-plain-cubic tunxd-bench --set mode=plain --set congestion=cubic --set label=plain-cubic --set bench=--raw
        [ "$rc" -eq 0 ] || break
        run bench-plain-bbr tunxd-bench --set mode=plain --set congestion=bbr --set label=plain-bbr
        [ "$rc" -eq 0 ] || break
        run bench-reality-bbr tunxd-bench --set mode=xray --set congestion=bbr --set label=reality-bbr
        if ! python3 "$repo/tests/sim/tunxd/bench.py" --table "$out"/bench-*/results/bench-*.json >"$out/table.md"; then rc=1; fi
        cat "$out/table.md"
    else
        run "$s" "$s"
    fi
    [ "$rc" -eq 0 ] || break
done
echo "results and logs: $out"
[ "$rc" -eq 0 ] && echo "ALL PASS" || echo "FAILED"
exit "$rc"
