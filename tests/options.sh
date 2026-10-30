#!/usr/bin/env bash
# Exercise install choices and generated policy with isolated paths and mocks.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# shellcheck source-path=SCRIPTDIR/..
. ./install.sh
CONF_DIR=$tmp/etc
CONFIG=$CONF_DIR/config.json
mkdir -p "$CONF_DIR"
XRAY_USER=$(id -un)
fail() { echo "FAIL: $*" >&2; exit 1; }

# Stop the mocked install immediately after writing net.env. No service, DNS,
# binary, user or host configuration changes are reached.
mock_install() (
    check_deps() { :; }
    install_xray() { :; }
    check_config() { :; }
    ensure_user() { :; }
    protect_config() { :; }
    write_net_script() { exit 0; }
    cmd_install "$@"
)
mock_install >/dev/null
grep -q '^IPV6_ENABLED="1"$' "$CONF_DIR/net.env" || fail 'new install must enable IPv6'
grep -q '"queryStrategy": "UseIP"' "$CONFIG" || fail 'enabled starter DNS'

# A legacy net.env has no IPv6 key, even if a previous invocation disabled it.
printf 'TUN_NAME="tunx0"\nGATEWAY="0"\n' >"$CONF_DIR/net.env"
IPV6_ENABLED=0
load_env
[ "$IPV6_ENABLED" = 1 ] || fail 'legacy default'
mock_install >/dev/null
grep -q '^IPV6_ENABLED="1"$' "$CONF_DIR/net.env" || fail 'legacy install compatibility'

cp "$CONFIG" "$tmp/original.json"
mock_install --disable-ipv6 --disable-ipv6 >"$tmp/install.out" 2>"$tmp/install.err"
grep -q '^IPV6_ENABLED="0"$' "$CONF_DIR/net.env" || fail 'explicit disable'
cmp -s "$CONFIG" "$tmp/original.json" || fail 'existing config changed'
grep -q 'may still return AAAA' "$tmp/install.err" || fail 'existing DNS warning'
mock_install >/dev/null 2>&1
grep -q '^IPV6_ENABLED="0"$' "$CONF_DIR/net.env" || fail 'update lost disabled choice'
cp "$CONFIG" "$tmp/supplied.json"
mock_install --config "$tmp/supplied.json" >/dev/null 2>&1
cmp -s "$CONFIG" "$tmp/supplied.json" || fail 'supplied config changed'
for flags in '--enable-ipv6 --disable-ipv6' '--disable-ipv6 --enable-ipv6'; do
    # Intentional splitting: each string contains two flags.
    # shellcheck disable=SC2086
    if mock_install $flags >"$tmp/conflict.out" 2>&1; then fail 'conflicting flags accepted'; fi
    grep -q 'mutually exclusive' "$tmp/conflict.out" || fail 'missing conflict error'
    grep -q '^IPV6_ENABLED="0"$' "$CONF_DIR/net.env" || fail 'conflict changed saved choice'
done
mock_install --enable-ipv6 --enable-ipv6 >/dev/null
grep -q '^IPV6_ENABLED="1"$' "$CONF_DIR/net.env" || fail 'explicit re-enable'
mock_install >/dev/null
grep -q '^IPV6_ENABLED="1"$' "$CONF_DIR/net.env" || fail 'update lost enabled choice'
echo 'ok: install options, legacy compatibility, persistence and config preservation'

rm "$CONFIG"
mock_install --disable-ipv6 >/dev/null
grep -q '"queryStrategy": "UseIPv4"' "$CONFIG" || fail 'disabled starter DNS'
if grep -q '"queryStrategy": "UseIP"' "$CONFIG"; then fail 'disabled starter uses dual-stack DNS'; fi
echo 'ok: disabled starter DNS'

# Run only generated tun-up, with every networking command intercepted.
NET_SCRIPT=$tmp/net
write_net_script
sed -n '/^  tun-up)$/,/^  \*)/p' "$NET_SCRIPT" | sed '1d;$d' | sed '$d' >"$tmp/tun-up"
for enabled in 0 1 legacy; do
    # Variables and mocks are used by the sourced generated code.
    # shellcheck disable=SC2034,SC2329
    (
        fams='-4 -6'
        if [ "$enabled" = legacy ]; then unset IPV6_ENABLED; else IPV6_ENABLED=$enabled; fi
        ip() { echo "ip $*" >>"$tmp/tun-$enabled.log"; }
        sysctl() { echo "sysctl $*" >>"$tmp/tun-$enabled.log"; }
        # shellcheck source=/dev/null
        . "$tmp/tun-up"
    )
    if [ "$enabled" = 0 ]; then
        grep -q 'disable_ipv6=1' "$tmp/tun-$enabled.log" || fail 'missing interface disable'
        grep -q 'ip -6 route del default dev tunx0 metric 10 table 100' "$tmp/tun-$enabled.log" || fail 'stale route not removed'
        if grep -qE 'ip -6 (addr|route) replace' "$tmp/tun-$enabled.log"; then fail 'disabled TUN gets IPv6'; fi
    else
        grep -q 'disable_ipv6=0' "$tmp/tun-$enabled.log" || fail 'missing interface re-enable'
        grep -q 'ip -6 addr replace fdfe:dcba:9876::1/126 dev tunx0 nodad' "$tmp/tun-$enabled.log" || fail 'missing IPv6 address'
        grep -q 'ip -6 route replace default dev tunx0 metric 10 table 100' "$tmp/tun-$enabled.log" || fail 'missing IPv6 route'
    fi
done
# A missing kernel IPv6 stack must not cause sysctl or IPv6 route operations.
# shellcheck disable=SC2034,SC2329
(
    fams=-4 IPV6_ENABLED=1
    ip() { echo "ip $*" >>"$tmp/tun-no-ipv6.log"; }
    sysctl() { fail 'sysctl called without kernel IPv6'; }
    # shellcheck source=/dev/null
    . "$tmp/tun-up"
)
if grep -q 'ip -6' "$tmp/tun-no-ipv6.log"; then fail 'IPv6 command without kernel IPv6'; fi
# The disabled option must not remove IPv6 policy rules or its fail-closed route.
grep -q 'fams="-4"; .*fams="-4 -6"' "$NET_SCRIPT" || fail 'IPv6 policy family removed'
# shellcheck disable=SC2016
grep -q 'ip \$f route replace unreachable default metric 4096 table 100' "$NET_SCRIPT" || fail 'unreachable fallback removed'
# shellcheck disable=SC2016
grep -q 'ip \$f rule add lookup 100 priority 9100' "$NET_SCRIPT" || fail 'catch-all rule removed'
echo 'ok: generated tun-up for disabled, enabled and legacy settings; fail-closed policy retained'

# Exercise reporting with network probes and service commands mocked.
# shellcheck disable=SC2329
(
    systemctl() { :; }
    sysctl() { echo 0; }
    ip() { :; }
    nft() { :; }
    env() { while [ "${1:-}" = -u ]; do shift 2; done; "$@"; }
    curl() {
        case " $* " in
            *' -6 '*) [ -z "$mock_v6" ] || echo "ip=$mock_v6" ;;
            *) echo 'ip=203.0.113.7' ;;
        esac
        return 0
    }
    dig() { echo '203.0.113.7'; }
    python3() { echo '203.0.113.7'; }
    local_test() {
        if cmd_test >"$tmp/test.out"; then result=0; else result=$?; fi
        [ "$result" = "$1" ] || fail "unexpected test result: $result (expected $1)"
        grep -q "$2" "$tmp/test.out" || fail 'incorrect IPv6 test output'
    }
    mock_v6=''
    local_test 0 'none (disabled; expected none)'
    cmd_status >"$tmp/status.out"
    grep -q 'IPv6: disabled' "$tmp/status.out" || fail 'disabled status'
    mock_v6='2001:db8::7'
    local_test 1 '2001:db8::7 (disabled; expected none)'
    IPV6_ENABLED=1
    write_net_env
    local_test 0 'IPv6       : 2001:db8::7$'
    mock_v6=''
    local_test 0 'IPv6       : none$'
    cmd_status >"$tmp/status.out"
    grep -q 'IPv6: enabled' "$tmp/status.out" || fail 'enabled status'
)
echo 'ok: status and test expectations; disabled IPv6 egress fails'
