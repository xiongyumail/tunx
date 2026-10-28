#!/usr/bin/env bash
# Static checks: shell syntax and lint of install.sh, and of the policy script
# and nftables ruleset it generates for each mode. The ruleset check (nft -c)
# needs root but changes nothing.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

bash -n install.sh
shellcheck -x install.sh tests/*.sh

# shellcheck source-path=SCRIPTDIR/..
. ./install.sh
CONF_DIR=$tmp

for mode in host wsl gateway; do
    GATEWAY=0
    is_wsl() { false; }
    case "$mode" in
        wsl) is_wsl() { true; } ;;
        gateway) GATEWAY=1 ;;
    esac
    NET_SCRIPT=$tmp/net-$mode
    write_net_script
    bash -n "$NET_SCRIPT"
    # Warnings only: unquoted family flags ($f) are deliberate. SC1091: net.env
    # exists only on an installed system.
    shellcheck -S warning -e SC1091 "$NET_SCRIPT"

    # The ruleset exactly as firewall_up loads it, with the runtime values filled in.
    # shellcheck disable=SC2016 # the names are matched literally
    sed -n '/^firewall_up() {$/,/^NFT$/p' "$NET_SCRIPT" | sed '1,2d;$d' |
        sed 's/\$TUN_NAME/tunx0/g; s/\$XRAY_UID/999/g' >"$tmp/fw-$mode.nft"
    nft -c -f "$tmp/fw-$mode.nft"

    has() { grep -q -- "$1" "$tmp/fw-$mode.nft"; }
    if [ "$mode" = gateway ]; then
        if ! has 'chain gateway' || ! has 'fib daddr type local' || ! has 'meta mark set 0x2a'; then
            echo "FAIL: gateway ruleset is missing its forward chain or inbound match"; exit 1
        fi
    elif has 'chain gateway' || has 'fib daddr'; then
        echo "FAIL: $mode ruleset has gateway parts"; exit 1
    fi
    if [ "$mode" = wsl ] && ! has '10.255.255.254'; then
        echo "FAIL: wsl ruleset does not drop WSL DNS"; exit 1
    fi
    echo "ok: $mode"
done
