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

    # Run firewall_up from the generated script with nft captured, once with no
    # open connections and once with a stubbed ss listing some.
    sed -n '/^open_inbound() {$/,/^NFT$/p' "$NET_SCRIPT" >"$tmp/fw-funcs"
    echo "}" >>"$tmp/fw-funcs"
    for conns in none some; do
        (
            # Read by the sourced firewall_up.
            # shellcheck disable=SC2034
            TUN_NAME=tunx0 XRAY_UID=999 fams="-4 -6"
            # nft and ss are called by the sourced functions.
            # shellcheck disable=SC2317,SC2329
            nft() { cat >"$tmp/fw-$mode-$conns.nft"; }
            # shellcheck disable=SC2317,SC2329
            if [ "$conns" = some ]; then
                ss() {
                    case "$*" in
                        -Htln) printf '%s\n' 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*' 'LISTEN 0 128 [::]:22 [::]:*' ;;
                        "-Htn4 state established")
                            printf '%s\n' '0 0 10.99.0.12:22 10.99.0.1:50432' '0 0 10.99.0.12:40000 1.1.1.1:443' ;;
                        "-Htn6 state established") printf '%s\n' '0 0 [fe80::1%ens3]:22 [fe80::2%ens3]:51000' ;;
                    esac
                }
            else
                ss() { :; }
            fi
            # shellcheck source=/dev/null
            . "$tmp/fw-funcs"
            firewall_up
        )
        nft -c -f "$tmp/fw-$mode-$conns.nft"
    done
    if ! grep -q '10.99.0.12 . 22 . 10.99.0.1 . 50432' "$tmp/fw-$mode-some.nft" ||
        ! grep -q 'fe80::1 . 22 . fe80::2 . 51000' "$tmp/fw-$mode-some.nft" ||
        grep -q 40000 "$tmp/fw-$mode-some.nft"; then
        echo "FAIL: open inbound connections not listed as expected"; exit 1
    fi
    cp "$tmp/fw-$mode-none.nft" "$tmp/fw-$mode.nft"

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
