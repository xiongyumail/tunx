#!/usr/bin/env bash
# Config checks: download Xray as install does (SHA-256 verified), then run
# check_config on the examples and the starter config, and make sure it rejects
# configs that do not fit. No root needed; nothing outside a temp dir changes.
# Set TUNX_PROXY to download through a proxy.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# shellcheck source-path=SCRIPTDIR/..
. ./install.sh
BIN=$tmp/bin/xray
ASSET_DIR=$tmp/share
CONF_DIR=$tmp/etc
CONFIG=$CONF_DIR/config.json
mkdir -p "$tmp/bin"

install_xray "$XRAY_VERSION_DEFAULT" "" "${TUNX_PROXY:-}"

# Placeholders such as <id> in the examples get valid dummy values.
pbk=$("$BIN" x25519 | awk -F': ' 'tolower($1) ~ /^(password|public key)/ {print $2; exit}')
for f in examples/*.jsonc; do
    sed -e "s/<address>/proxy.example.com/g; s/<id>/$("$BIN" uuid)/g; s/<serverName>/www.example.com/g" \
        -e "s/<publicKey>/$pbk/g; s/<shortId>/0123abcd/g" "$f" >"$tmp/example.jsonc"
    check_config "$tmp/example.jsonc"
    echo "ok: $f"
done
write_starter_config >/dev/null
check_config "$CONFIG"
echo "ok: starter config"

# Broken variants of the gateway example; each must be rejected.
XRAY_LOCATION_ASSET=$ASSET_DIR "$BIN" run -dump -c examples/gateway.jsonc >"$tmp/base.json"
mutate() {
    python3 -I - "$tmp/base.json" "$tmp/$1.json" "$2" <<'EOF'
import json, sys
cfg = json.load(open(sys.argv[1]))
rules = cfg["routing"]["rules"]
tun = next(i for i in cfg["inbounds"] if i["protocol"] == "tun")
case = sys.argv[3]
if case == "dns-late":
    i = next(n for n, r in enumerate(rules) if r.get("port") == "53")
    rules.append(rules.pop(i))
elif case == "two-tuns":
    cfg["inbounds"].append(dict(tun, tag="tun2"))
elif case == "tun-name":
    tun["settings"]["name"] = "other0"
elif case == "auto-route":
    tun["settings"]["autoSystemRoutingTable"] = ["vpn"]
elif case == "unlisted-host":
    out = next(o for o in cfg["outbounds"] if o["tag"] == "proxy")
    out["settings"]["servers"][0]["address"] = "proxy.example.com"
json.dump(cfg, open(sys.argv[2], "w"))
EOF
}
for case in dns-late two-tuns tun-name auto-route unlisted-host; do
    mutate "$case" "$case"
    if (check_config "$tmp/$case.json") 2>"$tmp/err"; then
        echo "FAIL: $case was accepted"; exit 1
    fi
    echo "ok: rejects $case ($(grep -m1 ERROR "$tmp/err" | sed 's/\x1b\[[0-9;]*m//g'))"
done
