#!/usr/bin/env bash
# tunx: send all traffic of a WSL2 (or systemd Linux) host into an
# Xray TUN and let your own Xray config decide where it goes.
#
#   sudo ./install.sh install [--config my-config.json]
#   sudo ./install.sh reload
#   sudo ./install.sh status | test | check
#   sudo ./install.sh tz
#   sudo ./install.sh uninstall
#
# This script owns the plumbing: Xray binary, TUN policy routing (fail closed),
# DNS and systemd units. Outbounds and routing rules live in the Xray config,
# which is never overwritten once it exists.
set -euo pipefail

XRAY_VERSION_DEFAULT="v26.10.21"
TUN_NAME="tunx0"
TUN_ADDR="198.18.0.1/30"
TUN_ADDR6="fdfe:dcba:9876::1/126"
TABLE=100
RULE_XRAY=8991
RULE_INBOUND=8995
# Gateway mode only: packets Xray writes back for forwarded clients, and ICMP
# from clients (the TUN carries only TCP and UDP), use the main table.
RULE_ICMP=8996
RULE_TUNBACK=8997
RULE_TUN=9100
# Connections opened from outside through a physical interface get this mark,
# so their replies can leave the same way.
MARK_INBOUND=0x2a
# Connections opened by Xray get this conntrack mark, so packets the kernel still
# sends after Xray has closed the socket (remaining data, FIN, RST) are let out.
MARK_XRAY=0x2b

BIN=/usr/local/bin/xray
# Xray runs as this system user; only its sockets bypass the TUN.
XRAY_USER=tunx
ASSET_DIR=/usr/local/share/xray
CONF_DIR=/etc/tunx
CONFIG=$CONF_DIR/config.json
NET_SCRIPT=/usr/local/sbin/tunx-net
UNIT_POLICY=/etc/systemd/system/tunx-policy.service
UNIT_TUN=/etc/systemd/system/tunx.service
UNIT_GUARD=/etc/systemd/system/tunx-guard.service
STATE_DIR=/var/lib/tunx
NM_CONF=/etc/NetworkManager/conf.d/90-tunx.conf
SYSCTL_CONF=/etc/sysctl.d/90-tunx-gateway.conf
GATEWAY=0

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: sudo $0 <command> [options]

Commands:
  install     Install or update Xray, routing, DNS and services, then start
  reload      Check $CONFIG, then restart Xray (nothing is restarted on error)
  check       Check $CONFIG without restarting
  uninstall   Stop, remove everything, restore DNS
  status      Show service, routing, and DNS state
  test        Check egress IP over TCP, DNS, UDP (STUN), and IPv6
  tz          Set the system time zone to that of the egress IP (restored on uninstall)

Install options:
  --config FILE        Xray config to install (checked first; the old one is kept as
                       a backup). Without it an existing config is left untouched, and
                       a starter config is written on first install.
  --version TAG        Xray release tag (default: $XRAY_VERSION_DEFAULT)
  --zip PATH           Use a local Xray-linux-*.zip instead of downloading
  --proxy URL          Proxy for downloading Xray, e.g. socks5h://192.168.1.10:1080
  --tun-name NAME      TUN interface name (default: $TUN_NAME)
  --gateway            Also forward the traffic of LAN clients that use this host
                       as their gateway into the TUN (kept on later installs)
EOF
}

need_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }

is_wsl() { grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; }

load_env() {
    # shellcheck disable=SC1091
    [ -r "$CONF_DIR/net.env" ] && . "$CONF_DIR/net.env"
    return 0
}

xray_asset_name() {
    case "$(uname -m)" in
        x86_64) echo "Xray-linux-64.zip" ;;
        aarch64 | arm64) echo "Xray-linux-arm64-v8a.zip" ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
}

check_deps() {
    local missing=()
    for c in curl unzip ip nft systemctl sha256sum python3; do
        command -v "$c" >/dev/null || missing+=("$c")
    done
    [ ${#missing[@]} -eq 0 ] || die "missing commands: ${missing[*]} (apt install curl unzip iproute2 nftables python3)"
    [ -d /run/systemd/system ] || die "systemd is not running (on WSL set [boot] systemd=true in /etc/wsl.conf)"
    [ -c /dev/net/tun ] || modprobe tun 2>/dev/null || true
    [ -c /dev/net/tun ] || die "/dev/net/tun not available"
}

ensure_user() {
    id -u "$XRAY_USER" >/dev/null 2>&1 ||
        useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$XRAY_USER"
}

# The config holds credentials: readable by root and the Xray user only.
protect_config() { chown "root:$XRAY_USER" "$CONFIG"; chmod 640 "$CONFIG"; }

install_xray() {
    local version="$1" zip="$2" via="$3" tmp
    if [ -z "$zip" ] && [ -x "$BIN" ] && "$BIN" version 2>/dev/null | head -1 | grep -q "^Xray ${version#v} "; then
        log "Xray $version already installed"
        return
    fi
    tmp=$(mktemp -d)
    if [ -z "$zip" ]; then
        local name url proxy=()
        name=$(xray_asset_name)
        url="https://github.com/XTLS/Xray-core/releases/download/$version/$name"
        [ -n "$via" ] && proxy=(-x "$via")
        log "Downloading Xray $version ($name)"
        curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 "${proxy[@]}" -o "$tmp/xray.zip" "$url" || die "download failed: $url (try --proxy or --zip)"
        curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 "${proxy[@]}" -o "$tmp/xray.dgst" "$url.dgst" || die "download failed: $url.dgst"
        local want got
        want=$(awk -F'= ' 'toupper($1)=="SHA2-256" {print $2}' "$tmp/xray.dgst" | head -1)
        got=$(sha256sum "$tmp/xray.zip" | awk '{print $1}')
        if [ -z "$want" ] || [ "$want" != "$got" ]; then die "SHA-256 mismatch (want $want, got $got)"; fi
        log "SHA-256 verified"
        zip="$tmp/xray.zip"
    fi
    unzip -q -o "$zip" xray geoip.dat geosite.dat -d "$tmp/out"
    install -d "$ASSET_DIR"
    install -m 755 "$tmp/out/xray" "$BIN.new" && mv -f "$BIN.new" "$BIN"
    install -m 644 "$tmp/out/geoip.dat" "$tmp/out/geosite.dat" "$ASSET_DIR/"
    rm -rf "$tmp"
    log "Installed $("$BIN" version | head -1)"
}

write_starter_config() {
    install -d -m 755 "$CONF_DIR"
    (umask 077; cat >"$CONFIG") <<EOF
// tunx starter config. Edit the "proxy" outbound and the routing rules,
// then run: sudo $0 reload
// Everything on this host enters the TUN inbound below; routing decides where it goes.
{
  "log": { "loglevel": "warning", "access": "none" },

  // Built-in DNS with cache. It answers the system's A/AAAA queries (see the
  // "dns-out" outbound) over DoH through the proxy. Upstream hostnames cannot be
  // resolved through the proxy itself: list every one in the first server's
  // "domains", which is queried directly.
  "dns": {
    "tag": "dns-internal",
    "queryStrategy": "UseIP",
    "serveStale": true,
    "serveExpiredTTL": 3600,
    "servers": [
      { "address": "https://223.5.5.5/dns-query", "domains": [ "full:proxy.example.com" ],
        "skipFallback": true, "queryStrategy": "UseIPv4" },
      "https://1.1.1.1/dns-query",
      "https://8.8.8.8/dns-query"
    ]
  },

  "inbounds": [
    {
      "tag": "tun-in",
      "port": 0,
      "protocol": "tun",
      "settings": {
        "name": "$TUN_NAME",          // must match --tun-name
        "mtu": 1500
      },
      "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ], "routeOnly": true }
    }
  ],

  "outbounds": [
    // Replace with your upstream. Examples: examples/ in the repository.
    // Hostnames are fine once listed in the first DNS server's "domains".
    {
      "tag": "proxy",
      "protocol": "socks",
      "settings": { "servers": [ { "address": "127.0.0.1", "port": 1080 } ] },
      "streamSettings": { "sockopt": { "domainStrategy": "UseIPv4" } }
    },
    { "tag": "direct", "protocol": "freedom" },
    // A/AAAA go to the built-in DNS above; other types go to 1.1.1.1 through the proxy.
    { "tag": "dns-out", "protocol": "dns",
      "settings": { "rewriteAddress": "1.1.1.1", "rewritePort": 53,
                    "rules": [ { "action": "hijack", "qType": "1,28" }, { "action": "direct" } ] },
      "streamSettings": { "sockopt": { "dialerProxy": "proxy" } } },
    { "tag": "block", "protocol": "blackhole" }
  ],

  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "inboundTag": [ "dns-internal" ], "ip": [ "223.5.5.5" ], "outboundTag": "direct" },
      { "inboundTag": [ "dns-internal" ], "outboundTag": "proxy" },
      // All DNS, also to LAN resolvers (DHCP-configured ones used by systemd-resolved
      // or NetworkManager), is answered here so no query leaves directly.
      { "port": "53", "outboundTag": "dns-out" },
      {
        "ip": [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                "100.64.0.0/10", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128" ],
        "outboundTag": "direct"
      },
      // Add domain or IP rules here, e.g.
      // { "domain": [ "geosite:cn" ], "outboundTag": "direct" },
      { "network": "tcp,udp", "outboundTag": "proxy" }
    ]
  }
}
EOF
    log "Wrote starter config $CONFIG (edit the \"proxy\" outbound, then: sudo $0 reload)"
}

# Check a config file: Xray accepts it and its TUN inbound matches the routing setup.
check_config() {
    local file="$1" dump
    [ -r "$file" ] || die "cannot read $file"
    dump=$(XRAY_LOCATION_ASSET=$ASSET_DIR "$BIN" run -dump -c "$file" 2>&1) || {
        echo "$dump" | tail -5 >&2; die "Xray cannot load $file"
    }
    if ! XRAY_LOCATION_ASSET=$ASSET_DIR "$BIN" run -test -c "$file" >/dev/null 2>&1; then
        XRAY_LOCATION_ASSET=$ASSET_DIR "$BIN" run -test -c "$file" 2>&1 | tail -5 >&2
        die "Xray rejected $file"
    fi
    TUN_NAME="$TUN_NAME" python3 -I -c '
import json, os, sys
cfg = json.load(sys.stdin)
name = os.environ["TUN_NAME"]
errors = []
tuns = [i for i in cfg.get("inbounds") or [] if i.get("protocol") == "tun"]
if len(tuns) != 1:
    errors.append("need exactly one tun inbound, found %d" % len(tuns))
else:
    s = tuns[0].get("settings") or {}
    if s.get("name") != name:
        errors.append("tun inbound name is %r, expected %r" % (s.get("name"), name))
    if s.get("autoSystemRoutingTable"):
        errors.append("remove autoSystemRoutingTable: routes are managed by tunx-net")
if not cfg.get("outbounds"):
    errors.append("no outbounds")
# With DNS hijacking, the built-in DNS also serves the system. An upstream hostname
# it would resolve through the proxy can never connect, so each must be listed in
# the "domains" of a DNS server.
if any(o.get("protocol") == "dns" for o in cfg.get("outbounds") or []):
    listed = []
    for srv in (cfg.get("dns") or {}).get("servers") or []:
        if isinstance(srv, dict):
            listed += srv.get("domains") or []
    def covered(host):
        for d in listed:
            if d in ("full:" + host, host) or (d.startswith("domain:") and
                    (host == d[7:] or host.endswith("." + d[7:]))):
                return True
        return False
    for o in cfg.get("outbounds") or []:
        st = o.get("settings") or {}
        for e in (st.get("vnext") or []) + (st.get("servers") or []) + [st]:
            host = e.get("address") if isinstance(e, dict) else None
            if (isinstance(host, str) and host and not host.replace(".", "").isdigit()
                    and ":" not in host and not covered(host)):
                errors.append("outbound %r address %r is not listed in any dns server "
                              "\x27domains\x27: add \x22full:%s\x22 to the directly queried server"
                              % (o.get("tag"), host, host))
# The port 53 rule must come before any rule that would catch DNS packets first
# (IP rules, catch-alls), or DNS sent to those addresses skips the built-in DNS
# and leaves directly, e.g. queries to a LAN resolver.
dns_tags = {o.get("tag") for o in cfg.get("outbounds") or [] if o.get("protocol") == "dns"}
if dns_tags:
    def has53(port):
        if port is None:
            return True
        for part in str(port).split(","):
            lo, _, hi = part.strip().partition("-")
            if lo.isdigit() and int(lo) <= 53 <= int(hi or lo):
                return True
        return False
    rules = (cfg.get("routing") or {}).get("rules") or []
    dns_rule = next((i for i, x in enumerate(rules) if x.get("outboundTag") in dns_tags
                     and not x.get("inboundTag") and x.get("port") is not None
                     and has53(x.get("port"))), None)
    if dns_rule is None:
        errors.append("no routing rule sends port 53 to the dns outbound")
    else:
        for i, x in enumerate(rules[:dns_rule]):
            if (x.get("inboundTag") or x.get("outboundTag") in dns_tags
                    or set(x) - {"ip", "network", "port", "outboundTag", "balancerTag", "ruleTag", "type"}
                    or not has53(x.get("port"))):
                continue
            errors.append("routing rule %d (to %r) comes before the port 53 rule, so DNS "
                          "sent to its addresses leaves without the built-in DNS: move "
                          "{\x22port\x22: \x2253\x22, ...} above it"
                          % (i + 1, x.get("outboundTag") or x.get("balancerTag")))
for e in errors:
    print("ERROR: " + e, file=sys.stderr)
sys.exit(1 if errors else 0)
' <<<"$dump" || die "$file does not fit this setup (see above)"
}

write_net_env() {
    install -d -m 755 "$CONF_DIR"
    {
        printf 'TUN_NAME="%s"\n' "$TUN_NAME"
        printf 'XRAY_UID="%s"\n' "$(id -u "$XRAY_USER")"
        printf 'GATEWAY="%s"\n' "$GATEWAY"
    } >"$CONF_DIR/net.env"
}

write_net_script() {
    # WSL answers DNS on 10.255.255.254, which sits on lo and so never enters the
    # TUN: queries sent there would leave through Windows. tunx does not use it.
    local wsl_dns="" inbound_match="" inbound_skb="" forward_chain=""
    if [ "$GATEWAY" = 1 ]; then
        # Forwarded connections are not inbound: they must enter the TUN.
        inbound_match="fib daddr type local"
        # Inbound packets carry the mark too, so with tcp_fwmark_accept an accepted
        # socket (e.g. SSH) routes by the main table from its first reply; the
        # host stays reachable while Xray is down.
        inbound_skb="ct mark $MARK_INBOUND meta mark set $MARK_INBOUND"
        # Forwarding is allowed only into and out of the TUN, plus ICMP.
        forward_chain="chain gateway {
    type filter hook forward priority filter; policy accept;
    iifname \"\$TUN_NAME\" accept
    oifname \"\$TUN_NAME\" accept
    meta l4proto { icmp, ipv6-icmp } accept
    counter drop
  }"
    fi
    if is_wsl; then
        wsl_dns='ip daddr 10.255.255.254 meta l4proto { tcp, udp } th dport 53 counter drop'
    fi
    cat >"$NET_SCRIPT" <<EOF
#!/bin/bash
# Policy routing and firewall for the Xray TUN (managed by tunx).
# Sockets of the Xray user, and replies to connections opened from outside, use
# the main table; everything else, LAN included, goes to table $TABLE and Xray
# does the routing. IPv4 and IPv6 both go to the TUN; the table's fallback is
# unreachable, so traffic fails closed while Xray is down.
# Routing alone cannot stop a program that binds its socket to a physical
# interface: when the lookup fails, the kernel sends it out as if on-link. The
# nftables table drops such packets unless they belong to a connection of the Xray
# user, reply to an inbound connection, or are link-level (broadcast, multicast,
# DHCP).
set -u
. $CONF_DIR/net.env
# IPv6 rules only when the kernel has IPv6.
fams="-4"; [ -e /proc/net/if_inet6 ] && fams="-4 -6"

mkdir -p /run/tunx
# One change at a time: install, boot and the guard may run this together.
case "\${1:-}" in policy-up|policy-down|ensure) exec 9>/run/tunx/lock; flock 9 ;; esac

rule_del() { while ip "\$1" rule show | grep -q "^\$2:"; do ip "\$1" rule del priority "\$2"; done; }
# rule_is FAMILY PRIORITY TEXT: exactly one rule at PRIORITY, reading TEXT.
rule_is() { [ "\$(ip "\$1" rule show priority "\$2" | sed 's/^[0-9]*:[[:space:]]*//; s/ \[detached\]//; s/[[:space:]]*\$//')" = "\$3" ]; }
# Fingerprint of the firewall table without its counters.
fw_sig() { nft list table inet tunx 2>/dev/null | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/' | sha256sum | cut -d" " -f1; }
# What differs from the state policy-up sets: the firewall table as loaded, the
# rules exactly as written, the unreachable fallback.
state_errors() {
  local f bad=""
  [ "\$(fw_sig)" = "\$(cat /run/tunx/fw.sig 2>/dev/null)" ] || bad="firewall"
  for f in \$fams; do
    rule_is \$f $RULE_XRAY "from all uidrange \$XRAY_UID-\$XRAY_UID lookup main" || bad="\$bad rule\$f:$RULE_XRAY"
    rule_is \$f $RULE_INBOUND "from all fwmark $MARK_INBOUND lookup main" || bad="\$bad rule\$f:$RULE_INBOUND"
    rule_is \$f $RULE_TUN "from all lookup $TABLE" || bad="\$bad rule\$f:$RULE_TUN"
    if [ "\$GATEWAY" = 1 ]; then
      rule_is \$f $RULE_TUNBACK "from all iif \$TUN_NAME lookup main" || bad="\$bad rule\$f:$RULE_TUNBACK"
    fi
    ip \$f route show table $TABLE | grep -q "^unreachable default" || bad="\$bad route\$f:unreachable"
  done
  if [ "\$GATEWAY" = 1 ]; then
    rule_is -4 $RULE_ICMP "from all ipproto icmp lookup main" || bad="\$bad rule-4:$RULE_ICMP"
  fi
  echo "\$bad"
}
# rule_set FAMILY PRIORITY SELECTOR...: replace the rule at PRIORITY.
rule_set() { rule_del "\$1" "\$2"; ip "\$1" rule add "\${@:3}" priority "\$2"; }

# open_inbound 4|6: established TCP connections to a listening port, as nft
# set elements (local address . port . peer address . port).
open_inbound() {
  local listen l r lp rp
  listen=" \$(ss -Htln | awk '{n = split(\$4, a, ":"); print a[n]}' | sort -u | tr '\n' ' ') "
  ss -Htn"\$1" state established | while read -r _ _ l r _; do
    lp=\${l##*:}; rp=\${r##*:}
    case "\$listen" in *" \$lp "*) ;; *) continue ;; esac
    l=\${l%:*}; r=\${r%:*}; l=\${l#[}; l=\${l%]}; r=\${r#[}; r=\${r%]}
    printf '%s . %s . %s . %s, ' "\${l%%\%*}" "\$lp" "\${r%%\%*}" "\$rp"
  done
}

firewall_up() {
  local open e4="" e6=""
  open=\$(open_inbound 4); [ -z "\$open" ] || e4="elements = { \$open }"
  if [ "\$fams" != "-4" ]; then
    open=\$(open_inbound 6); [ -z "\$open" ] || e6="elements = { \$open }"
  fi
  nft -f - <<NFT
table inet tunx
delete table inet tunx
table inet tunx {
  chain pre {
    type filter hook prerouting priority mangle; policy accept;
    iifname != { "lo", "\$TUN_NAME" } ct state new $inbound_match ct mark set $MARK_INBOUND
    $inbound_skb
  }
  $forward_chain
  # Inbound TCP connections already open when the table is loaded, such as the
  # SSH session running the install. Conntrack may have picked them up mid-way
  # with this host as the opener, so the pre chain cannot tell; without this
  # their replies would be sent into the TUN and reset.
  set open4 {
    type ipv4_addr . inet_service . ipv4_addr . inet_service
    \$e4
  }
  set open6 {
    type ipv6_addr . inet_service . ipv6_addr . inet_service
    \$e6
  }
  chain route {
    type route hook output priority mangle; policy accept;
    ip saddr . tcp sport . ip daddr . tcp dport @open4 ct mark set $MARK_INBOUND
    ip6 saddr . tcp sport . ip6 daddr . tcp dport @open6 ct mark set $MARK_INBOUND
    ct mark $MARK_INBOUND meta mark set $MARK_INBOUND
  }
  chain out {
    type filter hook output priority filter; policy accept;
    $wsl_dns
    oifname { "lo", "\$TUN_NAME" } accept
    # The owner of a socket is only visible while a process holds it.
    meta skuid \$XRAY_UID ct mark set $MARK_XRAY accept
    ct mark $MARK_XRAY accept
    meta mark $MARK_INBOUND accept
    ip daddr { 255.255.255.255, 224.0.0.0/4 } accept
    ip6 daddr { ff00::/8, fe80::/10 } accept
    udp sport 68 udp dport 67 accept
    udp sport 546 udp dport 547 accept
    counter drop
  }
}
NFT
}

case "\${1:-}" in
  policy-up)
    # Safe to rerun: the catch-all rule and the unreachable fallback stay in
    # place, so refreshing the bypass rules can only block. Routing comes first:
    # if the firewall fails, the unit fails, Xray is not started and traffic
    # stays blocked instead of leaving directly.
    for f in \$fams; do
      ip \$f route replace unreachable default metric 4096 table $TABLE || exit 1
      # The catch-all is never absent: a correct copy at $((RULE_TUN - 1)) covers the
      # moment its priority is cleaned up.
      if ! rule_is \$f $RULE_TUN "from all lookup $TABLE"; then
        ip \$f rule add lookup $TABLE priority $((RULE_TUN - 1)) || exit 1
        rule_del \$f $RULE_TUN
        ip \$f rule add lookup $TABLE priority $RULE_TUN || exit 1
        rule_del \$f $((RULE_TUN - 1))
      fi
      rule_set \$f $RULE_XRAY uidrange "\$XRAY_UID-\$XRAY_UID" lookup main
      rule_set \$f $RULE_INBOUND fwmark $MARK_INBOUND lookup main
      if [ "\$GATEWAY" = 1 ]; then
        rule_set \$f $RULE_TUNBACK iif "\$TUN_NAME" lookup main
      else
        rule_del \$f $RULE_TUNBACK
      fi
    done
    if [ "\$GATEWAY" = 1 ]; then
      rule_set -4 $RULE_ICMP ipproto icmp lookup main
    else
      rule_del -4 $RULE_ICMP
    fi
    firewall_up || exit 1
    fw_sig >/run/tunx/fw.sig
    ;;
  ensure)
    # Put everything back if another tool changed it (e.g. "nft flush ruleset").
    # Exit 4 if it is still wrong afterwards, so the guard backs off.
    bad=\$(state_errors)
    if [ -n "\$bad" ]; then
      echo "changed:\$bad; restoring"
      exec 9>&-
      "\$0" policy-up
      exec 9>/run/tunx/lock; flock 9
      bad=\$(state_errors)
      if [ -n "\$bad" ]; then echo "still wrong:\$bad"; exit 4; fi
    fi
    ;;
  watch)
    # React to rule, route and nftables changes at once, and check every 10
    # seconds anyway. Exits when a monitor stops; systemd starts it again.
    exec 3< <(nft monitor 2>/dev/null & ip monitor rule route 2>/dev/null & wait)
    while :; do
      "\$0" ensure; [ \$? -ne 4 ] || sleep 10
      read -r -t 10 _ <&3; rc=\$?
      [ \$rc -eq 0 ] || [ \$rc -gt 128 ] || exit 1
      while read -r -t 0.05 _ <&3; do :; done
    done
    ;;
  policy-down)
    for f in \$fams; do
      rule_del \$f $RULE_TUN
      rule_del \$f $RULE_TUNBACK
      rule_del \$f $RULE_INBOUND
      rule_del \$f $RULE_XRAY
      ip \$f route flush table $TABLE 2>/dev/null || true
    done
    rule_del -4 $RULE_ICMP
    nft delete table inet tunx 2>/dev/null || true
    ;;
  tun-up)
    for _ in \$(seq 50); do ip link show "\$TUN_NAME" >/dev/null 2>&1 && break; sleep 0.2; done
    ip link set "\$TUN_NAME" up
    ip addr replace $TUN_ADDR dev "\$TUN_NAME"
    ip route replace default dev "\$TUN_NAME" metric 10 table $TABLE
    # Without IPv6 on the TUN, IPv6 simply stays unreachable.
    if [ "\$fams" != "-4" ]; then
      ip -6 addr replace $TUN_ADDR6 dev "\$TUN_NAME" nodad &&
        ip -6 route replace default dev "\$TUN_NAME" metric 10 table $TABLE || true
    fi
    ;;
  *) echo "usage: \$0 policy-up|policy-down|ensure|watch|tun-up" >&2; exit 2 ;;
esac
EOF
    chmod 755 "$NET_SCRIPT"
}

write_units() {
    cat >"$UNIT_POLICY" <<EOF
[Unit]
Description=Policy routing for Xray TUN (fail closed)
# Install the rules before anything uses the network, so nothing leaves
# directly during boot while Xray is still starting.
DefaultDependencies=no
# After nftables.service: its default config flushes the whole ruleset.
After=local-fs.target nftables.service
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$NET_SCRIPT policy-up
# No ExecStop: stopping the unit (or shutting down) must not open the network.
# Only uninstall removes the rules.

[Install]
WantedBy=multi-user.target
EOF
    cat >"$UNIT_TUN" <<EOF
[Unit]
Description=Xray TUN ($CONFIG)
Requires=tunx-policy.service
After=tunx-policy.service

[Service]
User=$XRAY_USER
Group=$XRAY_USER
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
Environment=XRAY_LOCATION_ASSET=$ASSET_DIR
ExecStart=$BIN run -c $CONFIG
# "+": addresses and routes are set with full privileges.
ExecStartPost=+$NET_SCRIPT tun-up
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    cat >"$UNIT_GUARD" <<EOF
[Unit]
Description=Restore Xray TUN routing and firewall if changed
After=tunx-policy.service

[Service]
ExecStart=$NET_SCRIPT watch
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
}

# wsl_conf_set SECTION KEY VALUE: set a key in /etc/wsl.conf; the original file
# is kept once and restored on uninstall.
wsl_conf_set() {
    install -d "$STATE_DIR"
    touch /etc/wsl.conf
    [ -e "$STATE_DIR/wsl.conf.orig" ] || cp /etc/wsl.conf "$STATE_DIR/wsl.conf.orig"
    if grep -q "^$2" /etc/wsl.conf; then
        sed -i "s/^$2.*/$2=$3/" /etc/wsl.conf
    elif grep -q "^\[$1\]" /etc/wsl.conf; then
        sed -i "/^\[$1\]/a $2=$3" /etc/wsl.conf
    else
        printf '\n[%s]\n%s=%s\n' "$1" "$2" "$3" >>/etc/wsl.conf
    fi
}

setup_dns() {
    install -d "$STATE_DIR"
    if [ ! -e "$STATE_DIR/resolv.conf.orig" ] && [ ! -L "$STATE_DIR/resolv.conf.orig" ]; then
        cp -P /etc/resolv.conf "$STATE_DIR/resolv.conf.orig" 2>/dev/null || true
    fi
    if is_wsl; then wsl_conf_set network generateResolvConf false; fi
    rm -f /etc/resolv.conf
    {
        echo "# Managed by tunx: queries go through $TUN_NAME"
        echo "nameserver 1.1.1.1"
        echo "nameserver 8.8.8.8"
        echo "options edns0 timeout:2 attempts:2"
    } >/etc/resolv.conf
    # Keep NetworkManager from writing the LAN resolver back on reconnect.
    if [ -d /etc/NetworkManager/conf.d ]; then
        printf '[main]\nrc-manager=unmanaged\n' >"$NM_CONF"
        nmcli general reload conf 2>/dev/null || true
    fi
    log "DNS set to 1.1.1.1, 8.8.8.8"
}

restore_dns() {
    if [ -e "$STATE_DIR/resolv.conf.orig" ] || [ -L "$STATE_DIR/resolv.conf.orig" ]; then
        rm -f /etc/resolv.conf
        cp -P "$STATE_DIR/resolv.conf.orig" /etc/resolv.conf
        log "Restored /etc/resolv.conf"
    fi
    if [ -e "$STATE_DIR/wsl.conf.orig" ]; then
        cp "$STATE_DIR/wsl.conf.orig" /etc/wsl.conf
        log "Restored /etc/wsl.conf"
    fi
    if [ -e "$NM_CONF" ]; then
        rm -f "$NM_CONF"
        nmcli general reload conf 2>/dev/null || true
    fi
}

# Gateway mode: forward packets, do not tell clients to bypass this host
# (redirects), accept replies coming out of the TUN (loose reverse path), and
# let inbound connections route by their mark (see firewall_up): the reverse
# path check of their packets and the replies of accepted TCP sockets.
# The previous values are kept and restored on uninstall.
setup_gateway_sysctl() {
    local k
    install -d "$STATE_DIR"
    touch "$STATE_DIR/sysctl.orig"
    for k in net.ipv4.ip_forward net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects \
             net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.conf.all.src_valid_mark net.ipv4.tcp_fwmark_accept; do
        grep -q "^$k=" "$STATE_DIR/sysctl.orig" || echo "$k=$(sysctl -n "$k")" >>"$STATE_DIR/sysctl.orig"
    done
    cat >"$SYSCTL_CONF" <<EOF
# Managed by tunx (gateway mode)
net.ipv4.ip_forward=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.conf.all.src_valid_mark=1
net.ipv4.tcp_fwmark_accept=1
EOF
    sysctl -q -p "$SYSCTL_CONF"
    log "Gateway mode: forwarding enabled"
}

restore_gateway_sysctl() {
    rm -f "$SYSCTL_CONF"
    if [ -e "$STATE_DIR/sysctl.orig" ]; then
        sysctl -q -p "$STATE_DIR/sysctl.orig" && log "Restored forwarding settings"
    fi
}

cmd_install() {
    local config="" version="$XRAY_VERSION_DEFAULT" zip="" via=""
    load_env
    while [ $# -gt 0 ]; do
        case "$1" in
            --config) config="$2"; shift 2 ;;
            --version) version="$2"; shift 2 ;;
            --zip) zip="$2"; shift 2 ;;
            --proxy) via="$2"; shift 2 ;;
            --tun-name) TUN_NAME="$2"; shift 2 ;;
            --gateway) GATEWAY=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) die "unknown option: $1" ;;
        esac
    done
    [[ "$TUN_NAME" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || die "bad --tun-name: $TUN_NAME (1-15 chars: letters, digits, _ . -)"
    check_deps

    install_xray "$version" "$zip" "$via"
    local starter=0
    if [ -n "$config" ]; then
        check_config "$config"
        install -d -m 755 "$CONF_DIR"
        if [ -e "$CONFIG" ] && ! cmp -s "$config" "$CONFIG"; then
            cp -p "$CONFIG" "$CONFIG.bak-$(date +%Y%m%d-%H%M%S)"
            log "Previous config kept as $CONFIG.bak-*"
        fi
        install -m 600 "$config" "$CONFIG"
        log "Installed config from $config"
    elif [ -e "$CONFIG" ]; then
        log "Keeping existing $CONFIG"
        check_config "$CONFIG"
    else
        write_starter_config
        starter=1
    fi
    ensure_user
    protect_config
    write_net_env
    write_net_script
    write_units
    # Older versions ran the guard from a timer.
    if [ -e /etc/systemd/system/tunx-guard.timer ]; then
        systemctl disable --now tunx-guard.timer >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/tunx-guard.timer
    fi

    systemctl daemon-reload
    systemctl stop tunx.service 2>/dev/null || true
    # Not a restart: stopping the policy unit would drop the rules for a moment.
    "$NET_SCRIPT" policy-up
    systemctl enable --now tunx-policy.service tunx.service tunx-guard.service >/dev/null 2>&1
    systemctl restart tunx.service tunx-guard.service
    if [ "$GATEWAY" = 1 ]; then setup_gateway_sysctl; fi
    setup_dns
    if [ "$starter" -eq 1 ]; then
        warn "the starter config has no real upstream yet: public traffic is blocked until you edit $CONFIG and run: sudo $0 reload"
    else
        sleep 1
        cmd_test || warn "some checks failed, see above"
    fi
    log "Done. Uninstall with: sudo $0 uninstall"
    if [ -n "${http_proxy:-}${HTTPS_PROXY:-}${ALL_PROXY:-}" ]; then
        warn "proxy environment variables are still set; with the TUN they are no longer needed"
    fi
}

cmd_tz() {
    local tz cur
    [ -d "$STATE_DIR" ] || die "tunx is not installed (run install first)"
    tz=$(curl -s --max-time 10 https://ipinfo.io/json | python3 -I -c 'import json, sys; print(json.load(sys.stdin).get("timezone", ""))' 2>/dev/null || true)
    [ -n "$tz" ] || tz=$(curl -s --max-time 10 https://ipapi.co/timezone/ || true)
    { [[ "$tz" =~ ^[A-Za-z_]+(/[A-Za-z0-9_+-]+)*$ ]] && [ -e "/usr/share/zoneinfo/$tz" ]; } || die "cannot get the egress time zone (got: ${tz:-nothing})"
    cur=$(timedatectl show -p Timezone --value 2>/dev/null || true)
    [ -e "$STATE_DIR/timezone.orig" ] || echo "${cur:-UTC}" >"$STATE_DIR/timezone.orig"
    # Otherwise WSL resets the time zone to the Windows one at every start.
    if is_wsl; then wsl_conf_set time useWindowsTimezone false; fi
    timedatectl set-timezone "$tz"
    # Debian-based systems also keep the name here; Java and tzlocal read it first.
    if [ -e /etc/timezone ]; then echo "$tz" >/etc/timezone; fi
    log "Time zone set to $tz (was ${cur:-unknown})"
}

cmd_check() {
    load_env
    [ -x "$BIN" ] || die "Xray is not installed (run install first)"
    check_config "$CONFIG"
    log "$CONFIG is OK"
}

cmd_reload() {
    cmd_check
    systemctl restart tunx.service
    sleep 1
    systemctl is-active --quiet tunx.service || die "tunx failed to start: journalctl -u tunx"
    log "Reloaded"
}

cmd_uninstall() {
    # The guard first, or it would put the rules back.
    systemctl disable --now tunx-guard.service >/dev/null 2>&1 || true
    systemctl disable --now tunx.service tunx-policy.service >/dev/null 2>&1 || true
    if [ -x "$NET_SCRIPT" ]; then "$NET_SCRIPT" policy-down 2>/dev/null || true; fi
    if [ -e "$CONFIG" ]; then
        local saved
        saved="/root/tunx-config-$(date +%Y%m%d-%H%M%S).json"
        install -m 600 "$CONFIG" "$saved"
        log "Config saved to $saved"
    fi
    rm -f "$UNIT_TUN" "$UNIT_POLICY" "$UNIT_GUARD" "$NET_SCRIPT" "$BIN"
    rm -rf "$ASSET_DIR" "$CONF_DIR"
    systemctl daemon-reload
    restore_gateway_sysctl
    restore_dns
    if [ -e "$STATE_DIR/timezone.orig" ]; then
        local tz
        tz=$(cat "$STATE_DIR/timezone.orig")
        timedatectl set-timezone "$tz" && log "Restored time zone $tz"
        if [ -e /etc/timezone ]; then echo "$tz" >/etc/timezone; fi
    fi
    rm -rf "$STATE_DIR"
    userdel "$XRAY_USER" 2>/dev/null || true
    log "Removed. Traffic now uses the normal route."
}

cmd_status() {
    load_env
    systemctl --no-pager --lines=5 status tunx.service 2>/dev/null | sed -n '1,5p' || true
    echo "Guard: $(systemctl is-active tunx-guard.service 2>/dev/null)"
    echo
    echo "Rules:"; ip rule show | grep -E "^($RULE_XRAY|$RULE_INBOUND|$RULE_ICMP|$RULE_TUNBACK|$RULE_TUN):" || echo "  (none)"
    if [ "${GATEWAY:-0}" = 1 ]; then echo "Gateway: on (ip_forward=$(sysctl -n net.ipv4.ip_forward))"; fi
    echo "Table $TABLE:"; ip route show table $TABLE 2>/dev/null || true
    echo "IPv6 table $TABLE:"; ip -6 route show table $TABLE 2>/dev/null || true
    echo "Interface:"; ip -br addr show "$TUN_NAME" 2>/dev/null || echo "  $TUN_NAME missing"
    echo "Firewall:"; nft list table inet tunx 2>/dev/null | awk '/counter/ {printf "  dropped %s packets\n", $(NF-3)}' | tail -1 || true
    echo "DNS:"; grep '^nameserver' /etc/resolv.conf || true
}

cmd_test() {
    local fail=0 noenv=(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY)
    local tcp dns udp
    tcp=$("${noenv[@]}" curl -s --max-time 10 https://1.1.1.1/cdn-cgi/trace | awk -F= '/^ip=/{print $2}' || true)
    echo "TCP egress : ${tcp:-FAIL}"; [ -n "$tcp" ] || fail=1
    if command -v dig >/dev/null; then
        dns=$(dig +short +time=4 +tries=1 txt ch whoami.cloudflare @1.1.1.1 | tr -d '"' || true)
        echo "DNS egress : ${dns:-FAIL}"; [ -n "$dns" ] || fail=1
        # Informational: a repeated lookup is answered from the cache when DNS is hijacked.
        local q
        dig +short +time=4 +tries=1 www.example.com >/dev/null 2>&1 || true
        q=$(dig +noall +stats +time=4 +tries=1 www.example.com 2>/dev/null | awk '/Query time/ {print $4 " ms"}' || true)
        echo "DNS repeat : ${q:-FAIL}"
    else
        echo "DNS egress : skipped (install dnsutils for dig)"
    fi
    if command -v python3 >/dev/null; then
        udp=$(python3 -I - <<'EOF' 2>/dev/null
import os, socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
s.sendto(struct.pack("!HHI", 1, 0, 0x2112A442) + os.urandom(12), ("stun.cloudflare.com", 3478))
d, _ = s.recvfrom(2048); i = 20
while i < len(d):
    t, l = struct.unpack("!HH", d[i:i+4]); v = d[i+4:i+4+l]
    if t == 0x20:
        print(socket.inet_ntoa(bytes(a ^ b for a, b in zip(v[4:8], struct.pack("!I", 0x2112A442))))); break
    i += 4 + l + (-l % 4)
EOF
)
        echo "UDP (STUN) : ${udp:-FAIL}"; [ -n "$udp" ] || fail=1
    fi
    # Informational: IPv6 works only if the upstream has IPv6.
    local v6
    v6=$("${noenv[@]}" curl -s -6 --max-time 8 'https://[2606:4700:4700::1111]/cdn-cgi/trace' | awk -F= '/^ip=/{print $2}' || true)
    echo "IPv6       : ${v6:-none}"
    # Other programs must not get around the TUN by binding to the physical
    # interface: the firewall drops the packet and sendto fails with EPERM.
    local dev bind
    dev=$(ip -4 route show table main default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i+1); exit}}')
    if [ -n "$dev" ]; then
        bind=$(python3 -I - "$dev" <<'EOF' 2>/dev/null || true
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, sys.argv[1].encode())
    s.sendto(b"x", ("192.0.2.1", 9))
except PermissionError:
    print("blocked")
else:
    print("LEAK")
EOF
)
        echo "Bind $dev  : ${bind:-FAIL}"; [ "$bind" = "blocked" ] || fail=1
    fi
    local x
    for x in "${dns:-}" "${udp:-}"; do
        if [ -n "$tcp" ] && [ -n "$x" ] && [ "$x" != "$tcp" ]; then
            warn "egress addresses differ ($tcp vs $x)"; fail=1
        fi
    done
    return $fail
}

main() {
    local cmd="${1:-}"; shift || true
    case "$cmd" in
        install) need_root; cmd_install "$@" ;;
        reload) need_root; cmd_reload ;;
        check) need_root; cmd_check ;;
        uninstall) need_root; cmd_uninstall ;;
        status) cmd_status ;;
        test) cmd_test ;;
        tz) need_root; cmd_tz ;;
        -h | --help | help | "") usage ;;
        *) usage; exit 2 ;;
    esac
}

# Tests source this file for its functions.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
