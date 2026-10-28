#!/usr/bin/env bash
# Integration test in a KVM VM: install tunx with --gateway on Debian 13, then
# check the VM's own egress and a LAN client that uses it as its gateway.
#
#   runner: bridge tunxbr0 10.99.0.1/24, NAT to the internet,
#           SOCKS5 upstream on 10.99.0.1:1080 (Xray, freedom out, access log)
#   VM:     10.99.0.12, tunx --gateway, examples/gateway.jsonc -> 10.99.0.1:1080
#   client: network namespace, 10.99.0.20, default via 10.99.0.12
#
# Needs root, KVM, qemu-system-x86, qemu-utils, genisoimage, curl, dig, python3.
# It changes the host network (bridge, tap, netns, NAT): run it only on a
# throwaway machine such as a CI runner. Logs end up in $TUNX_VM_LOGS.
# shellcheck disable=SC2016 # commands in single quotes run in the VM
set -euo pipefail
cd "$(dirname "$0")/.."
repo=$PWD
work=$(mktemp -d)
logs=${TUNX_VM_LOGS:-$work/logs}
mkdir -p "$logs"

IMAGE_URL=https://cloud.debian.org/images/cloud/trixie/latest
IMAGE=debian-13-genericcloud-amd64.qcow2
BR=tunxbr0
HOST_IP=10.99.0.1
VM_IP=10.99.0.12
CLIENT_IP=10.99.0.20
FAR_IP=10.98.0.1
NS=tunxclient

pass=0
ok() { echo "ok: $*"; pass=$((pass + 1)); }
fail() {
    echo "FAIL: $*" >&2
    if [ -s "$work/socks-access.log" ]; then
        echo "-- upstream access log (last lines):" >&2; tail -n 8 "$work/socks-access.log" >&2
    fi
    exit 1
}
step() { echo; echo "== $*"; }

cleanup() {
    set +e
    [ -f "$work/qemu.pid" ] && kill "$(cat "$work/qemu.pid")" 2>/dev/null
    [ -f "$work/socks.pid" ] && kill "$(cat "$work/socks.pid")" 2>/dev/null
    cp "$work/console.log" "$work/socks-access.log" "$logs/" 2>/dev/null
    chmod -R a+rX "$logs"
    ip netns del $NS 2>/dev/null
    rm -rf /etc/netns/$NS
    ip link del tunxtap0 2>/dev/null
    ip link del tunxc0 2>/dev/null
    ip link del $BR 2>/dev/null
    rm -rf "$work"
}
trap cleanup EXIT

vm() { ssh -i "$work/key" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "tester@$VM_IP" "$@"; }
client() { ip netns exec $NS "$@"; }
wait_ssh() {
    local _
    for _ in $(seq "${1:-60}"); do vm true 2>/dev/null && return 0; sleep 3; done
    return 1
}
# Upstream access log: log_mark before a request, then log_has MARK PATTERN.
log_mark() { wc -l <"$work/socks-access.log"; }
log_has() {
    local since
    sleep 1
    since=$(tail -n +"$(($1 + 1))" "$work/socks-access.log")
    grep -q -- "$2" <<<"$since"
}

step "Host network"
ip link add $BR type bridge
ip addr add $HOST_IP/24 dev $BR
# Off the client's subnet, so a ping to it is forwarded by the gateway (CI
# runners drop ICMP to the internet).
ip addr add $FAR_IP/32 dev $BR
ip link set $BR up
ip tuntap add tunxtap0 mode tap
ip link set tunxtap0 master $BR up
ip netns add $NS
ip link add tunxc0 type veth peer name tunxc1
ip link set tunxc0 master $BR up
ip link set tunxc1 netns $NS
ip -n $NS addr add $CLIENT_IP/24 dev tunxc1
ip -n $NS link set tunxc1 up
ip -n $NS link set lo up
ip -n $NS route add default via $VM_IP
# The client's resolver does not exist: only the gateway's DNS hijack answers it.
mkdir -p /etc/netns/$NS
echo "nameserver 192.0.2.53" >/etc/netns/$NS/resolv.conf
sysctl -q -w net.ipv4.ip_forward=1
# Docker on CI runners sets the FORWARD policy to DROP.
iptables -I FORWARD -i $BR -j ACCEPT
iptables -I FORWARD -o $BR -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.99.0.0/24 ! -o $BR -j MASQUERADE

step "Upstream SOCKS5 on $HOST_IP:1080"
# shellcheck source-path=SCRIPTDIR/..
. ./install.sh
BIN=$work/bin/xray
ASSET_DIR=$work/share
mkdir -p "$work/bin"
install_xray "$XRAY_VERSION_DEFAULT" "" ""
touch "$work/socks-access.log"
cat >"$work/socks.json" <<EOF
{
  "log": { "loglevel": "warning", "access": "$work/socks-access.log" },
  "inbounds": [ { "listen": "$HOST_IP", "port": 1080, "protocol": "socks",
                  "settings": { "udp": true, "ip": "$HOST_IP" } } ],
  "outbounds": [ { "protocol": "freedom" } ]
}
EOF
XRAY_LOCATION_ASSET=$ASSET_DIR "$BIN" run -c "$work/socks.json" >"$logs/socks.log" 2>&1 &
echo $! >"$work/socks.pid"

step "VM"
curl -fsSL -o "$work/SHA512SUMS" "$IMAGE_URL/SHA512SUMS"
curl -fsSL -o "$work/$IMAGE" "$IMAGE_URL/$IMAGE"
(cd "$work" && grep " $IMAGE\$" SHA512SUMS | sha512sum -c - >/dev/null) || fail "image checksum"
qemu-img create -q -f qcow2 -F qcow2 -b "$work/$IMAGE" "$work/vm.qcow2" 8G
ssh-keygen -q -t ed25519 -N "" -f "$work/key"
mkdir -p "$work/seed"
printf 'instance-id: tunx-ci\nlocal-hostname: tunx-ci\n' >"$work/seed/meta-data"
cat >"$work/seed/network-config" <<EOF
version: 2
ethernets:
  lan:
    match: { name: "en*" }
    addresses: [ $VM_IP/24 ]
    routes: [ { to: default, via: $HOST_IP } ]
    nameservers: { addresses: [ 1.1.1.1 ] }
EOF
cat >"$work/seed/user-data" <<EOF
#cloud-config
users:
  - name: tester
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    ssh_authorized_keys: [ "$(cat "$work/key.pub")" ]
packages: [ curl, unzip, nftables, python3, bind9-dnsutils ]
EOF
genisoimage -quiet -output "$work/seed.iso" -volid cidata -joliet -rock \
    "$work/seed/user-data" "$work/seed/meta-data" "$work/seed/network-config"
qemu-system-x86_64 -enable-kvm -cpu host -m 1024 -smp 2 \
    -drive file="$work/vm.qcow2",if=virtio -drive file="$work/seed.iso",media=cdrom \
    -netdev tap,id=n0,ifname=tunxtap0,script=no,downscript=no -device virtio-net-pci,netdev=n0 \
    -display none -serial file:"$work/console.log" -daemonize -pidfile "$work/qemu.pid"
wait_ssh 100 || fail "VM did not come up (console log in $logs)"
# status --wait exits non-zero on mere warnings; what matters is the packages.
vm 'cloud-init status --wait >/dev/null || true; dpkg -s curl unzip nftables python3 bind9-dnsutils >/dev/null' ||
    { vm 'cloud-init status --long' || true; fail "cloud-init packages"; }
ok "VM up"

step "Install tunx --gateway"
sed "s/192\.168\.1\.10/$HOST_IP/" examples/gateway.jsonc >"$work/gateway.jsonc"
scp -q -i "$work/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    "$repo/install.sh" "$work/gateway.jsonc" "tester@$VM_IP:"
vm 'sudo bash ~/install.sh install --gateway --config ~/gateway.jsonc' >"$logs/install.log" 2>&1 ||
    { cat "$logs/install.log"; fail "install"; }
ok "install"

step "VM's own traffic (install.sh test)"
vm 'bash ~/install.sh test' | tee "$logs/test.log" || fail "install.sh test"
ok "egress checks"

step "Client through the gateway"
mark=$(log_mark)
client curl -fsS -m 15 -o /dev/null http://example.com/ || fail "client HTTP via the gateway"
log_has "$mark" "from tcp:$VM_IP:[0-9]* accepted tcp:.*:80\$" || fail "client HTTP did not use the upstream"
ok "client TCP goes through the upstream"

# 192.0.2.53 does not exist: an answer can only come from the hijacked DNS.
ans=$(client dig +short +time=5 +tries=2 @192.0.2.53 example.com A | tr "\n" " ")
[ -n "$ans" ] || fail "DNS through the gateway is not answered"
aaaa=$(client dig +short +time=5 +tries=2 @192.0.2.53 example.com AAAA)
[ -z "$aaaa" ] || fail "gateway config should return no AAAA records, got $aaaa"
ok "client DNS hijacked, IPv4 only ($ans)"

mark=$(log_mark)
udp=$(client python3 -I - <<'EOF'
import os, socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(struct.pack("!HHI", 1, 0, 0x2112A442) + os.urandom(12), ("stun.cloudflare.com", 3478))
d, _ = s.recvfrom(2048); i = 20
while i < len(d):
    t, l = struct.unpack("!HH", d[i:i+4]); v = d[i+4:i+4+l]
    if t == 0x20:
        print(socket.inet_ntoa(bytes(a ^ b for a, b in zip(v[4:8], struct.pack("!I", 0x2112A442))))); break
    i += 4 + l + (-l % 4)
EOF
)
[ -n "$udp" ] || fail "client UDP (STUN)"
log_has "$mark" "from udp:$VM_IP:[0-9]* accepted udp:.*:3478\$" || fail "client UDP did not use the upstream"
ok "client UDP goes through the upstream ($udp)"

# geoip:cn goes direct from the VM, not through the upstream.
mark=$(log_mark)
client curl -ksS -m 15 -o /dev/null https://223.5.5.5/ || fail "client direct route (223.5.5.5)"
! log_has "$mark" "223\.5\.5\.5" || fail "geoip:cn traffic went through the upstream"
ok "client geoip:cn goes direct"

client ping -c 2 -W 3 $HOST_IP >/dev/null || fail "client ping to the LAN"
client ping -c 2 -W 3 $FAR_IP >/dev/null || fail "client ping through the gateway"
ok "client ICMP"

step "Fail closed"
vm 'sudo systemctl stop tunx.service'
if client curl -s -m 5 -o /dev/null http://example.com/ || client curl -ks -m 5 -o /dev/null https://223.5.5.5/; then
    fail "client reached the internet while Xray was stopped"
fi
ok "client cut off while Xray is stopped"
vm true || fail "new SSH connection to the VM while Xray is stopped"
ok "VM reachable over SSH while Xray is stopped"
vm 'sudo systemctl start tunx.service'
sleep 3
client curl -fsS -m 15 -o /dev/null http://example.com/ || fail "client after restart"
ok "client back after start"

vm 'sudo pkill -9 -x xray'
sleep 5
client curl -fsS -m 15 -o /dev/null http://example.com/ || fail "client after kill -9"
ok "Xray restarted after kill -9"

step "Guard"
vm 'sudo nft flush ruleset; sudo ip rule del priority 8997; sudo ip rule del priority 8996'
sleep 3
vm 'sudo nft list chain inet tunx gateway >/dev/null && ip rule | grep -q "^8997:" && ip rule | grep -q "^8996:"' ||
    fail "guard did not restore the firewall and rules"
client curl -fsS -m 15 -o /dev/null http://example.com/ || fail "client after restore"
ok "guard restores firewall and gateway rules"

step "Reboot"
vm 'sudo systemctl reboot' || true
sleep 10
wait_ssh 60 || fail "VM did not come back after reboot"
sleep 3
client curl -fsS -m 15 -o /dev/null http://example.com/ || fail "client after reboot"
vm '[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ]' || fail "forwarding off after reboot"
ok "works after reboot"

step "Uninstall"
vm 'sudo bash ~/install.sh uninstall' >"$logs/uninstall.log" 2>&1 || fail "uninstall"
vm '[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ] && ! ip rule | grep -qE "^(8991|8995|8996|8997|9100):" &&
    ! sudo nft list table inet tunx >/dev/null 2>&1 && [ ! -e /etc/sysctl.d/90-tunx-gateway.conf ]' ||
    fail "uninstall left state behind"
vm 'curl -fsS -m 15 -o /dev/null https://example.com/' || fail "VM has no direct network after uninstall"
ok "uninstall restores the VM"

echo
echo "All $pass checks passed."
