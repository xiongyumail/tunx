# tunx

Send all traffic of WSL2 (or any Linux with systemd) into an Xray TUN, and let your own Xray config decide where it goes: outbound proxies, split rules, and LAN direct are all written in the Xray config. Programs that ignore proxy variables, UDP, and DNS are all covered.

The script handles only the infrastructure: installing Xray, the TUN and policy routing (cut off rather than leak when it fails), DNS, systemd services, and restoring everything on uninstall. Once a config exists, it is never overwritten.

```bash
git clone https://github.com/xiongyumail/tunx.git
cd tunx
cp examples/vless-reality.jsonc my.jsonc     # fill in your upstream
sudo ./install.sh install --config my.jsonc
```

Without `--config`, a first install writes a starter config to `/etc/tunx/config.json`. Until you fill in the upstream, public traffic is blocked and only the LAN works. After editing, run `sudo ./install.sh reload`.

After installing, the script checks the egress once. The first three addresses should be identical and equal to the proxy's exit IP. The IPv6 line shows the exit's IPv6 address, or `none` if the upstream has no IPv6. The last line confirms that other programs cannot get around the TUN by binding to the physical interface:

```
TCP egress : 203.0.113.7
DNS egress : 203.0.113.7
DNS repeat : 0 ms
UDP (STUN) : 203.0.113.7
IPv6       : 2001:db8::7
Bind eth0  : blocked
```

## Commands

| Command | Purpose |
|:--|:--|
| `sudo ./install.sh install [--config FILE]` | Install or update Xray, routing, DNS, and services, then start |
| `sudo ./install.sh reload` | Check `/etc/tunx/config.json`, then restart Xray. Nothing is restarted if the check fails |
| `sudo ./install.sh check` | Only check the config |
| `sudo ./install.sh uninstall` | Remove all files, restore `resolv.conf` and `wsl.conf`; the config is backed up to `/root/tunx-config-*.json` |
| `./install.sh status` | Service, routing rules, and DNS status |
| `./install.sh test` | Check the egress address for TCP, DNS, UDP (STUN), and IPv6 |
| `sudo ./install.sh tz` | Optional: set the system time zone to that of the egress IP (looked up at ipinfo.io through the TUN). It also updates `/etc/timezone` where it exists (read first by Java and tzlocal). On WSL it also writes `useWindowsTimezone=false`, otherwise WSL resets it at every start. Uninstall restores both; rerun after changing the exit |

Install options:

| Option | Default | Description |
|:--|:--|:--|
| `--config FILE` | none | Xray config to install; checked first, the old config is kept as `config.json.bak-*` |
| `--version TAG` | `v26.10.21` | Xray version |
| `--zip PATH` | none | Offline install from a local `Xray-linux-*.zip` |
| `--proxy URL` | none | Proxy used only to download Xray, e.g. `socks5h://192.168.1.10:1080` |
| `--tun-name NAME` | `tunx0` | TUN interface name, at most 15 characters; must match `name` in the config |

Reinstalling with the same version skips the download.

## Config requirements

`check` and `reload` verify these items:

- Exactly one `tun` inbound, with `name` equal to `--tun-name` (default `tunx0`).
- Do not set `autoSystemRoutingTable` on the TUN inbound; routes are managed by the script.
- **Upstream as a hostname**: it cannot be resolved through the upstream itself. List it in the `domains` of a DNS server queried directly (`https://223.5.5.5/dns-query` with `skipFallback: true` in the examples), and route that server's address with `inboundTag: dns-internal` to the `direct` outbound. When the config has a `dns` outbound, `check` fails if an upstream hostname is not listed. See `examples/`.
- To split by domain, enable `sniffing` on the TUN inbound (`routeOnly: true`), then add `domain` rules.

Examples:

- `examples/vless-reality.jsonc`: a VLESS + Reality upstream; the fields map to a 3x-ui share link.
- `examples/socks-split.jsonc`: two SOCKS5 upstreams, `geosite:cn` direct, specific domains to the second upstream.

## How it works

- Xray creates a TUN interface (default `tunx0`). All traffic on the system, including LAN traffic, goes through it to Xray, and Xray's routing rules decide the outbound.
- There are three policy routing rules in the kernel:
  - `8991`: connections of the `tunx` system user, which Xray runs as, use the original routing table. This is how Xray's own connections avoid the TUN; it works even if the upstream address is a changing public IP (DDNS), and it follows the default route when the network changes.
  - `8995`: replies to connections opened from outside through a physical interface (e.g. Windows connecting to a server in WSL) use the original routing table, so they leave the way the request came in. These connections are marked with conntrack. Connections this host opens to on-link addresses, such as the Windows host, go through the TUN and leave through Xray's `direct` outbound.
  - `9100`: everything else looks up routing table 100, whose default route points to the TUN.
- An nftables table `inet tunx` drops packets leaving a physical interface unless they come from the `tunx` user, reply to an inbound connection, or are broadcast, multicast, link-local or DHCP. Routing alone is not enough: when a program binds its socket to the physical interface and the lookup fails, the kernel sends the packet out as if the destination were on-link. With the table in place, binding to the interface gets a permission error instead, and an unprivileged user cannot take another user's identity. `test` checks this (`Bind eth0 : blocked`).
- IPv4 and IPv6 get the same rules. The TUN has `198.18.0.1/30` and `fdfe:dcba:9876::1/126`, so IPv6 also enters Xray and is carried inside the upstream connection; this works even when the host itself has no IPv6. Programs with Happy Eyeballs (curl, browsers) may pick IPv6 for dual-stack hosts; both families leave through the same upstream.
- The routing rules are installed by `tunx-policy.service` before the network is up (`Before=network-pre.target`), so nothing leaves directly during boot while Xray is still starting. A reinstall refreshes them in place instead of removing and re-adding them.
- Table 100 has an `unreachable` fallback. If Xray dies, traffic is cut off instead of falling back to a direct connection and leaking; systemd restarts Xray after 2 seconds. During that time the LAN and the host are unreachable too; replies to inbound connections still work.
- `/etc/resolv.conf` is changed to `1.1.1.1` and `8.8.8.8`, and DNS queries also go out through the TUN. On WSL the script also writes `generateResolvConf=false` to `/etc/wsl.conf` so a restart does not change it back. With NetworkManager, it writes `rc-manager=unmanaged` so a reconnect does not put the LAN resolver back (a LAN resolver is a private address and would be reached directly).
- DNS cache (starter config and examples): traffic to port 53 is routed to a `dns` outbound. A and AAAA queries are answered by Xray's built-in DNS, which caches answers and queries DoH (`1.1.1.1`, `8.8.8.8`) through the proxy over a kept-alive connection; other query types are forwarded through the proxy unchanged. `serveStale` returns an expired answer at once and refreshes it in the background. Without the cache, every lookup opens a new connection through the upstream; with it, a repeated lookup takes about 0 ms and a new one about one round trip. Port 53 traffic to private addresses still goes direct, so `dig @<router>` reaches the router. For a few seconds after Xray starts, lookups can time out while the first DoH connection is set up.
- Xray is downloaded from GitHub Releases and its SHA-256 is verified. If downloads are slow or the TUN is down, use `--proxy` or `--zip`.

## Requirements

- systemd. On WSL, set `[boot] systemd=true` in `/etc/wsl.conf`.
- `curl`, `unzip`, `iproute2`, `nftables`, `python3`; the `test` command also uses `dig` (`dnsutils`).
- x86_64 or arm64.

## Installed files

| Path | Contents |
|:--|:--|
| `/usr/local/bin/xray`, `/usr/local/share/xray/` | Xray and geo data |
| `/etc/tunx/config.json` (mode 640, group `tunx`) | Your Xray config |
| `/etc/tunx/net.env` | TUN interface name, uid of the `tunx` user |
| `/usr/local/sbin/tunx-net` | Policy routing script |
| `tunx-policy.service`, `tunx.service` | Routing rules (oneshot) and the Xray service (runs as user `tunx` with `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`) |
| user `tunx` | System user for Xray; removed on uninstall |
| nftables table `inet tunx` | Firewall described above; loaded by `tunx-policy.service`, removed on uninstall |
| `/var/lib/tunx/` | Backups of the original `resolv.conf`, `wsl.conf` and time zone, restored on uninstall |
| `/etc/NetworkManager/conf.d/90-tunx.conf` | Only with NetworkManager; removed on uninstall |

## Notes

- Existing `http_proxy`-style environment variables and APT/Git proxy settings are left alone. Once the TUN is working they can be removed; the script warns if it finds proxy environment variables still set.
- Tested on WSL2.
- Only traffic of this Linux host (or WSL distribution) is covered. On WSL, Windows programs, including ones started from WSL, use the Windows network.
- Whether IPv6 reaches the internet depends on the upstream's exit. If it has no IPv6, IPv6 connections fail and programs fall back to IPv4; nothing leaves directly either way.
- Xray's TUN inbound is a fairly new feature; verify on your machine before changing versions.

## License

MIT
