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
| `--gateway` | off | Gateway mode, see below. Kept on later installs until uninstall |

Reinstalling with the same version skips the download.

## Gateway mode

With `--gateway`, the host also serves LAN clients that use it as their default gateway (e.g. a small VM on the LAN). Their TCP and UDP traffic enters the TUN and follows the same Xray routing; the host's own traffic is handled as before.

```bash
sudo ./install.sh install --gateway --config examples/gateway.jsonc
```

On a client, set the gateway to this host. For DNS, either point it at this host too (`examples/gateway.jsonc` listens on port 53; turn off the systemd-resolved stub first with `DNSStubListener=no` in `/etc/systemd/resolved.conf.d/`), or at any public address (e.g. `223.5.5.5`): port 53 traffic passing through is answered by Xray's built-in DNS. Another DNS server on the LAN is reached directly, not through the gateway. `examples/gateway.jsonc` returns only IPv4 addresses, because clients usually get IPv6 routes from the router and IPv6 would bypass the gateway.

What changes in this mode:

- Only connections addressed to the host itself are marked as inbound. Forwarded connections are not, so they go to table 100 and the TUN.
- Rule `8997` sends packets that Xray writes back for clients (coming in on the TUN) to the main table, so they leave through the LAN interface.
- Rule `8996` sends ICMP to the main table: the TUN carries only TCP and UDP, so a client's ping goes to the router as is.
- The firewall gets a `gateway` chain on the forward hook that only lets traffic into or out of the TUN, plus ICMP. If Xray is down, clients are cut off instead of being forwarded directly.
- `/etc/sysctl.d/90-tunx-gateway.conf` turns on forwarding, turns off ICMP redirects (they would tell clients to bypass the host), sets loose reverse path filtering, and lets inbound connections route by their mark (`src_valid_mark`, `tcp_fwmark_accept`). The last two keep the host reachable over SSH while Xray is down. Uninstall removes the file and restores the previous values.

## Config requirements

`check` and `reload` verify these items:

- Exactly one `tun` inbound, with `name` equal to `--tun-name` (default `tunx0`).
- Do not set `autoSystemRoutingTable` on the TUN inbound; routes are managed by the script.
- **Upstream as a hostname**: it cannot be resolved through the upstream itself. List it in the `domains` of a DNS server queried directly (`https://223.5.5.5/dns-query` with `skipFallback: true` in the examples), and route that server's address with `inboundTag: dns-internal` to the `direct` outbound. When the config has a `dns` outbound, `check` fails if an upstream hostname is not listed. See `examples/`.
- **DNS rule order**: with a `dns` outbound, a rule sending port 53 to it must exist and come before any IP rule or catch-all (e.g. the private-address `direct` rule or `geoip:cn`), otherwise DNS sent to those addresses leaves without the built-in DNS. `check` fails if not; install and reload stop before changing anything.
- To split by domain, enable `sniffing` on the TUN inbound (`routeOnly: true`), then add `domain` rules.

Examples:

- `examples/vless-reality.jsonc`: a VLESS + Reality upstream; the fields map to a 3x-ui share link.
- `examples/socks-split.jsonc`: two SOCKS5 upstreams, `geosite:cn` direct, specific domains to the second upstream.
- `examples/gateway.jsonc`: for gateway mode; a SOCKS5 upstream on the LAN, mainland China direct, IPv4-only DNS answers.

## How it works

- Xray creates a TUN interface (default `tunx0`). All traffic on the system, including LAN traffic, goes through it to Xray, and Xray's routing rules decide the outbound.
- There are three policy routing rules in the kernel:
  - `8991`: connections of the `tunx` system user, which Xray runs as, use the original routing table. This is how Xray's own connections avoid the TUN; it works even if the upstream address is a changing public IP (DDNS), and it follows the default route when the network changes.
  - `8995`: replies to connections opened from outside through a physical interface (e.g. Windows connecting to a server in WSL) use the original routing table, so they leave the way the request came in. These connections are marked with conntrack. Connections this host opens to on-link addresses, such as the Windows host, go through the TUN and leave through Xray's `direct` outbound.
  - `9100`: everything else looks up routing table 100, whose default route points to the TUN.
- An nftables table `inet tunx` drops packets leaving a physical interface unless they belong to a connection opened by the `tunx` user (tracked with a conntrack mark, so the data, FIN and RST the kernel still sends after Xray closes a socket get out), reply to an inbound connection, or are broadcast, multicast, link-local or DHCP. Routing alone is not enough: when a program binds its socket to the physical interface and the lookup fails, the kernel sends the packet out as if the destination were on-link. With the table in place, binding to the interface gets a permission error instead, and an unprivileged user cannot take another user's identity. `test` checks this (`Bind eth0 : blocked`).
- IPv4 and IPv6 get the same rules (IPv6 only if the kernel has it). The TUN has `198.18.0.1/30` and `fdfe:dcba:9876::1/126`, so IPv6 also enters Xray and is carried inside the upstream connection; this works even when the host itself has no IPv6. Programs with Happy Eyeballs (curl, browsers) may pick IPv6 for dual-stack hosts; both families leave through the same upstream.
- The routing rules are installed by `tunx-policy.service` before the network is up (`Before=network-pre.target`), so nothing leaves directly during boot while Xray is still starting. A reinstall refreshes them in place instead of removing and re-adding them. Stopping `tunx-policy.service` (which also stops Xray, so traffic is blocked) or shutting down leaves them in place; only `uninstall` removes them. If the firewall cannot be loaded, the unit fails after the routing rules are in place, so Xray does not start and traffic stays blocked. `tunx-guard.service` watches routing and nftables changes (`ip monitor`, `nft monitor`) and also checks every 10 seconds. It compares the rule content, the fallback route and the whole firewall table with what was installed, and puts them back within about half a second if another tool removed or changed them (e.g. `nft flush ruleset`, a flushed chain, an added accept rule, a widened `uidrange`); its journal records each restore.
- Table 100 has an `unreachable` fallback. If Xray dies, traffic is cut off instead of falling back to a direct connection and leaking; systemd restarts Xray after 2 seconds. During that time the LAN and the host are unreachable too; replies to inbound connections still work.
- `/etc/resolv.conf` is changed to `1.1.1.1` and `8.8.8.8`, and DNS queries also go out through the TUN. On WSL the script also writes `generateResolvConf=false` to `/etc/wsl.conf` so a restart does not change it back. With NetworkManager, it writes `rc-manager=unmanaged` so a reconnect does not put the LAN resolver back (a LAN resolver is a private address and would be reached directly).
- DNS cache (starter config and examples): traffic to port 53 is routed to a `dns` outbound. A and AAAA queries are answered by Xray's built-in DNS, which caches answers and queries DoH (`1.1.1.1`, `8.8.8.8`) through the proxy over a kept-alive connection; other query types are forwarded through the proxy unchanged. `serveStale` returns an expired answer at once and refreshes it in the background. Without the cache, every lookup opens a new connection through the upstream; with it, a repeated lookup takes about 0 ms and a new one about one round trip. Port 53 traffic to private addresses is answered the same way, so resolvers handed out by DHCP (used by systemd-resolved or NetworkManager on desktop Linux) do not leak queries; `dig @<router>` is answered by Xray, not the router. On WSL, DNS to `10.255.255.254` (WSL's own resolver, reached over `lo` and forwarded by Windows) is dropped by the firewall. For a few seconds after Xray starts, lookups can time out while the first DoH connection is set up.
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
| `tunx-guard.service` | Restores the rules and the firewall if they are removed or changed |
| `/var/lib/tunx/` | Backups of the original `resolv.conf`, `wsl.conf` and time zone, restored on uninstall |
| `/etc/NetworkManager/conf.d/90-tunx.conf` | Only with NetworkManager; removed on uninstall |

## Notes

- Existing `http_proxy`-style environment variables and APT/Git proxy settings are left alone. Once the TUN is working they can be removed; the script warns if it finds proxy environment variables still set.
- Tested on WSL2, and in gateway mode on a Debian 13 VM.
- Without `--gateway`, only traffic of this Linux host (or WSL distribution) is covered. On WSL, Windows programs, including ones started from WSL, use the Windows network.
- Whether IPv6 reaches the internet depends on the upstream's exit. If it has no IPv6, IPv6 connections fail and programs fall back to IPv4; nothing leaves directly either way.
- Xray's TUN inbound is a fairly new feature; verify on your machine before changing versions.

## Tests

- `sudo tests/static.sh`: shell syntax and ShellCheck, and the generated policy script and nftables ruleset for the normal, WSL and gateway modes (`nft -c`, nothing is loaded).
- `tests/config.sh`: downloads Xray into a temp dir, checks the examples and the starter config, and checks that broken configs are rejected.

- `sudo tests/vm.sh`: installs tunx with `--gateway` in a Debian 13 KVM VM, with a SOCKS5 upstream on the host and a client in a network namespace. It checks the VM's own egress, that the client's TCP, UDP and DNS go through the gateway and mainland China addresses go direct, that the client is cut off while Xray is stopped (and the VM still answers SSH), recovery after `kill -9`, the guard restoring flushed rules, reboot, and uninstall. It changes the host network, so run it only on a throwaway machine.

The first two run in GitHub Actions on every push, the VM test when `install.sh`, the examples or the test change.

## License

MIT
