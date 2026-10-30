# tunxd

`tunxd` is the node daemon. It accepts and dials link sessions
(`internal/link`), captures traffic from a TUN device (`internal/netstack`),
routes every flow by destination prefix (`internal/route`), checks the access
policy (`internal/policy`) and either forwards the flow over a link or
delivers it on this host (`internal/egress`). It can enrol with tunx-hub and
poll and partially apply rendered configuration without restarting.

## Commands

```
tunxd keygen                 print a new key pair (JSON: private_key, public_key)
tunxd check -c config.json   validate a config, print the public key and the TUN setup
tunxd run -c config.json [-pull-interval 30s -hub-dir DIR]
tunxd enroll -hub URL -token-file FILE [-dir DIR]
tunxd pull [-dir DIR]
```

`run` logs JSON lines (slog) to stderr. On SIGTERM it stops accepting and
dialing, closes all sessions and flows, and exits 0.

Build: `go build -o tunxd ./cmd/tunxd`.

`enroll` exchanges a one-time hub token, writes `node.key`, `hub.json`,
`tunxd.json` and `xray.json` with mode 0600, then pulls the first bundle.
The token file may be `-` to read stdin. Plain HTTP is accepted only for a
loopback hub. `pull` sends the saved ETag and leaves the files untouched on
304; a changed bundle is validated before its two config files are replaced.
The node token and private key are never printed.

With `-pull-interval`, `run` keeps serving the last good configuration when
the hub is unavailable. Changes to routes, policy, groups and hop limit are
applied to new flows without closing existing flows or link sessions. The
new Xray file is written but not reloaded. Changes to identity, keys, TUN,
addresses, peers, listeners, link timers, status or logging are kept on disk
and logged as requiring a restart.

## How a flow is handled

1. **Ingress.** A flow captured from the TUN gets `Identity` = this node's
   name and `Hops` = 0. A flow from a link keeps the identity the peer
   claims, which must be the peer's own name or match the peer's
   `relay_for`, and must not be this node's own name; otherwise it is closed
   (`spoofed`).
2. **Hop limit.** A flow is refused when it arrived with more hops than
   `hop_limit`, or when forwarding it would exceed `hop_limit`.
3. **Route.** Longest prefix match on the destination. The advertisers of
   that prefix are tried in priority order:
   - this node: deliver locally (with the advertiser's `source`,
     `interface`, `mark`);
   - a peer with a session up: open the flow on that session;
   - otherwise the advertiser's `via` peers that are up, in order (`"*"`:
     every peer, by peer `priority`).
   A flow is never sent back over the link it arrived on. When the longest
   match has no reachable advertiser the flow is refused (`no_route`); a
   shorter prefix is never used as a fallback, so a site whose exit is down
   is cut off rather than sent elsewhere. For TCP, `no_route`, `unreachable`
   and `hop_limit` from a live peer also try the next candidate; policy
   denials, destination resets and generic errors remain terminal.
4. **Policy.** The access policy is checked at the ingress node (flows from
   the TUN) and at the delivering node. Relays only do the identity check of
   step 1.
5. **Data.** The flow is opened on the next hop with `Hops + 1` and spliced
   both ways: TCP keeps half-close, UDP and ICMP keep message boundaries.

A TCP connection from the TUN is completed only after the delivering node
has connected to the destination: each hop answers the flow open with OK or
a refusal reason (protocol version 2, see `docs/protocol.md`). The client
gets an RST when the destination refused the connection (`refused`); every
other refusal (`denied`, `no_route`, `hop_limit`, unreachable, error) is
silent, so the SYN goes unanswered and the client times out, as through a
firewall that drops. UDP and ping do not wait for the answer. A relay
accepts upstream when its next-hop stream opens; that hop-local acceptance
does not confirm delivery. A downstream refusal closes the flow, but its
reason may not propagate after acceptance. A refused ping gets no reply. Nothing is faked: no
ICMP errors are generated.

When an advertiser's session ends (closed, or no transport bytes received for
`keepalive_timeout`), new flows move to the next advertiser at once. Flows
that were open on the dead session end.

## Config reference

JSON; `//` and `/* */` comments are allowed, unknown fields are errors. See
`examples/` for a hub and two site gateways.

| Field | Meaning |
|:--|:--|
| `node` | This node's name, 1–64 bytes, no whitespace or `*?[]@/\` |
| `network` | Network ID; both ends of a link must agree |
| `private_key` | Base64 ed25519 seed (32 bytes) or key (64 bytes) |
| `private_key_file` | File holding the key instead, relative to the config |
| `addresses` | Overlay addresses of this node; each gets a local host route |
| `tun.name` | TUN device to create (needs `CAP_NET_ADMIN`) |
| `tun.mtu` | MTU used by the capture stack; set the same on the device |
| `tun.addresses`, `tun.capture` | Addresses and routes the operator configures (printed by `check`) |
| `listen[].address` | Where link connections are accepted, normally the target of the local Xray inbound |
| `peers[].name`, `public_key` | A node this node links with |
| `peers[].dial` | Address to dial (normally a local Xray inbound wired to the peer); empty: the peer dials us |
| `peers[].interface`, `mark` | `SO_BINDTODEVICE` / `SO_MARK` on the dialing socket |
| `peers[].congestion`, `listen[].congestion` | TCP congestion control of the link socket (`bbr`, `cubic`, ...; default: the system's). Use it when tunxd's own link socket crosses the lossy path; behind Xray set `sockopt.tcpcongestion` in Xray instead. BBR must already be available on the test host |
| `peers[].priority` | Order for `via: ["*"]`, lower first |
| `peers[].relay_for` | Identities (patterns or `@group`) this peer may carry besides its own name |
| `routes[].prefix` | Destination prefix, without host bits |
| `routes[].advertisers[]` | `node`, `priority` (lower first), `via` (peers that relay to `node`); for this node also `source` (`snat` or `preserve`), `interface`, `mark` |
| `groups` | Named lists of identity patterns, referenced as `@name` |
| `policy[]` | Rules: `action` (`allow`/`deny`), `identity`, `src`, `dst`, `proto` (`tcp`, `udp`, `icmp`, `any`), `ports` (`22`, `"8000-8999"`). Empty fields match anything; first match wins; no match denies |
| `hop_limit` | Maximum links a flow may cross, default 8 |
| `link` | `handshake_timeout`, `keepalive_interval`, `keepalive_timeout` (`"5s"`); `stream_buffer`: per-flow window in bytes (default 4 MiB, about 200 Mbit/s for one flow at 80 ms RTT; smaller bounds how much one bulk flow queues ahead of others on a slow link) |
| `status` | Loopback address of the status endpoint; empty disables it |
| `log_level` | `debug`, `info` (default), `warn`, `error` |
| `client_socks` | Authenticated loopback SOCKS5 ingress: `listen`, and `users[]` with `name` and `password`. TCP CONNECT is injected with the username as its policy identity; UDP ASSOCIATE is not yet supported |

Identity patterns use shell glob syntax (`site-*`).

## Status endpoint

`GET http://<status>/status` returns JSON:

- `sessions`: peer, whether this node dialed it, since when, smoothed RTT;
- `routes`: prefix, advertisers, and the current choice (`local`,
  `peer:<name>`, or empty when unreachable);
- `stats`: flows and bytes per identity and per peer (`tx` toward the
  destination for an identity, toward the peer for a peer), and refused flows
  by reason (`no_route`, `denied`, `hop_limit`, `spoofed`, `open_failed`,
  `deliver_failed`, and `refused`: the next hop answered the open with a
  refusal).

## Host setup

tunxd creates the TUN device but does not configure the host. `tunxd check`
prints the commands for the `tun` section, for example on site A:

```
ip link set dev tunx0 mtu 1400
ip addr add 10.200.0.2/24 dev tunx0
ip addr add fd74:756e:7800::2/64 dev tunx0
ip link set dev tunx0 up
ip -4 route replace 10.0.2.0/24 dev tunx0
```

Run them after tunxd has created the device (or create it first with
`ip tuntap add dev tunx0 mode tun` and let tunxd attach). Further:

- A gateway forwards LAN traffic into the TUN:
  `sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1`, and the
  site router sends the remote prefixes to the gateway.
- Ping delivery uses unprivileged ping sockets:
  `sysctl -w net.ipv4.ping_group_range="0 2147483647"` (or a range that
  contains tunxd's group).
- `source: preserve` needs `CAP_NET_ADMIN`, the site router must route the
  remote source prefixes back to the gateway, and replies addressed to those
  non-local sources must reach tunxd's transparent sockets instead of being
  routed into the TUN:

  ```
  table ip tunx {
    chain pre {
      type filter hook prerouting priority mangle; policy accept;
      socket transparent 1 meta mark set 0x7478
      iifname != "tunx0" ip daddr { 10.0.1.0/24 } icmp type echo-reply meta mark set 0x7478
    }
  }
  ```

  ```
  ip rule add fwmark 0x7478 lookup 7478
  ip route add local 0.0.0.0/0 dev lo table 7478
  ```

  and the same for IPv6 (`table ip6`, `ip6 daddr`, `icmpv6 type
  echo-reply`, `ip -6`). The `socket` match covers TCP and UDP. It does not
  find ping sockets, so echo replies addressed to the preserved sources (the
  remote prefixes in the set) need the second rule. Verified in the
  scenarios (`tests/sim/scenarios/tunxd-*.yaml`) include negative TCP, UDP
  and ping checks without this table; remote verification is pending.
- Lossy uplinks: all flows to a peer share one TCP connection. Congestion
  control and the stream window affect throughput and queued latency.
  `tunxd-bench` compares CUBIC and BBR with concurrent ping under load. On
  the pve-test loss profile, CUBIC became unusable at 1–3% loss; configure
  BBR for such links when the host provides it. Focused BBR runs completed
  all 18 samples for both plain and Reality links: about 115 Mbit/s at 1%
  loss and 56–66 Mbit/s at 3% loss. These are test-VM observations, not
  capacity guarantees for other networks.
- Link traffic must not enter the TUN: dial through the local Xray, or bind
  the peer's dialing socket with `interface` / `mark` and policy routing.

## Testing

`go test -race ./...` runs without root: `internal/forward` starts several
nodes in one process, linked over loopback TCP, with the TUN of a node
replaced by a gVisor channel endpoint, and covers TCP, UDP and ping across a
link, the reverse direction, a relay, policy, identity spoofing, advertiser
failover, the hop limit and open answers. Tests that need root use the
build tag `tunxroot`.

End to end, `tests/sim/run-tunxd.sh` builds tunxd and runs the scenarios
`tunxd-plain` (plain TCP links) and `tunxd-xray` (links through Xray, VLESS
+ Reality across a censor) in a disposable VM with network namespaces: TUN
setup, both directions between two sites, IPv6, `source: preserve`, open
answers, link sockets kept out of the TUN, an unprivileged node pinging
through ping sockets, failover and recovery, link cuts during a flow,
SIGTERM. A separate benchmark covers throughput and latency at 0, 1 and
3% loss. The current changes passed 88/88 plain and 94/94 Xray scenario
steps on pve-test. See `tests/sim/README.md`.
