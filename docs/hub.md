# tunx-hub

`tunx-hub` is the controller. It keeps the whole network in SQLite, serves a
REST API, and renders for every node its tunxd config and its Xray config.
Nodes keep the last config they pulled, so the network keeps working while
the hub is down. This version has no web panel yet and does not push
configs; nodes pull them.

## Commands

```
tunx-hub init [-network NAME] [-admin NAME] [-password-file FILE]
tunx-hub serve [-listen 127.0.0.1:8780] [-tls-cert F -tls-key F] [-insecure-cookie]
tunx-hub render NODE          print a node's rendered configs (JSON)
tunx-hub import FILE          replace the network with a YAML file ("-": stdin)
tunx-hub export FILE          write the network as YAML ("-": stdout)
tunx-hub token NAME           create an API token, printed once
tunx-hub enroll-token NODE    create a one-time enrolment token, valid 24 h
```

Every command takes `-db FILE` (default `tunx-hub.db`); flags go before
arguments. `init` reads the administrator password (12 characters or more)
from `-password-file` or the first line of stdin and prints the TOTP secret
and `otpauth://` URI once. `serve` binds to loopback by default; on another
address use `-tls-cert`/`-tls-key` or a TLS proxy. The session cookie is
`Secure` unless `-insecure-cookie` is given.

## Concepts

| Object | Key fields |
|:--|:--|
| network | `name` (network ID), `prefixes` (overlay, IPv4 and IPv6), `dns_suffix`, `hop_limit` |
| node | `name`, `public_key`, `addresses`, `tags`, `capabilities` (`listen`, `relay`, `advertise`, `exit`), `endpoints`, `proxies`, `tun`, `link_listen`, `client_listen`, `dial_port_base`, `status`, `log_level` |
| endpoint (in a node) | `name`, `transport` (`reality`, `tls`, `vless`, `socks`), `address`/`port` dialed by others, `listen`, `network` (`raw` or `xhttp`) and `path`, `reality` or `tls` settings, `clients` (accepts standard clients) |
| link | `name`, `dialer`, `listener`, `endpoint` (of the listener), `cost` (default 10), `priority`, `interface`/`mark` (dialer's socket), `dialer_proxy` (a proxy of the dialer), `disabled`, generated `uuid` and `short_id` |
| route | `name`, `prefix`, `advertisers` (`node`, `priority`, `source` `snat`/`preserve`, `interface`, `mark`) |
| access policy | `name`, `priority`, `action`, `sources`, `source_prefixes`, `destinations`, `proto`, `ports` |
| egress policy | `name`, `priority`, `sources`, `exit`, `xray_rules` (opaque Xray routing rules) |
| client | `name`, `node`, `endpoint`, `tags`, `disabled`, generated `uuid`, `short_id`, `password` |
| group | `name`, `members` (identity selectors, no nested groups) |

Node and client names are identities and share one namespace.

**Selectors.** Sources and group members are `node:NAME`, `client:NAME`,
`tag:TAG`, `group:NAME` (not in groups) or a glob such as `site-*`.
Destinations are prefixes, addresses, `node:NAME` or `tag:TAG` (the nodes'
overlay addresses). An empty list matches anything; a selector that selects
nothing (a tag nobody has) drops the rule instead of matching anything.

**Ordering.** Access and egress policies are evaluated by `priority`, then
name; first match wins, no match denies. Everything else is ordered by name.

**Validation.** Every change is applied to a copy of the whole network and
checked (names, references, capabilities, prefixes, transports) before it is
stored, in one transaction. Advertisers need `advertise`, or `exit` for a
default route; endpoints need `listen`; only `relay` nodes forward flows of
others. Plain `vless` endpoints must have a private address (private IP, or
a `.lan`, `.local`, `.internal`, `.home.arpa` name): current Xray refuses
unencrypted VLESS to anything else.

## Keys and credentials

- **Node keys.** The hub generates the ed25519 key pair at enrolment and
  returns the private key once; only the public key is stored. The rendered
  tunxd config names `private_key_file: node.key`, which the node writes
  next to its config. Enrolling again (new one-time token) rotates the key
  and the node's config token. A node without a public key is not enrolled:
  it is left out of every other node's config.
- **Generated secrets.** REALITY private keys of endpoints, link and client
  UUIDs, short IDs and client SOCKS passwords are generated when empty and
  then kept: a later import or `PUT` that leaves them empty keeps the stored
  value. Set a new value explicitly to rotate one. They appear in exports
  and API reads (admin only) and are redacted in the audit log.
- **Admins.** Password (argon2id) plus TOTP (SHA-1, 6 digits, 30 s, ±1 step,
  each step usable once). Five failed logins lock a username for a minute.
  Sessions last 12 h; the cookie is `HttpOnly`, `SameSite=Strict`.
- **Tokens.** API tokens (`tunx_at_…`) act as an admin; node tokens
  (`tunx_nt_…`) read only their node's config; enrolment tokens
  (`tunx_et_…`) are one-time. Only SHA-256 hashes are stored.

## Rendering

`render.Node` is deterministic: the same network gives the same bytes, and
`revision` (also the `ETag` of the config endpoint) changes exactly when the
content changes. The rendered tunxd config is checked with
`internal/config` validation before it is returned.

**Paths.** The link graph has the enrolled nodes and their enabled links,
weighted by `cost`. A flow may pass through a node only if it is a relay.
For each advertiser of a route, a node gets: the advertiser directly when
they share a link, and as `via` every relaying neighbor whose shortest path
to the advertiser avoids this node, cheapest first. Advertisers are ordered
by route `priority`, then path cost; unreachable ones are left out. Every
node also gets a host route to every other node's addresses.

**Default routes.** An egress policy sends the internet traffic of its
sources to its exit: a node gets `0.0.0.0/0` and `::/0` toward the exits of
the policies matching it or its clients, and a relay toward every exit. The
exit delivers them itself. When no exit is reachable the flow is refused,
never sent directly. Relays route by destination only, so two sources with
different exits that share a relay are separated by priority at the relay.

**Peers.** One link per pair of nodes is used by tunxd (lowest priority,
then cost, then name); others are rendered in Xray and reported as standby.
The dialer's peer gets `dial` = a loopback Xray port (`dial_port_base`,
default 10800, plus the index of the link among the node's dialed links).
`relay_for` of a peer lists the clients attached to it and, for a relay,
every node (and their clients) it reaches without this node.

**Policy.** A node gets the access rules that can apply where it checks
policy: rules whose sources match an identity entering at this node (itself
and its clients), or whose destinations overlap what it delivers (its
addresses, its advertised prefixes, the default route on an exit). Dropping
the other rules does not change any first-match result there.

**TUN.** `tun.addresses` are the node's addresses with the overlay prefix
length; `tun.capture` lists the remote non-overlay prefixes it routes
(default routes are not captured: that needs host policy routing so Xray's
own traffic stays out of the TUN).

### Xray wiring

```
dialer node                                  listener node
tunxd ──► 127.0.0.1:10800 "dial-<link>"      "in-<endpoint>" :443 ──► "tunxd" freedom
          tunnel inbound                     VLESS user email "link:<link>"   redirect 127.0.0.1:7700
          └► "link-<link>" outbound ───────►  (REALITY / TLS / plain, or SOCKS
             VLESS user <link uuid>,          account "link-<link>")
             sockopt interface/mark/dialerProxy
```

- The dialer's outbound user ID is the link's UUID, which is a user of the
  listener's endpoint with email `link:<link>`; REALITY short IDs are per
  link and per client; the client-side `password` is the endpoint's public
  key. Raw REALITY and TLS use the Vision flow; XHTTP uses none.
- The listener routes link users to the `tunxd` outbound (freedom with
  `redirect` to `link_listen`), so the destination a dialer asks for does not
  matter. Anything else arriving on an endpoint is blocked.
- `dialer_proxy` chains a link through one of the dialer's `proxies` (an
  opaque Xray outbound, tagged `proxy-<name>`) with `sockopt.dialerProxy`.
- Outbounds `block` (first, the default) and `direct` always exist; egress
  `xray_rules` may use them.

### Standard clients

A phone connects to a `clients: true` endpoint with its own VLESS user
(email `client:<name>`). Its traffic carries arbitrary destinations, which
tunxd must receive with the client's identity. The listening node's Xray
routes each client user to its own SOCKS outbound `client-<name>` that
connects to tunxd's local SOCKS server (`client_listen`, default
127.0.0.1:7701) with username = client name and the client's generated
password. tunxd authenticates the account, takes the identity from the
username and the destination from the SOCKS request (CONNECT for TCP, UDP
ASSOCIATE for UDP), and handles the flow as if it entered from the TUN with
that identity. The accounts are rendered in the bundle's `client_socks`
section. Egress `xray_rules` of policies that match a client are applied to
its traffic before this hand-over. `GET /api/clients/{name}/share` returns
the `vless://` share link.

### What tunxd must add

1. **Config pull.** Enrol once (`POST /api/enroll`, write `node.key`, keep
   the node token), then poll `GET /api/nodes/{name}/config` with
   `If-None-Match: "<revision>"`; on 200 write the tunxd and Xray configs,
   restart or reload Xray, reload tunxd. Keep the last config when the hub is
   unreachable.
2. **Reload.** Apply a new config without dropping flows: swap the route
   table and policy (route tables are already swapped atomically), add and
   remove peers and listeners, keep sessions to unchanged peers.
3. **Client identity.** A `client_socks` section (`listen`, `users[]` with
   `name` and `password`): a SOCKS5 server with username/password auth,
   CONNECT and UDP ASSOCIATE, that injects flows with `Identity` = the
   username and `Hops` = 0. Until then the section lives beside the tunxd
   config in the bundle.
4. Optional: several `dial` addresses per peer, to use standby links.

## REST API

JSON bodies and responses; errors are `{"error": "…"}`. Admin endpoints
accept a session cookie (state-changing requests also need the header
`X-Tunx-CSRF: 1`) or `Authorization: Bearer tunx_at_…`.

| Method and path | Auth | Purpose |
|:--|:--|:--|
| `POST /api/login` | none | `{"username","password","totp"}` → session cookie |
| `POST /api/logout`, `GET /api/me` | admin | end session; who am I |
| `GET`/`PUT /api/network` | admin | network settings |
| `GET /api/{kind}` | admin | list; kinds: `nodes`, `links`, `routes`, `access`, `egress`, `clients`, `groups` |
| `POST /api/{kind}` | admin | create (409 if the name exists) |
| `GET`/`PUT`/`DELETE /api/{kind}/{name}` | admin | read, replace, delete |
| `GET /api/export`, `POST /api/import` | admin | whole network as YAML; import replaces it, idempotent, all or nothing |
| `GET /api/audit?limit=N` | admin | audit log, newest first |
| `GET`/`POST /api/tokens`, `DELETE /api/tokens/{name}` | admin | API tokens (`{"name"}` → token, shown once) |
| `POST /api/nodes/{name}/enroll-token` | admin | one-time enrolment token |
| `POST /api/enroll` | enrolment token | `{"token"}` → `node`, `network`, `private_key`, `public_key`, `node_token`, `config_path`, `key_file` |
| `GET /api/nodes/{name}/config` | that node's token or admin | rendered bundle; `ETag`, `If-None-Match` → 304 |
| `GET /api/clients/{name}/share` | admin | `vless://` share link |
| `GET /api/health` | none | `{"ok": true}` |

Writes return `{"changes": [{"action","kind","name"}], "object": …}`. A
change that would make the network invalid returns 400 and changes nothing.
Every change is in the audit log: actor (`admin:<user>`, `token:<name>`,
`enroll:<node>`, `cli`), time, action, object, and the changed fields with
secrets redacted. Logins, failed logins and token creation are logged too.

The bundle:

```json
{
  "node": "site-a",
  "revision": "33e5813…",
  "tunxd": { "node": "site-a", "private_key_file": "node.key", "peers": […], "routes": […], "policy": […] },
  "xray": { "inbounds": […], "outbounds": […], "routing": {…} },
  "client_socks": { "listen": "127.0.0.1:7701", "users": [{"name": "phone", "password": "…"}] },
  "warnings": ["link \"b-hub\": node \"site-b\" is not enrolled; link skipped"]
}
```

## Example network

`examples/network.yaml` is a complete network: a public hub, two site
gateways dialing it over REALITY (site B bound to `eth1`), a remote exit the
hub dials over REALITY + XHTTP, and a phone on the hub. Abridged:

```yaml
network:
  name: example
  prefixes: [10.200.0.0/24, fd74:756e:7800::/64]
groups:
  - {name: sites, members: [tag:site]}
nodes:
  - name: hub
    addresses: [10.200.0.1, fd74:756e:7800::1]
    tags: [core]
    capabilities: [listen, relay]
    endpoints:
      - name: reality
        transport: reality
        address: hub.example.com
        port: 443
        reality: {target: www.example.com:443, server_names: [www.example.com]}
        clients: true
  - name: exit
    addresses: [10.200.0.4]
    capabilities: [listen, exit]
    endpoints:
      - {name: main, transport: reality, address: exit.example.net, port: 443, network: xhttp, path: /tx,
         reality: {target: www.example.org:443, server_names: [www.example.org]}}
  - {name: site-a, addresses: [10.200.0.2], tags: [site], capabilities: [advertise], tun: {name: tunx0, mtu: 1400}}
  - {name: site-b, addresses: [10.200.0.3], tags: [site], capabilities: [advertise], tun: {name: tunx0, mtu: 1400}}
links:
  - {name: a-hub, dialer: site-a, listener: hub, endpoint: reality}
  - {name: b-hub, dialer: site-b, listener: hub, endpoint: reality, interface: eth1}
  - {name: hub-exit, dialer: hub, listener: exit, endpoint: main, cost: 20}
routes:
  - {name: site-a-lan, prefix: 10.0.1.0/24, advertisers: [{node: site-a, source: preserve}]}
  - {name: site-b-lan, prefix: 10.0.2.0/24, advertisers: [{node: site-b}]}
access:
  - {name: core-any, priority: 10, action: allow, sources: [tag:core]}
  - {name: a-to-b, priority: 20, action: allow, sources: [node:site-a], destinations: [10.0.2.0/24]}
  - {name: b-to-a-ssh, priority: 30, action: allow, sources: [node:site-b], destinations: [10.0.1.0/24], proto: [tcp], ports: [22]}
  - {name: phone-lans, priority: 40, action: allow, sources: [client:phone], destinations: [10.0.1.0/24, 10.0.2.0/24]}
  - {name: no-other-private, priority: 60, action: deny, destinations: [10.0.0.0/8, fd74:756e:7800::/64]}
  - {name: internet, priority: 70, action: allow, sources: [group:sites, client:phone]}
egress:
  - name: via-exit
    priority: 10
    sources: [group:sites, client:phone]
    exit: exit
    xray_rules: [{domain: ["domain:ads.example.org"], outboundTag: block}]
clients:
  - {name: phone, node: hub, endpoint: reality}
```

Rendered output for each node of the full example is in
`internal/hub/render/testdata/`.

## Testing

`go test -race ./internal/hub/... ./cmd/tunx-hub/...` covers migrations,
transactional and idempotent import, audit redaction, enrolment, login with
TOTP and replay, tokens and CSRF, CRUD, YAML round trip, path computation
with relays and priorities, and golden renders of the example. Rendered
tunxd configs are loaded with `internal/config`; rendered Xray configs are
checked with `xray run -test` when `xray` is on `PATH`.
