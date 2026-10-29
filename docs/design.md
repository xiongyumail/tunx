# tunx virtual network: design

## Goal

tunx is a general overlay network. Xray carries the links, so a link can use
VLESS + Reality, TLS, plain VLESS or SOCKS and survives censorship. tunx itself
handles addressing, routing, policy, ICMP and source addresses. A controller
manages nodes, links, policies and traffic from a web panel.

No topology is built in. Hub and spoke, full mesh, several hubs and multi-hop
relays are all configurations of the same model.

## Architecture

```
┌─ tunx-hub (controller, may be more than one) ┐
│ API + web panel + SQLite                      │
│ computes routes, renders node configs,        │
│ collects stats, sends alerts                  │
└──────────────▲────────────────────────────────┘
               │ control channel (over the overlay or direct)
┌─ node ───────┴────────────────────────────────┐
│ tunxd: TUN captures TCP / UDP / ICMP (gVisor) │
│   route table → local / a link / an exit /    │
│   local Xray (domain rules)                   │
│   policy, stats, DNS                          │
│ Xray: link transport only                     │
└───────────────────────────────────────────────┘
standard clients (phones): connect to a node's Xray inbound, identified by
the Xray user, handed to tunxd
```

Nodes keep the last config they received. When the controller is down the
network keeps working; only changes wait.

### Why tunxd forwards traffic itself

Generating Xray configs alone (reverse portal/bridge, routing by user) cannot
carry ICMP, cannot carry the original source across hops (the VLESS header has
only the destination), and makes multi-hop routing and failover a pile of
special cases. tunxd uses Xray as a pipe and does the network layer itself.

## Data model

| Object | Contents |
|:--|:--|
| Network | Overlay prefixes (IPv4, IPv6 ULA), DNS suffix |
| Node | Identity key, overlay addresses, tags. Capabilities instead of fixed roles: listen, relay, advertise prefixes, act as exit |
| Link | Two nodes and which one dials; transport stack (Reality, TLS, plain VLESS, SOCKS, XHTTP, chained through another link); bind interface; cost and priority; mux or one connection per flow |
| Route | Prefix → advertising nodes, with priority or balancing. The default route is an exit |
| Egress policy | Which exit a source uses for the internet, optionally by domain, geo or prefix |
| Access policy | Source (identity, group, tag) → destination (prefix, node, tag, port, protocol) → allow or deny. Default deny |
| Client | A device without tunxd, attached to a listening node, exported as a share link or subscription |
| Prefix mapping | Maps an overlapping site prefix to another prefix |

Everything exports to and imports from YAML. The panel, CLI and API edit the
same data.

## Data plane

**Link session.** One transport connection between two tunxd, normally
through Xray: the dialing side connects to a local Xray inbound that is wired
to the peer; the peer's Xray hands the connection to its tunxd. A session
starts with mutual authentication by node key, then becomes a multiplexed
session where either side opens streams. Reverse access needs nothing extra.

**Streams.** Each stream starts with a header that carries `core.FlowMeta`:
protocol, original source, destination, identity, hop count.

- TCP: the ingress node terminates TCP, so there is no TCP over TCP.
- UDP: one stream per 5-tuple, messages framed with a length.
- ICMP: echo requests and replies as messages; the exit sends real echoes.
- Control: keepalive, RTT and loss probes, route updates.

**Forwarding.** A relay looks up the destination and passes the stream to the
next hop with `Hops` incremented. The last hop delivers it:

- `snat`: dial from its own address. Needs nothing from the site.
- `preserve`: dial with `IP_TRANSPARENT` from the original source. The site
  router must route the source prefix back to this node.

ICMP echo is sent with a ping socket. Nothing on the overlay answers ICMP
locally; a destination that is unreachable or denied gets no reply, like TCP.

**Policy.** Checked at the ingress node and again at the delivering node.
Relays check that the claimed identity may arrive over that link, which stops
spoofing.

**Failure.** Keepalive timeout triggers reconnect with backoff. A pair of
nodes may have several links with automatic failover; when an advertising
node drops, its prefixes move to the next advertiser. Target: recover within
30 seconds.

**Loss.** With a mux, a lost packet stalls other streams on the same
connection. A link can instead open one connection per flow, or keep several
connections in parallel.

## Control plane and panel

- `tunx-hub`: one Go binary with SQLite, a REST API and a Vue + Ant Design Vue
  panel.
- Pages: overview (topology, status, traffic), nodes, links, routes and
  exits, policies, clients and subscriptions, DNS, settings (alerts by
  webhook), audit log.
- Enrolment: the panel prints a one-time install command; the node registers
  and then pulls its config.
- Distribution: the hub renders each node's tunxd and Xray config and pushes
  it over a long-lived connection; nodes reload without dropping flows.
- Security: two-factor login; credentials generated by the hub and rotatable;
  every policy change in the audit log.

## Compatibility and layout

The existing client and gateway modes of `install.sh` stay as they are.

```
cmd/tunxd        node daemon
cmd/tunx-hub     controller and panel
internal/core    shared types: FlowMeta, Flow, Handler
internal/link    link session: handshake, mux, stream header, keepalive
internal/netstack TUN capture with gVisor
internal/route   route table and forwarder
internal/policy  access and egress policy
internal/config  node config
web/             panel
tests/sim        network namespace simulation
docs/
```

MIT license. gVisor is Apache-2.0; Xray runs as a separate process.

## Milestones

| | Content | Acceptance (simulation) |
|:--|:--|:--|
| M0 | This document, link protocol spec, simulation framework (topology YAML → namespaces + netem) | Any topology comes up from YAML |
| M1 | tunxd data plane: two nodes, one link (plain VLESS, then Reality), TCP / UDP / ICMP, prefix advertisement | TCP, UDP and real ping across sites; reverse access |
| M2 | Routing: many nodes, relays, multi-hop, advertiser failover, exits, access policy, source preservation | 3-hop topology; any link cut recovers within 30 s; policy enforced |
| M3 | Controller: API, distribution, stats, CLI, YAML import/export | One change reloads the whole network |
| M4 | Panel | The scenarios below done from the web only |
| M5 | Standard clients and subscriptions, overlay DNS, prefix mapping | A phone joins by subscription; overlapping prefixes connect |
| M6 | Real deployment | Scenarios below on real sites |

CI runs the simulation for every milestone and records throughput and latency
at 0%, 1% and 3% loss.

## Reference scenario

Two sites, A and B, each with a gateway node in front of its LAN; one hub with
a public address; a remote exit node; a terminal node at site A; a phone.

| Scenario | Pass |
|:--|:--|
| Terminal at A reaches a host on B's LAN | TCP, UDP and ping work; B sees the terminal's real address |
| Hosts on B reach A | Allowed or denied by policy |
| Phone over Reality reaches both LANs | Works |
| Terminal's internet traffic | Leaves through the remote exit; with the hub down it is cut, never sent direct |
| B's link | Uses only its designated interface, over Reality |
| Hub opens a connection to the terminal's overlay address | Works |
