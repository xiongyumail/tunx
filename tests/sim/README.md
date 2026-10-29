# Network simulation (tests/sim)

Brings up an arbitrary network topology from a YAML file with Linux network
namespaces, runs scenarios against it and tears it down. Used to test the
overlay across simulated sites, routers, NAT, lossy WAN links and a
censoring firewall.

Each **segment** is an L2 switch: a Linux bridge inside its own namespace.
Each **node** is a namespace whose interfaces are veth pairs plugged into
segments. Nothing is created in the host namespace, and every namespace name
starts with a prefix, so several topologies can run side by side.

```
ts-sw-lan-a (bridge br0)          ts-term-a           ts-router-a
  term-a-eth0 ─────── veth ─────── eth0                 lan0 ── ...
  router-a-lan0 ───── veth ───────────────────────────── lan0
```

## Requirements

Run as root on a disposable Linux VM (Debian 13 tested target) with:

```
apt install iproute2 nftables python3 python3-yaml iperf3 tcpdump ethtool
```

`ethtool` is optional; without it TSO/GSO stay on and netem loss applies to
64 KB super-packets instead of single packets, which distorts loss tests.

Only `plan`, `status`, `--dry-run` and `test_sim.py` work without root.

## Quick start

```
cd tests/sim
python3 test_sim.py                                   # self-test, no root
python3 sim.py plan topologies/two-sites.yaml         # print every command

sudo python3 sim.py up topologies/two-sites.yaml
sudo python3 sim.py exec topologies/two-sites.yaml term-a -- ping -c3 203.0.113.10
sudo python3 sim.py exec topologies/two-sites.yaml gw-b           # a shell inside gw-b
sudo python3 sim.py netem topologies/two-sites.yaml --segment mobile loss 3%
sudo python3 sim.py link topologies/two-sites.yaml router-b wan0 down
sudo python3 sim.py status topologies/two-sites.yaml
sudo python3 sim.py down topologies/two-sites.yaml

# Fresh up, scenario, down; results as JSON:
sudo python3 sim.py run topologies/two-sites.yaml scenarios/smoke.yaml \
     --set mobile_loss=1% --results /tmp/smoke-1pct.json
```

## Commands

| Command | What it does |
|:--|:--|
| `plan TOPO [--phase up\|down\|all]` | Print the commands `up` and `down` run. No root. |
| `up TOPO [--force]` | Build the topology. If the same topology is already fully up it is a no-op; otherwise leftovers of the prefix are removed first and everything is rebuilt. |
| `down TOPO` / `down --prefix P` | Kill all processes in the namespaces, then delete every namespace that starts with `P-`. Works after a failed or partial `up`, and when nothing is up. Logs and results stay. |
| `status TOPO` | Which namespaces exist, process counts, current netem settings. Exit 0 when fully up. |
| `exec TOPO NODE [-- CMD...]` | Run a command (default `$SHELL`) inside a node. |
| `netem TOPO NODE IF [--dir out\|in\|both] PARAMS...` | Change netem on one interface. `out` = traffic leaving the node (default), `in` = traffic towards the node. |
| `netem TOPO --segment SEG PARAMS...` | Change netem on every port of a segment (traffic towards each attached node). |
| `link TOPO NODE IF up\|down [--admin]` | Cut or restore a link. Default pulls the cable at the switch port (the node sees no carrier, keeps its config). `--admin` sets the node's own interface down; `up --admin` restores its addresses and routes. |
| `run TOPO SCENARIO [--keep] [--no-up] [--results F]` | `up --force`, run the scenario, `down`. `--keep` leaves it up; `--no-up` uses the running topology. Exit 1 if any step failed. |

Common options: `--set NAME=VALUE` overrides a variable (topology or
scenario), `--prefix P` overrides the namespace prefix (or `SIM_PREFIX`),
`--rundir D` the run directory (or `SIM_RUNDIR`). Global: `-n/--dry-run`
prints commands instead of running them, `-v` echoes each command.

netem `PARAMS` are key/value pairs (`loss 3%`, `delay 40ms jitter 5ms`,
`loss=1%`). Changes merge with the current settings of that qdisc; `loss off`
removes one key, `reset` returns to the topology file, `clear` removes netem.

## Run directory

Default `/run/tunx-sim/<prefix>/`:

```
state.json             topology fingerprint, vars, current netem (exists only while up)
logs/<node>.log        stdout/stderr of the node's start commands and scenario background steps
logs/<node>.iperf3.log iperf3 servers started by measure steps
nodes/<node>/          working directory of the node: generated files, sim-rules.nft, pid files
results/<scenario>.json
```

All namespaces share the host filesystem; give daemons paths under
`${node.dir}` so nodes do not collide.

## Topology YAML

```yaml
name: two-sites          # default: file name
prefix: ts               # namespace prefix, 1-8 [a-z0-9]; default from name
rundir: /run/tunx-sim/ts # default /run/tunx-sim/<prefix>
offload: false           # true keeps TSO/GSO/GRO on (faster, less realistic loss)

vars:                    # overridable with --set; referenced as ${name}
  mobile_loss: 0%

segments:
  internet:
    subnet: [203.0.113.0/24, 2001:db8:113::/64]   # optional, at most one per family
  mobile:
    subnet: 100.64.0.0/24
    netem: {delay: 40ms, loss: "${mobile_loss}"}  # on every port, towards the nodes
    mtu: 1400                                     # optional default for its interfaces

nodes:
  router-b:
    forward: true                     # ip_forward and IPv6 forwarding
    sysctl:                           # any per-namespace sysctl
      net.ipv4.conf.all.rp_filter: 0
    interfaces:
      wan0:
        segment: mobile
        addr: 100.64.0.2              # prefix length from the segment subnet, or 100.64.0.2/24
        gateway: 100.64.0.1           # default route (gateway6 for IPv6)
        nat: masquerade               # home-router NAT out of this interface
        netem: {loss: 1%}             # node egress
        netem_in: {delay: 10ms}       # node ingress; replaces the segment's netem on this port
        mtu: 1400
        mac: 02:00:00:00:00:01
      lan0: {segment: lan-b, addr: 10.0.2.1}
    routes:
      - 10.0.1.0/24 via 10.0.2.2                   # string: passed to `ip route replace`
      - {to: 2001:db8:5::/48, via: "2001:db8:113::1", metric: 10}
      - default6 via 2001:db8:113::1               # IPv6 default by keyword
    firewall:                                      # censor / filter helper (nftables)
      - iif: wan0                                  # forwarded traffic arriving on wan0 ...
        allow:
          - {proto: tcp, to: 203.0.113.10, ports: [443, 4430]}
          - {proto: icmp}
        default: drop                              # ... everything else: drop | reject | accept
        local: false                               # true: also filter the node's own input (iif) / output (oif)
    nftables: [rules/extra.nft]                    # extra rulesets, relative to the topology file
    files:                                         # written into the node directory before start
      tunxd.yaml: |
        listen: ${router-b.wan0}:4430
      run.sh: {src: scripts/run.sh, mode: "0755"}
    start:                                         # background commands, cwd = node directory
      - exec ./run.sh
```

Rules and checks:

- Names: nodes and segments `[a-z][a-z0-9-]*` (max 24, nodes may not start
  with `sw-`); interfaces 1-15 chars, not `lo`.
- Addresses must lie inside the segment subnet of their family and be unique
  on a segment. Gateways and route `via` addresses must be on a connected
  subnet (add `onlink` to a route to skip that check).
- Unknown keys are errors with a suggestion, e.g.
  `nodes.gw-b.interfaces.eth0: unknown key 'adr' (did you mean 'addr'?)`.
- netem keys: `delay`, `jitter` (needs delay), `loss`, `reorder` (needs
  delay), `duplicate`, `corrupt`, `rate`, `limit` (packets, default 10000).
  Bare numbers mean ms for times and % for ratios. Segment netem applies once
  per direction, so `delay: 40ms` on a segment gives about 80 ms RTT.
  Jitter reorders packets (netem behaviour).
- The firewall always accepts `ct state established,related` first, so
  replies to allowed traffic pass.
- IPv6 addresses are added with `nodad` so they work immediately.

### Variables

`${...}` is expanded in every string of topology and scenario files; `$$` is
a literal `$` (use it for shell `${VAR}` in commands and files). Bare `$VAR`
is left for the shell.

| Reference | Value |
|:--|:--|
| `${name}` | a variable from `vars` (topology, then scenario), after `--set` |
| `${name:-default}` | the same with a fallback |
| `${node}` | first IPv4 address of the node |
| `${node.if}` / `${node.if.v6}` | first IPv4 / IPv6 address of an interface |
| `${node.if.cidr}` / `${node.if.cidr6}` | the same with prefix length |
| `${node.ns}` / `${node.dir}` | namespace name / node directory |
| `${sim}` `${run}` `${prefix}` `${topo}` | this directory, run directory, prefix, topology file directory |
| `${env.NAME}` | an environment variable |

## Scenario YAML

```yaml
name: smoke
vars: {probe: "python3 ${sim}/probe.py"}
keep_going: false        # true: run all steps even after a failure
steps:
  - name: optional label
    exec: ${probe} tcp ${hub.eth0} 443   # sh -c inside the node
    node: term-a
    rc: 0                # number, list, 'nonzero' or 'any' (default 0)
    match: '^peer ${router-a.wan0} '     # regex on stdout+stderr
    not_match: 'refused'
    timeout: 30
    continue: true       # a failure here does not stop the scenario
  - wait_until: ${probe} tcp ${hub.eth0} 443
    node: gw-b
    timeout: 60          # deadline in seconds
    interval: 1
  - background: exec tunxd -c tunxd.yaml # started in the node directory, log to logs/<node>.log
    node: gw-a
  - sleep: 2
  - netem: {loss: 3%}    # or 'reset' / 'clear'; same merge rules as the CLI
    segment: mobile      # or node + if (+ dir: out|in|both)
  - link: down           # up | down
    node: router-b
    if: wan0
    admin: false
  - measure: ping
    from: router-b
    to: ${carrier.mob0}
    count: 20
    interval: 0.2
    expect: {avg_rtt_min_ms: 75, avg_rtt_max_ms: 200, loss_max_pct: 5}
  - measure: iperf3      # starts a one-off iperf3 server on 'server'
    from: gw-b
    server: hub
    to: ${hub.eth0}      # default: server's first IPv4 address
    port: 4430           # default 5201
    proto: tcp           # tcp | udp (udp: bitrate, default 10M)
    duration: 5
    reverse: false
    parallel: 1
    expect: {mbps_min: 5, loss_max_pct: 1}
```

A scenario stops at the first failed step unless the step has
`continue: true` or the scenario sets `keep_going: true`; the remaining
steps are reported as skipped. Output looks like:

```
[10/25] PASS     0.1s  gw-b reaches the hub on TCP 443 (seen as the carrier)  -- exit 0
[15/25] PASS     4.0s  latency mobile  -- avg 80.4 ms, loss 0.0%
result: 25 passed, 0 failed, 0 skipped -> PASS
results: /run/tunx-sim/ts/results/smoke.json
```

The results file holds the vars, every step (status, seconds, detail, output
tail) and a `measurements` map (`rtt_*_ms`, `loss_pct`, `mbps`,
`retransmits`, `jitter_ms`) for comparing runs at different loss rates.

## probe.py

A stdlib helper for reachability checks: `probe.py serve --tcp 443 --udp 53`
answers every connection or datagram with `peer <addr> <port>`, and
`probe.py tcp|udp HOST PORT` prints that answer (exit 1 when nothing
answers). Scenarios use it to check both reachability and the source address
the server saw (NAT, source preservation).

## Example: two-sites

`topologies/two-sites.yaml` models the reference scenario of `docs/design.md`:

| Node | Segment(s) | Role |
|:--|:--|:--|
| hub | internet 203.0.113.10 | public hub; probe server on TCP 443/8080, UDP 443 |
| exit, phone, web | internet .20 .30 .80 | remote exit, a phone, a public server |
| router-a | internet .11, lan-a 10.0.1.1 | site A home router, NAT; 10.0.2.0/24 via gw-a |
| gw-a, term-a | lan-a .2 .10 | site A gateway node and terminal |
| carrier | internet .12, mobile 100.64.0.1 | mobile carrier: NAT and censor (only TCP 443/4430 to hub) |
| router-b | mobile .2, lan-b 10.0.2.1 | site B router, NAT; only uplink is mobile; 10.0.1.0/24 via gw-b |
| gw-b, host-b | lan-b .2 .10 | site B gateway node and target host |

The mobile segment has `delay ${mobile_delay}` (40ms) and
`loss ${mobile_loss}` (0%). `scenarios/smoke.yaml` checks plain IP
reachability, NAT sources, the censor, latency and throughput across the
mobile link, runtime netem and a link cut.

## Troubleshooting

- `sim.py status TOPO` shows stray or missing namespaces; `sim.py down TOPO`
  (or `down --prefix P`) always cleans up.
- `ip netns exec ts-sw-mobile tcpdump -ni router-b-wan0` captures on a switch port.
- `ip netns exec ts-carrier nft list ruleset` shows the generated rules;
  the source is in `nodes/carrier/sim-rules.nft`.
