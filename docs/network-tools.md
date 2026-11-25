# scapegoat network tools

For the person at the sensor who needs to know why the link will not come up.
Everything here is reachable from the CLI (`scapegoat net ...`), the web page, and the API
(`GET /api/net`, `POST /api/net/<action>`).

## What `scapegoat net show` tells you

| Section | Shows | Look for |
|---|---|---|
| **hints** | Plain-English problems found, each with the command that fixes it | Read this first |
| **interfaces** | Each network port: up/down, carrier (cable), MAC, MTU, addresses, rx/tx bytes, packets, errors, drops | `carrier: false` = no cable/link; no address in the sensor's subnet; rising `rx_errors` |
| **neighbors** | The ARP table: which IPs this node has found on the wire, and their MAC | Sensor IP `FAILED`/`INCOMPLETE` = it does not answer on this wire |
| **routes** | The routing table | A route that sends the sensor's IP out the wrong port or via a gateway |
| **sessions** | Per sensor session: peer IP/port, the interface and source address used to reach it, whether a local address is in the peer's subnet, the peer's ARP state, who is listening on the UDP port | `same_subnet: []`, wrong `route.iface`, nobody listening |
| **expected_local_address** | `{cidr, present_on}`: whether this node holds `expected_local_address` from the config (e.g. `192.0.2.177/24`) and on which interface (`null` = missing). Detail in `expected_local` | `present: false` — the sensor learns our address from our keepalives, so it must be the one the sensor expects |
| **firewall** | `ufw status verbose` (or `nft` rules) and any rules mentioning the session port | Firewall on, default deny, no rule for UDP 47000 |

A session may list several possible sensor addresses in `peer_candidates` (besides or instead
of `peer`), for when the sensor address is not known for sure. Every candidate gets the same
checks (subnet, route, ARP) under `sessions[].peers[]`; ping each one to see which answers.

Many sensors only talk to a C2 address **in the same subnet as their own address**. If scapegoat has
no address in that subnet, nothing else matters until it does.

## Probes (read-only, always allowed)

| Command | Does |
|---|---|
| `scapegoat net ping <ip>` | 3 ICMP echoes; replies and average round-trip time |
| `scapegoat net capture [--port 47000] [--seconds 10]` | Lists every UDP packet on the port for N seconds (tcpdump): time, interface, direction, source, destination, length. Sends nothing |
| `udp_probe(ip, port)` (API) | Route, ARP state and subnet match for a peer. Sends nothing: putting test bytes on a sensor's port is not safe, and silence proves nothing for UDP |

## Controls (change the node; guarded)

| Action | Arguments | Runs |
|---|---|---|
| `addr_add` | `--iface eth0 --cidr 192.0.2.10/24` | `ip addr add 192.0.2.10/24 dev eth0` |
| `addr_del` | `--iface eth0 --cidr 192.0.2.10/24` | `ip addr del 192.0.2.10/24 dev eth0` |
| `link_up` | `--iface eth0` | `ip link set dev eth0 up` |
| `link_down` | `--iface eth0` | `ip link set dev eth0 down` (cuts your own session if you came in on it) |
| `neigh_flush` | `--iface eth0` | `ip neigh flush dev eth0` (after swapping the sensor or its address) |
| `fw_allow` | `--iface eth0 --from_cidr 192.0.2.0/24 --port 47000` | `ufw allow in on eth0 from 192.0.2.0/24 to any port 47000 proto udp` |

**Safety rule.** A control runs only when **both**:

1. `/etc/scapegoat/scapegoat.toml` has `allow_net_control = true` (then restart scapegoat), and
2. the request carries `--confirm` (API: `"confirm": true`).

Otherwise it is refused and the message shows the exact command it would have run. Interface
names must be interfaces that exist; addresses, networks and ports are checked before anything
runs; commands are never passed through a shell. Every request, refused or run, is kept in the
audit log (last 200, with the command and its output). An address added with `addr_add` lasts
until reboot; make it permanent in netplan once the link works.

## Field checklist: the sensor link will not come up

Work down the list; stop at the first thing that is wrong.

1. **Cable and carrier.** The hint "eth0 has no carrier: check the cable to the sensor network
   switch" names the port that should face the sensor. No carrier: cable, switch port, or the
   sensor end is off. Admin down: `link_up`. Hints name a port for `--iface` only if it has
   carrier and is not wireless or virtual (wlan*, wt*, podman*, veth*, lo, docker*); with no
   such port they print `<iface>` for you to fill in.
2. **Address in the sensor's subnet.** The sensor address comes from the sensor crew (example
   `192.0.2.81`). scapegoat needs an address in the same subnet on that port. If the config
   sets `expected_local_address`, use exactly that (the hint names it), e.g.
   `scapegoat net addr_add --iface eth0 --cidr 192.0.2.177/24 --confirm`; otherwise use a
   free address the sensor operator agrees to.
3. **Route.** `sessions[].peers[].route.iface` is the port the cable is in, with no gateway. If it goes
   out another port or via a gateway, a conflicting address or route is in the way.
4. **Neighbor / ARP.** `scapegoat net ping <sensor ip>`, then check the sensor's ARP entry. `FAILED`
   or `INCOMPLETE` = the sensor is not on this wire, is off, or has a different IP. A MAC that
   changed after a swap: `neigh_flush`.
5. **Firewall.** If ufw is active with default deny and no rule for UDP 47000, the sensor's
   replies are dropped: `fw_allow ... --confirm`.
6. **Packets on the wire.** `scapegoat net capture --seconds 35` (longer than one 30 s keepalive
   interval). Expect `Out` packets from scapegoat to the sensor every 30 s. No `Out`: the session is
   not enabled (`scapegoat status`). `Out` but no `In`: the sensor is not answering — check its
   ID and C2 settings with the sensor crew, and that it sees scapegoat's address in its subnet.
   `In` from another port than configured: can be normal; scapegoat records the address the sensor answers from (`scapegoat status`).

Controls and capture need root; scapegoat runs as root under systemd.

## Topology: routed or same-lan

`snapshot()["topology"]` = `{mode, source}`. Config `topology = "routed" | "same-lan"` wins;
otherwise `expected_local_address` set to a CIDR means same-lan; otherwise routed when the
route to the first peer uses a gateway and no local address is in the peer's subnet.

| Mode | Checks |
|---|---|
| routed | route to the sensor uses a gateway on a wired interface (hint if it leaves on Wi-Fi or `wt0`); a local address in the sensor's subnet is a fault (hint: `addr_del`); the router answers ARP. Never suggests adding an address. |
| same-lan | an address in the sensor's subnet (hint: `addr_add`), direct route, the sensor answers ARP. |

`probe.capture()` also captures ICMP; `icmp_unreachable` lists unreachable replies and `hints`
says "The router <ip> cannot find the sensor at <peer>: the sensor link not enabled, wrong address,
or the sensor not on that segment."
