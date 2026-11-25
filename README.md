# scapegoat

**[usareur-af.github.io/scapegoat](https://usareur-af.github.io/scapegoat/)**

scapegoat runs on a small computer (a Raspberry Pi, for example) on a sensor's network and
plays the **C2 side of a sensor link**. It is for sensors that send nothing until a C2 system
speaks to them first. scapegoat speaks first, keeps the link alive and shows whether the
sensor is answering.

It also copies everything the sensor sends to other programs on the node.

- One statically linked binary, for amd64 or arm64. It installs on a node with no internet access.
- It runs on Ubuntu 24.04 and Raspberry Pi OS, and on macOS for development.

## What the core does

| Piece | What it does |
|---|---|
| Session engine (`src/session.rs`) | One UDP socket per sensor sends and receives. It runs a keepalive schedule and the link states handshaking → establishing → established → degraded → lost, and locks onto the first candidate address that answers. It keeps per-message counters and an event log, and copies messages to `forward` targets. |
| Protocols | A protocol builds and reads bytes; the core owns sockets, timers and state. `toy` ships with the core. Other protocols are **plugins**: crates that depend on this one and build their own node binary (`docs/plugins.md`). |
| Traffic log and watch | Every message sent and received, with decoded fields and problems. Read it with `scapegoat watch <session>` or on the web page. |
| Web page and API | `http://127.0.0.1:8730`. The page has no build step. The JSON API is described in the code (`src/api.rs`). |
| CLI | `scapegoat status`, `events`, `action`, `watch`, `lock`, `net ...`, `sim ...` |
| Network tools | `scapegoat net` is a read-only view of interfaces, routes, ARP, listeners and firewall, with plain-English hints. Guarded controls need `allow_net_control = true` plus `--confirm` (`docs/network-tools.md`). |
| Simulators | `scapegoat sim toy` is a peer that waits to be spoken to first. Plugins add their own simulators. |
| Conformance kit (`src/conformance.rs`) | Checks any protocol plugin against the contract the core relies on |

## Try it on a laptop

```
tools/build-bin.sh            # bin/<arch>/scapegoat; or unpack a release archive
bin/scapegoat sim toy --bind 127.0.0.1:47001 &
bin/scapegoat serve --config deploy/scapegoat.toml &
bin/scapegoat status
```

On a machine that is not Linux, `cargo run -- <command>` runs the same program.

## Install on a node

```
sudo ./deploy/install.sh
```

The binary goes to `/opt/scapegoat/bin/scapegoat` (from `bin/<arch>/scapegoat`, or the file
`SCAPEGOAT_BINARY` names, for example a node binary built from a plugin's crate), the config
to `/etc/scapegoat/scapegoat.toml`, and the service is `scapegoat` (systemd). Profiles in
`profiles/` and `plugins/*/profiles/` are installed to `/etc/scapegoat/profiles`.

## C2 outputs

A protocol plugin can turn its sensor's messages into tracks (the `tracks(msg)` hook).
scapegoat then encodes each track with goat-transformers' published packs and sends it to
the outputs you configure: ASTERIX CAT062, CoT XML or SAPIENT, over UDP (unicast or
multicast) or to a Zenoh key through the Zenoh REST plugin.

```
[transformers]
path = "/opt/goat-transformers"      # a checkout of USAREUR-AF/goat-transformers

[outputs.cat062]
format = "asterix-cat062"
to = ["udp://239.255.62.1:8600", "zenoh:site/sensor/cat062"]
sac = 1
sic = 7
```

Each output has its own `enabled` switch and optional `sessions` list. CoT takes `how`,
`stale_s` and `uid_prefix`; SAPIENT needs `node_id`. Without goat-transformers the outputs
are off and `scapegoat status` says why. On a field node, the `transformers` component
installs goat-transformers from a pinned ref (see `deploy/field-node/README.md`). The group
in the example is a placeholder. One track path per sensor: if another program
already publishes a sensor's tracks, do not also publish them from scapegoat.

## A field node

`deploy/field-node/` builds a whole node from one site file: addresses and mode, scapegoat,
capture (the pack's units or first-bite's tap) and a Billie kid. Read
`deploy/field-node/README.md`.

## Tests

```
cargo test                                   # the program
python3 -m unittest discover -s tests -t .   # the field-node installer (shell, driven from Python)
```

## Licence

Apache-2.0. See LICENSE and NOTICE.
