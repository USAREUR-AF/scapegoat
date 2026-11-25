# Changelog

## Unreleased

scapegoat is written in Rust (ADR 0002). It is one statically linked binary for amd64 or
arm64; both are in the release archive, with `bin/scapegoat`, which runs the one for the
machine.

Config files and profiles, the HTTP API, the web page, the CLI and its output, the
environment variables and the wire behavior are unchanged, so deployed nodes and their configs
keep working. `deploy/install.sh` installs the binary to `/opt/scapegoat/bin/scapegoat` and
removes an earlier version's Python tree; the systemd unit runs the binary.

A protocol plugin is now a Rust crate that depends on this one and builds its own node binary
(`docs/plugins.md`); a Python plugin no longer loads. The C2 outputs link the goat-transformers
Rust engine and still read its packs and model from `[transformers] path`.

`scapegoat check-config <file>` checks a config file the way `serve` loads it; the field-node
`scapegoat` component uses it.

- The `toy` protocol's keepalive fields are `seq`, `ack`, `ask` and `flags`; its actions are
  `ping` and `ask_reply` (`ask = 1`). Its default keepalive interval is 10 s.
- The gate for actions that make a device transmit is named for that: `allow_transmit_control`,
  `[features] transmit_control`, and the plugin attribute `transmit_actions`.
- A plugin can keep old config key names working with `config_aliases` on its registry
  entry (`docs/plugins.md`).
- A node binary can give the registry site extension tables (`src/extension.rs`): environment
  variable and request header aliases, config fallback paths, extra profile directories and
  extra island status URLs, as the Python core's `scapegoat/core/ext.py` read them.

## 0.1.0

The first public release of the scapegoat core: the session engine (keepalive schedule,
link states, lock-on to the first candidate that answers), the owed-reply ledger, the safety
latch for dangerous actions, the traffic log and `watch`, the web page and JSON API, the CLI,
the read-only network tools with guarded controls, the plugin loader with the `toy` protocol
and its simulator, the protocol conformance kit, the installer, and the field-node installer.

The core names no device type: a protocol plugin names its device, the setting that holds
its ID and the keepalive field that carries the peer's ID (`docs/plugins.md`).

Python 3.11 or newer (TOML settings); tested on 3.11 and 3.12.
