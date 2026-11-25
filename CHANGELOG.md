# Changelog

## 0.1.0

The first public release of the scapegoat core: the session engine (keepalive schedule,
link states, lock-on to the first candidate that answers), the owed-reply ledger, the safety
latch for dangerous actions, the traffic log and `watch`, the web page and JSON API, the CLI,
the read-only network tools with guarded controls, the plugin loader with the `toy` protocol
and its simulator, the protocol conformance kit, the installer, and the field-node installer.

The core names no device type: a protocol plugin names its device, the setting that holds
its ID and the keepalive field that carries the peer's ID (`docs/plugins.md`).

Python 3.11 or newer (TOML settings); tested on 3.11 and 3.12.
