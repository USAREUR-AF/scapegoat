<!--
SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
SPDX-License-Identifier: Apache-2.0
-->

# ADR 0002: scapegoat is written in Rust

| Field | Value |
|---|---|
| Status | Proposed |
| Date | 2026-11-25 |
| Deciders | operator |
| Owner | `goat-owners` |
| Related | goatcore ADR 0112 (`docs/adr/0112-tech-strategy-workload-shape-language-boundary.md`, language by workload shape); goatrope ADR 0003 (the same move for goatrope); goat-transformers `engines/rust` |

## Decision

scapegoat is written in Rust. It ships as one statically linked binary for each of
amd64 and arm64, and both binaries go in the one release archive.

The Python tree is ported module by module on an integration branch and removed in the
last step. No new feature goes into the Python tree while the port runs.

Protocols are Rust crates compiled into the binary. The open crate is a library and a
`scapegoat` binary that registers the `toy` protocol. A plugin is a separate crate that
depends on the open crate, registers its protocol, and builds its own node binary.

## Why Rust

goatcore ADR 0112 chooses the language by workload shape. A long-running process on a
per-packet path is Rust. Scripts and test drivers may be Python. scapegoat's roles fall
on the Rust side of that line:

| Role | Workload | ADR 0112 row |
|---|---|---|
| Session engine | a daemon that receives every sensor datagram, decodes it, answers it and copies it to forward targets | per-packet hot path: Rust |
| C2 outputs | every track encoded into CAT062, CoT or SAPIENT and sent | on the data path: Rust |
| HTTP API and web page | a local API polled by one page and the CLI | none of its own; shares the binary |
| CLI, network tools, simulators, conformance kit | commands run once | none of their own; share the binary |

The CLI and the simulators go in the same binary, so one file is installed, verified and
rolled back. goat-transformers already has a Rust engine (`engines/rust`), so the outputs
link it in instead of importing the Python engine from a checkout at run time.
goatrope made the same move (goatrope ADR 0003).

## How plugins work

Python loads a plugin from a directory at run time. Rust has no safe equivalent, so a
plugin is linked in at build time.

| Piece | What it is |
|---|---|
| `scapegoat` library | the session engine, the `Protocol` trait, config, API, CLI, outputs, network tools, conformance kit, and a protocol registry |
| `Protocol` trait | the same hooks as the Python `Protocol` class (`docs/plugins.md`): required `keepalive` and `decode`; optional `on_receive`, `actions`, `build_action`, `split`, `summarize`, `soften_problems`, `periodic`, `owes`, `status`, `drain_events`, `tracks`, and the descriptive values (`peer_request_field`, `sim_marker`, `device_noun` and the rest) |
| Registration | a plugin crate gives the registry a name, a constructor from `protocol_settings`, an optional `validate_session`, its simulators, its profiles, and its `config_aliases` (old key name to new, for session keys and `[features]` keys; setting both names is a config error). Aliases sit on the registry entry, not the trait, because they are applied while the config is read, before any protocol is constructed |
| `scapegoat` binary | `main` registers `toy` and runs the library's command line |
| A node's binary | a plugin crate's own `main` registers `toy` and its protocol, then runs the same command line. It has the same verbs, API and page. Only the registry differs |
| Conformance kit | a library function that runs every check against any registered protocol, called from the plugin crate's tests |

Why this shape:

- A private protocol stays in its own private repository and depends on the public
  crate by a pinned git revision. Nothing private enters the public repository, and the
  public crate needs no knowledge of any plugin. This is the overlay a private
  repository builds a node from: the open crate plus its own crate.
- The plugin is type-checked against the trait at build time. An interface change
  fails the plugin's build, not a node in the field.
- No `unsafe` loading of shared objects and no ABI to keep stable between separately
  built files.

Options considered for plugins:

| Option | Why not |
|---|---|
| Dynamic libraries (`dlopen` of a `.so`) | Rust has no stable ABI; every plugin must be built with the exact same compiler and crate versions, and loading is `unsafe` |
| A plugin as a separate process over a pipe or socket | adds a copy and a context switch on every datagram, and a second process to supervise, on the per-packet path |
| An embedded scripting language | brings back an interpreter and its own type rules for what is decode code on untrusted input |

## What does not change

Deployed nodes and their configs keep working without edits.

| Contract | Stays |
|---|---|
| Config files | `/etc/scapegoat/scapegoat.toml`, a JSON file of the same structure, every key, every default, every refusal and its message; `profile` and `profiles_dir` with the same merge rules |
| Profiles | the same TOML or JSON files in `/etc/scapegoat/profiles`; the shipped `sim-local`; a plugin's profiles |
| Plugin path keys | `plugin_path` and `SCAPEGOAT_PLUGIN_PATH` are still accepted. A plugin's profiles found there are still listed. A protocol that is not compiled into the binary is refused with a message that names the binary to install |
| HTTP API | every route on `127.0.0.1:8730`, its method, its query parameters, its status codes, and its JSON keys and values |
| Web page | `ui/index.html`, unchanged, served by the binary from a copy built into it |
| CLI | every verb (`serve`, `status`, `events`, `actions`, `action`, `enable`, `disable`, `reset`, `watch`, `lock`, `profiles`, `net ...`, `sim ...`), every flag in both spellings, `--api` and `--json` before or after the verb, exit codes, and the text each prints |
| Environment | `SCAPEGOAT_API`, `SCAPEGOAT_CONFIG`, `SCAPEGOAT_PLUGIN_PATH` |
| Wire behavior | sockets, keepalive schedule, link states and their event text, lock-on, the owed-reply ledger, the safety latch, forwarding and its socket rotation |
| C2 outputs | `[transformers]` and `[outputs.<name>]`, the same destinations and the same encoded bytes. The goat-transformers engine is linked into the binary; its packs and model are still read from `[transformers] path`, `GOAT_TRANSFORMERS_PATH` or `/opt/goat-transformers`, as now |
| Island publish | the same keys and JSON body to the Zenoh REST plugin |
| Service | the systemd unit name `scapegoat` and `/opt/scapegoat`; the unit's `ExecStart` runs the binary instead of the interpreter |

Python protocol plugins that are not ported no longer load. Each must be ported to a
crate before a node that uses it moves to the binary.

## How the port is done

Each step is one pull request into the integration branch `rust-port`, with a table of
which Python test each Rust test covers. The Python tree stays in place and passes until
the last step.

1. **Session engine, `toy` protocol and its simulator, config and profiles.**
2. **HTTP API and CLI**: `status`, `events`, `watch`, `actions`, `action`, `enable`,
   `disable`, `reset`, `lock`, `profiles`, `sim`, `serve`. The Python tests that drive the
   API or CLI over a socket run against the binary as well.
3. **C2 outputs**, through the goat-transformers Rust engine.
4. **Network tools** (`net` and the `/api/net` routes).
5. **Conformance kit.**
6. **Remove the Python tree**, and move `deploy/install.sh`, the field-node `scapegoat`
   component, the README, the CHANGELOG, the landing page and the release workflow to the
   binary.

The bar for merging `rust-port` into `main` is every one of the Python tests covered by a
passing Rust test or by the Python test run against the binary, and the landing page's
recording (`site/record.py`) giving the same state moves against the binary.

## Consequences

- One file to install, hash and roll back, with no interpreter on the node.
- A protocol plugin is Rust code built into the node's binary; a node runs the binary
  built from its plugin's crate.
- Two toolchains in CI during the port; one after it.
- The arm64 binary is built on an arm64 runner, natively, not emulated.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep Python | the session engine and the outputs are per-datagram daemon code; ADR 0112 puts that in Rust |
| Go | ADR 0112 puts the sustained per-packet regime in Rust, and goat-transformers' engine for this is Rust |
| Rewrite in one pull request | the tests could not tell which change broke which behavior; the module-by-module order keeps every step tested |
