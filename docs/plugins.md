# Protocol plugins

The scapegoat core holds no protocol of any real sensor. A protocol is a Rust type that
implements the `scapegoat::protocol::Protocol` trait, and a plugin is a crate that depends on
this crate and builds its own node binary (ADR 0002).

- **Built-in:** `toy` (`src/toy.rs`) ships with the core and is what the `scapegoat` binary
  registers.
- **Plugins:** a separate crate, for example in a private repository, depends on this crate
  by a pinned git revision, registers its protocol and builds the binary its nodes run. That
  binary has the same commands, API and web page; only the protocols it knows differ.

## A node binary

```rust
use scapegoat::protocol::{ConfigAliases, Plugin, Registry};

fn main() {
    Registry::new()
        .with(scapegoat::toy::plugin())
        .with(Plugin {
            name: "mine".into(),
            create: |settings| Ok(Box::new(MyProtocol::new(settings))),
            validate_session: Some(check_addresses), // refuse a site config: Err(message)
            simulators: vec![("mine".into(), my_sim::main)],  // scapegoat sim mine
            profiles: vec![("mine-site".into(), include_str!("../profiles/mine-site.toml").into())],
            builtin: false,
            // old config key names still accepted: (old, new); setting both is an error
            config_aliases: ConfigAliases {
                session: vec![("allow_old_name".into(), "allow_transmit_control".into())],
                features: vec![("old_name".into(), "transmit_control".into())],
            },
        })
        .install();
    std::process::exit(scapegoat::run(std::env::args().skip(1).collect()));
}
```

`examples/fake_node.rs` in this repository is a complete, small node binary.

`config_aliases` keeps a plugin's old config key names working. Session aliases apply to
sessions using the plugin's protocol; feature aliases apply whenever the plugin is in the
binary. Setting both an old name and its new name refuses the config.

A site config names a protocol that is not compiled into the binary: the session reports
`protocol "<name>" is not installed: this binary (<file>) has toy, ...`. `plugin_path` and
`SCAPEGOAT_PLUGIN_PATH` are still read for the profiles a plugin ships as files
(`<dir>/<name>/profiles/*.toml`, listed by `scapegoat profiles`).

## What a protocol provides

| Trait item | Required | Meaning |
|---|---|---|
| `name()` | yes | The name a site config's `protocol` gives |
| `keepalive(link, action)` | yes | Bytes of one keepalive. Call `link.next_tx()` once for its sequence number. |
| `decode(datagram)` | yes | A `Decoded`. Never panics on bad input: a problem goes in `problems`. |
| `default_port()`, `keepalive_interval_s()` | no | The local port when `local` is not set; the keepalive interval when `protocol_settings` does not set one |
| `on_receive(link, msg)` | no | Replies to send now, for example an answer to a keepalive request |
| `actions()`, `build_action(link, name, args)` | no | Manual triggers offered by the CLI and the web page; `dangerous: true` needs `--arm`, the device ID and the session's allow flag |
| `split(datagram)` | no | The messages in one datagram, padding bytes and a problem |
| `summarize(msg)` | no | The one-line field summary shown by `watch` |
| `soften_problems(part, msg)` | no | Turns tolerable decode problems into notes |
| `periodic(link, now)`, `owes(msg)`, `status()`, `drain_events()` | no | Messages due on a schedule, "this message must be answered", protocol facts for the status (`display` lines and tables), events for the log |
| `peer_request_field()`, `peer_request_actions()` | no | The keepalive field in which the peer asks for something, and code -> action |
| `peer_status_fields()` | no | Keepalive fields that carry the peer's own status |
| `transmit_actions()` | no | Actions hidden unless `[features] transmit_control = true` |
| `tracks(msg)` | no | Normalized tracks for the C2 outputs: `track_id`, `source_id`, `time` (epoch s), `lat`, `lon`, optional `hae`, `vel_east`/`vel_north`/`vel_up`, `confirmed`, `coasting`, `final`, `simulated`, `classification` (`src/outputs.rs`) |
| `sim_marker()` | no | `(field, value)` the plugin's simulator puts in its keepalives, so status says SIMULATOR |
| `device_noun()`, `device_id_setting()`, `peer_id_field()` | no | What the CLI and the web page call the device (default `device`, so status says REAL DEVICE), the `protocol_settings` key holding its ID (an operator types that ID to send a dangerous action; default `device_id`), and the keepalive field carrying the peer's own ID (default `device_id`) |

A `Decoded` holds `name`, `fields` (labels, in order), `ok`, `problems`, `is_keepalive`,
`peer_tx_counter`, and optionally `values` (raw numbers of labelled fields) and `raw` (the
bytes).

## Conformance

A plugin crate's tests check its protocol against the contract the core relies on:

```rust
scapegoat::protocol_conformance!(|| Box::new(MyProtocol::new(&serde_json::Map::new())));
```

`src/toy.rs` is a complete, small example of every hook.
