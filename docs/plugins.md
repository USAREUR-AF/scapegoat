# Protocol plugins

The scapegoat core holds no protocol of any real sensor. A protocol is a Python package with
a class that subclasses `scapegoat.core.protocol.Protocol`.

- **Built-in** protocols live in `scapegoat/packages/<name>/`. Only `toy` ships.
- **Plugins** live in a plugin directory as `<dir>/<name>/__init__.py`. They are imported as
  `scapegoat_plugins.<name>`, so a plugin may use relative imports among its own modules.

## Where scapegoat looks

1. `SCAPEGOAT_PLUGIN_PATH` (directories separated by `:`), then `plugin_path = [...]` in the
   site config
2. `/etc/scapegoat/plugins`, `/opt/scapegoat/plugins` (`deploy/install.sh` installs here)
3. `plugins/` in a source checkout

`scapegoat sim <name>` lists the simulators it can find when the name is unknown.

## What a plugin provides

| Name | Required | Meaning |
|---|---|---|
| `create(settings)` or class `<Name>Protocol` | yes | Builds the Protocol from `[sessions.<id>.protocol_settings]` |
| `keepalive(link, action=0)` | yes | Bytes of one keepalive. Call `link.next_tx()` once for its sequence number. |
| `decode(datagram)` | yes | A `Decoded`. Never raises on bad input. |
| `on_receive(link, msg)` | no | Replies to send now, for example an answer to a keepalive request |
| `actions()`, `build_action(link, name)` | no | Manual triggers offered by the CLI and the web page; `dangerous=True` needs `--confirm` and the session's allow flag |
| `split(datagram)` | no | Messages in one datagram, or `(messages, padding_bytes, problem)` |
| `summarize(msg)` | no | The one-line field summary shown by `watch` |
| `soften_problems(part, msg)` | no | Turns tolerable decode problems into notes |
| `peer_request_field`, `peer_request_actions` | no | The keepalive field in which the peer asks for something, and code → action |
| `peer_status_fields` | no | Keepalive fields that carry the peer's own status |
| `transmit_actions` | no | Actions hidden unless `[features] transmit_control = true` |
| `tracks(msg)` | no | Normalized tracks for the C2 outputs: `track_id`, `source_id`, `time` (epoch s), `lat`, `lon`, optional `hae`, `vel_east`/`vel_north`/`vel_up`, `confirmed`, `coasting`, `final`, `simulated`, `classification` (`scapegoat/core/outputs.py`) |
| `sim_marker` | no | `(field, value)` the plugin's simulator puts in its keepalives, so status says SIMULATOR |
| `device_noun`, `device_id_setting`, `peer_id_field` | no | What the CLI and the web page call the device (default `device`, so status says REAL DEVICE), the `protocol_settings` key holding its ID (an operator types that ID to send a dangerous action; default `device_id`), and the keepalive field carrying the peer's own ID (default `device_id`) |
| module `CONFIG_ALIASES` | no | Old config key names the plugin still accepts: `{"session": {"old": "new"}, "features": {"old": "new"}}`. Session aliases apply to sessions using this protocol; feature aliases apply whenever the plugin is installed. Setting both names is an error. |
| module `validate_session(sc)` | no | Raise `ValueError` to refuse a site config |
| module `PROFILES = "profiles"` | no | A folder of profile TOML files listed by `scapegoat profiles` |
| module `SIMULATORS = {"name": "module:main"}` | no | Simulators for `scapegoat sim <name>` |

`scapegoat/packages/toy/__init__.py` is a complete, small example of every hook.
