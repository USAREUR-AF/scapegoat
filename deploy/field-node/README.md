# Field node installer

A field node is a small computer (a Raspberry Pi, for example) cabled to a sensor's network.
This folder builds one from **one site file**, and running it again brings the node back to
what the file says. The site file chooses which **components** the node runs:

| Component | Does | Needed when |
|---|---|---|
| `network` | Static addresses on the sensor interface, in one of the pack's modes, kept by a netplan file. | Always, for a cabled sensor |
| `capture` | Packet capture of the sensor link: first-bite's tap (`mind --tap-only`, the default), or a pack's own capture units. | When the raw link should be recorded or published |
| `kids` | Any number of Billie kids (install, listener, CAT062 identities, activate). | When the sensor's data goes to the fabric |
| `passthrough` | Publishes each UDP datagram from the sensor, unchanged, to the Billie island key you name. Senders outside the allowed network are dropped. If ufw is active it adds an input rule. | When no kid takes the sensor's format yet |
| `scapegoat` | A surrogate C2, for a sensor that sends nothing until a C2 system speaks first. Contributed by the scapegoat project. | Only for such sensors. A sensor that sends a standard format on its own needs a kid and no scapegoat. |
| `transformers` | goat-transformers at `/opt/goat-transformers`, from a pinned ref of the public USAREUR-AF/goat-transformers (commit or tarball sha256 checked; a mismatch installs nothing). Keeps only the Python engine, `model/` and the packs the outputs use. | When scapegoat's C2 outputs are on (`SCAPEGOAT_OUTPUTS`) |
| `usb_eth` | One netplan file, `/etc/netplan/56-usb-ethernet.yaml`, that gives any hot-plugged USB Ethernet adapter (`enx*`) a DHCP address and a default route at `USB_ETH_ROUTE_METRIC`. Optional: boot does not wait for it. No DHCPv6; IPv4 link-local only. Written and checked with `netplan generate`, never applied by the installer: it takes effect at the next plug-in, reboot or `sudo netplan apply`. Replaces any other `*usb-ethernet*.yaml` netplan file. Adapters an earlier systemd-networkd file claims by name (first-bite's `pi-tap` bridge ports, `05-pi-tap-<iface>.network`) keep that owner. | When a cable to a site LAN may be plugged in as an uplink. Switched on by `USB_ETH=on`, also with `COMPONENTS="none"` |

Sensor-specific facts (modes, scapegoat profiles, capture lists) come from a **pack** named
by `FIELD_PACK`:

- `packs/plain` is built in, with three modes:
  - `static` sets `SENSOR_CIDRS` on the interface.
  - `static-hosts` sets them as /32 addresses with no subnet route and routes only the hosts
    in `SENSOR_HOST_ROUTES` (on-link, from the node's address). Use it when the sensor subnet
    also holds the uplink's gateway, where a subnet route would take the default route.
  - `dhcp` leaves the interface to DHCP. It only checks that `SENSOR_CIDRS` is there and
    writes no netplan file.
- `packs/toy` is the scapegoat example.
- A protocol plugin ships its own pack in `plugins/<name>/field-node/`.

## Who owns what on a field node

| Piece | Owner |
|---|---|
| Sensor link (surrogate C2), when needed | scapegoat and its protocol plugin |
| Capture | first-bite (tap), or the pack |
| Kids and the platform (translator, island bridge, which adds the slot prefix) | Billie |
| Putting it all on a node from one site file | this installer |

## Build a node

```
cp deploy/field-node/examples/standard-format-radar.env my-site.env   # or toy-scapegoat.env, or a plugin's
sudo deploy/field-node/install-field-node.sh --site my-site.env --check   # what would change
sudo deploy/field-node/install-field-node.sh --site my-site.env           # do it
```

| Command | Does |
|---|---|
| `install-field-node.sh --site <file>` | Installs, or brings the node back to `<file>`. Copies it to `/etc/field-node/site.env` and the pack to `/etc/field-node/pack`. |
| `install-field-node.sh` | Same, using `/etc/field-node/site.env` |
| `install-field-node.sh --check` | Prints each phase's state and changes nothing. Exit 0 = matches; 3 = differs. |
| `install-field-node.sh --mode <mode>` | Also switches the sensor mode |
| `install-field-node.sh --uninstall --yes` | Undoes the components, in reverse order |

## Phases

Each phase checks before it changes anything, and changes only what differs. A failed check
stops the run.

| Phase | Component | Changes |
|---|---|---|
| Preflight | all | Nothing. It checks the site values: node name, interface, MAC-free file, each mode's addresses, and that every sensor address is in the node's subnet for that mode. It checks the kids' bundles, ports and CAT062 entries, the capture settings, and the tools. It refuses an interface that `billie network` already manages (one owner per interface). |
| Site file and pack | all | Copies both to `/etc/field-node/` |
| scapegoat: protocol data and mode hook | scapegoat | Copies the pack's protocol data if missing. Installs the mode hook that renders `/etc/scapegoat/scapegoat.toml`. |
| Mode commands | network | Installs `field-node-mode`, plus the pack's alias for it if any |
| Sensor mode | network | `field-node-mode <mode>`: the netplan file, the addresses now, the recorded mode, then the mode hooks |
| scapegoat program | scapegoat | `deploy/install.sh` when `/opt/scapegoat` differs |
| Capture | capture | `first-bite` (default): tap instances through first-bite's `deployment/tap/install.sh`. It needs `/usr/local/bin/mind`. TAP_INTERFACE comes from SENSOR_IFACE and `{host}` becomes NODE_NAME. A changed settings file restarts its running tap. The pack's units are removed. Files go to `/var/lib/first-bite-tap/<name>/` and are kept on uninstall. `units`: the pack's units. `off`: nothing. |
| Billie kids | kids | For each kid, as needed: `billie kid install` (after the sha256 check), `kid configure`, `cat062 source set`, `kid activate` |
| Verify | all | Every service active, every address of the mode on the interface |

## Site file

| Variables | Component | Meaning |
|---|---|---|
| `COMPONENTS` | all | Default `network capture kids`. Add `scapegoat` only for a sensor that needs a surrogate C2. |
| `NODE_NAME`, `NODE_ROLE`, `SENSOR_IFACE` | all | `SENSOR_IFACE` is a name (`eth0`), or a glob (`enx*` for a USB Ethernet adapter, whose name carries its MAC address) that must match exactly one interface. A glob cannot be used with `CAPTURE=units`. |
| `FIELD_PACK`, `FIELD_MODE` + the mode's variables | network | `plain`: `SENSOR_CIDRS="addr/prefix ..."`; `FIELD_MODE=dhcp` when the interface takes its address from DHCP |
| `CAPTURE`, `FIRST_BITE_TAP_INSTALL`, `CAPTURE_TAPS` or `FIRST_BITE_TAP_ENV_DIR` | capture | Default `first-bite`. `CAPTURE_TAPS="name=/path/settings.env ..."` overrides the pack's `TAP_ENVS`. Keep `TAP_FILTER` on one line in a settings file. |
| `KIDS`, `KID_<KEY>_{VERSION,BUNDLE,SHA256,TRANSPORT,BIND,PORT,SOURCE_CIDR,CAT062}` | kids | KEY = kid name in capitals, `-` as `_`. `CAT062="<source>:<sac>:<sic> ..."`. Older one-kid files (`KID_NAME`, `KID_BUNDLE`, `CAT062_SOURCE`, ...) still work. |
| `PASSTHROUGH`, `PASSTHROUGH_<KEY>_{BIND,PORT,SOURCE_CIDR,KEY,CONTENT_TYPE}` | passthrough | `KEY` is the island key; `{host}` becomes NODE_NAME. The fabric topic is `<slot>/<KEY>`. |
| `ALLOW_NET_CONTROL`, `ISLAND_REST`, `SCAPEGOAT_FORWARD` or `SCAPEGOAT_FORWARD_KID` + the pack's `REQUIRED_VARS` | scapegoat | Where scapegoat copies each received message (a kid's listener) |
| `SCAPEGOAT_OUTPUTS`, `OUTPUT_<NAME>_{FORMAT,TO,SAC,SIC,ENABLED,SESSIONS,HOW,STALE_S,NODE_ID,UID_PREFIX,MULTICAST_TTL}`, `GOAT_TRANSFORMERS_PATH` | scapegoat | scapegoat's C2 outputs, rendered into `[outputs.<name>]`. One track path per sensor: not together with a kid that publishes the same tracks. |
| `GOAT_TRANSFORMERS_REF` + `GOAT_TRANSFORMERS_COMMIT` (git) or `GOAT_TRANSFORMERS_SHA256` (tarball; offline: `GOAT_TRANSFORMERS_TARBALL=<path>`), `GOAT_TRANSFORMERS_GIT`, `GOAT_TRANSFORMERS_PACKS` | transformers | The pin is required. Packs default to the formats of `SCAPEGOAT_OUTPUTS` (plus `canonical-track-v2`). |
| `USB_ETH`, `USB_ETH_ROUTE_METRIC` | usb_eth | `USB_ETH=on` adds the component. The metric decides who carries traffic out: lower than the Wi-Fi's (for example 300 under a Wi-Fi at 600) makes a plugged cable the uplink; higher than every other default route (for example 700) means it never takes the uplink. |

## Modes and packs

`field-node-mode` (no argument) shows the current mode, the pack's modes and the addresses.
`sudo field-node-mode <mode>` switches. A switch rewrites the netplan file, so the addresses
survive a reboot. It adds and removes addresses with `ip addr` and never re-applies netplan,
so other links are not disturbed. It then runs the mode hooks in
`/usr/local/lib/field-node/mode.d/`.

| Pack file / key | Meaning |
|---|---|
| `pack.env`: `PACK_NAME`, `MODES`, `MODE_ALIASES`, `MODE_TOOL_ALIAS`, `NETPLAN_SUFFIX` | Modes and their names. The netplan file is `55-<iface>-<suffix>.yaml`. |
| `pack.env`: `CAPTURE_UNITS`, `CAPTURE_SCRIPTS`, `CAPTURE_TIMER_STARTED`, `TAP_ENVS` | Capture |
| `pack.env`: `SESSION_ID`, `SENSOR_PORT`, `DATA_VAR`, `DATA_SRC_VAR`, `DATA_CHECK`, `REQUIRED_VARS` | scapegoat packs only |
| `modes/<mode>.mode`: `DESCRIPTION`, `LOCAL_CIDRS_VARS`, `PEER_VAR`, `CANDIDATES_VAR`, `MANAGED`, `PREFIX_ROUTE`, `HOST_ROUTES_VAR`, `PROFILE`, `EXTRA_TOML` | One mode. `MANAGED=false`: the addresses come from DHCP, so they are checked, never set. `PREFIX_ROUTE=false`: the addresses go on as /32s, and only the hosts in `HOST_ROUTES_VAR` are routed. `PROFILE` and `EXTRA_TOML` are for scapegoat. |
| `session.toml.in` | scapegoat's `protocol_settings` for the session; `${VAR}` takes site values |

## Writing a component

A component is `components/<name>.sh`, sourced by the installer. It may define:

| Name | Purpose |
|---|---|
| `<name>_phases` | The number of phases it adds |
| `<name>_preflight` | Checks only. Calls `die` on a problem. |
| `<name>_pre` | Runs before every component's apply. Used for files that another component's step needs. |
| `<name>_apply` | One or more `phase` calls. Each change goes through `act`. |
| `<name>_verify` | Calls `expect_active <unit>`, or sets `FAILED=1` |
| `<name>_uninstall` | Undoes the component |

`FIELD_HOOKS+=(file)` lists a mode hook so that `--check` also sees its drift. Helpers are in
`lib/common.sh`.

## Finding the sensor on an unknown network

See `docs/find-a-device-on-an-unknown-network.md`. Agree any probe with the equipment owner
first.

## Undo

`sudo deploy/field-node/install-field-node.sh --uninstall --yes` undoes the components in
reverse order. Kids are stopped, but their packages are kept. The site file and every
capture file are kept.

Tests: `tests/test_field_node.py`. The cases are the toy pack, a capture-hook pack, a
standard-format radar node (no scapegoat, one kid), DHCP, a static-hosts node with a glob
interface and a pass-through, and an older one-kid site file. They run in a scratch root
with stub system commands.
