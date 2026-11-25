"""scapegoat command line. Every command except `serve` and `sim` talks to the
running service over its local HTTP API."""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request

from .core import ext

DEFAULT_API = ext.env("SCAPEGOAT_API", "http://127.0.0.1:8730")[0]
DEFAULT_CONFIG = "/etc/scapegoat/scapegoat.toml"


def resolve_config(explicit: str | None) -> tuple:
    """-> (path, note). --config, then $SCAPEGOAT_CONFIG, then
    /etc/scapegoat/scapegoat.toml (then any fallback a site extension declares)."""
    if explicit:
        return explicit, ""
    path, note = ext.env("SCAPEGOAT_CONFIG")
    if path:
        return path, note
    if not os.path.exists(DEFAULT_CONFIG):
        for old in ext.config_fallbacks():
            if os.path.exists(old):
                return old, ext.config_fallback_note(old, DEFAULT_CONFIG)
    return DEFAULT_CONFIG, ""
NET_CONTROL = ("addr_add", "addr_del", "link_up", "link_down", "neigh_flush", "fw_allow")

STATE_MARK = {
    "established": "[OK]  established",
    "establishing": "[..]  establishing",
    "handshaking": "[>>]  handshaking",
    "degraded": "[!]   degraded",
    "lost": "[XX]  lost",
    "disabled": "[--]  disabled",
}


class CliError(Exception):
    pass


def _user() -> str:
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return ""


# ---------------------------------------------------------------- API client
def call(api: str, method: str, path: str, body: dict | None = None, timeout: float = 15):
    url = api.rstrip("/") + path
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json", "X-Scapegoat-Source": "cli",
        "X-Scapegoat-User": _user()})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"null")
    except urllib.error.HTTPError as exc:
        try:
            with exc:
                msg = json.loads(exc.read()).get("error")
        except Exception:
            msg = None
        raise CliError(msg or f"HTTP {exc.code} from {url}") from None
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
        reason = getattr(exc, "reason", exc)
        raise CliError(f"cannot reach the scapegoat service at {api} ({reason}).\n"
                       "Is it running?  Check: systemctl status scapegoat") from None


# ---------------------------------------------------------------- formatting
def _age(v):
    if v is None:
        return "never"
    return f"{v:.0f}s ago" if v >= 10 else f"{v:.1f}s ago"


def _table(rows, headers):
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)]
    line = "  ".join(f"{{:<{w}}}" for w in widths)
    out = [line.format(*headers), line.format(*["-" * w for w in widths])]
    out += [line.format(*map(str, r)) for r in rows]
    return "\n".join(out)


def _peer_text(s):
    if s.get("locked"):
        seen = s.get("peer_seen")
        return (seen or s["locked"]) + (" (locked, forced)" if s.get("lock_forced") else "")
    cands = [c["address"] for c in s.get("candidates", [])] or [s["peer"]]
    return "probing " + ", ".join(cands)


def print_expected(health):
    el = (health or {}).get("expected_local")
    if el:
        mark = "[OK]" if el.get("present") else "[!] " if el.get("present") is False else "[?] "
        print(f"Node address: {mark} {el.get('text')}")


def print_node(node, indent=""):
    """The 'This node' block: hostname, Billie identity, one row per address with its role."""
    if not node:
        return
    head = f"{indent}This node: {node.get('hostname', '?')}"
    b = node.get("billie") or {}
    if b.get("node_handle"):
        head += f"   Billie node {b['node_handle']}"
    if b.get("billie_fabric_prefix"):
        head += f"   slot {b['billie_fabric_prefix']}"
    print(head)
    if b.get("billie_fabric_endpoint"):
        print(f"{indent}  fabric endpoint {b['billie_fabric_endpoint']}")
    if node.get("error"):
        print(f"{indent}  (addresses not available: {node['error']})")
    rows = []
    for a in node.get("addresses") or []:
        cable = {True: "cable", False: "NO CABLE"}.get(a.get("cable"), "")
        rows.append([a["role"], a["iface"], a["cidr"], a.get("link", "?") + (f", {cable}" if cable else ""),
                     a.get("route_note") or ("default route" if a.get("default_route") else "")])
    if rows:
        print(indent + "  " + _table(rows, ["ROLE", "IFACE", "ADDRESS", "LINK", ""]).replace(
            "\n", "\n" + indent + "  "))
    elif not node.get("error"):
        print(f"{indent}  (no addresses except loopback)")


def _node(api):
    try:
        return call(api, "GET", "/api/node", timeout=5)
    except CliError:
        return None


TOPOLOGY_TEXT = {"routed": "routed (sensor reached through a router; no sensor-subnet address "
                           "on this node)",
                 "same-lan": "same-lan (this node is on the sensor's subnet)",
                 "auto": "auto (inferred from the route: see scapegoat net)"}


def identity_lines(ident) -> list:
    if not ident:
        return []
    first = ident.get("title") or ident.get("hostname") or "?"
    if ident.get("role_note") and ident.get("billie_node"):
        first += f"   ({ident['role_note']})"
    elif ident.get("role_note"):
        first = f"{ident.get('hostname')} · {ident['role_note']}"
    parts = []
    if ident.get("billie_node"):
        parts.append(f"Billie node {ident['billie_node']}")
    for r in ident.get("sensor_sees") or []:
        parts.append(f"sensor sees us at {r['address']}" + (f" ({r['session']})" if
                                                          len(ident["sensor_sees"]) > 1 else ""))
    if ident.get("mesh_address"):
        parts.append(f"mesh {ident['mesh_address']}")
    if ident.get("slot_short"):
        parts.append(f"slot {ident['slot_short']}")
    return [first] + (["  " + "  ·  ".join(parts)] if parts else [])


def print_outputs(o):
    """C2 outputs block for `scapegoat status`."""
    if not o or not o.get("outputs"):
        return
    print("C2 outputs:" + (f"  OFF: {o['error']}" if o.get("error") else
                           f"  {o.get('tracks_in', 0)} tracks in, {o.get('encode_errors', 0)} encode errors"))
    for x in o["outputs"]:
        state = "on " if x["enabled"] else "off"
        print(f"  [{state}] {x['name']:<10} {x['format']:<15} -> {', '.join(x['to'])}   "
              f"sent {x['sent']}, errors {x['errors']}"
              + (f" ({x['last_error']})" if x.get("last_error") else ""))


def print_status(sessions, health=None, node=None):
    for line in identity_lines((health or {}).get("identity")):
        print(line)
    if health and health.get("identity"):
        print()
    print_node(node)
    if node:
        print()
    if health and health.get("profile"):
        print(f"Profile: {health['profile']}")
    if health and health.get("topology"):
        print(f"Topology: {TOPOLOGY_TEXT.get(health['topology'], health['topology'])}")
    print_expected(health)
    if health:
        print()
    if not sessions:
        print("No sessions configured. Add a [sessions.<name>] table to the config.")
        return
    rows = []
    for s in sessions:
        rows.append([s["id"], s.get("peer_kind", "?"), STATE_MARK.get(s["state"], s["state"]),
                     _peer_text(s),
                     _age(s.get("last_rx_age_s")), _age(s.get("last_tx_age_s")),
                     f'{s["tx_datagrams"]}/{s["rx_datagrams"]}', s.get("bad_datagrams", 0)])
    print(_table(rows, ["SESSION", "KIND", "STATE", "PEER", "LAST RX", "LAST TX", "TX/RX", "BAD"]))
    for s in sessions:
        if s.get("error"):
            print(f"\n{s['id']}: ERROR: {s['error']}")
        for line in _attention_lines(s):
            print(f"{s['id']}: {line}")
    print_outputs((health or {}).get("outputs"))

def _peer_status_text(ps):
    if not ps:
        return ""
    return ", ".join(str(v) for v in ps.values() if v)


def _attention_lines(s):
    """Lines an operator must see: what the device asks for, and problems."""
    out = []
    pr = s.get("peer_request")
    if pr:
        line = f"{(s.get('device_noun') or 'device').upper()} IS ASKING: {pr['label']}"
        act = pr.get("suggested_action")
        if pr.get("disabled_reason"):
            line += f"  ({pr['disabled_reason']})"
        elif act:
            a = next((x for x in s.get("actions", []) if x["name"] == act), {})
            line += f"  -> scapegoat action {s['id']} {act}" + (" --confirm" if a.get("dangerous") else "")
            if a and not a.get("allowed"):
                line += "  (needs allow_radiate_control = true)"
        out.append(line)
    probs = s.get("problems") or []
    if probs:
        p = probs[0]
        more = f" (+{len(probs) - 1} more: scapegoat status {s['id']})" if len(probs) > 1 else ""
        out.append(f"PROBLEM: {p['problem']} (x{p['count']}){more}")
    return out


def print_session(s):
    print(f"Session {s['id']}  ({s['protocol']})   {_kind_banner(s)}")
    print(f"  State:       {STATE_MARK.get(s['state'], s['state'])} for {s.get('state_age_s')}s")
    print(f"  Peer:        {_peer_text(s)}; seen from {s.get('peer_seen') or 'nothing yet'}")
    for c in s.get("candidates", []):
        tag = "LOCKED" if c["locked"] else ("probing" if c["probing"] else "dropped")
        print(f"    candidate {c['address']:<22} {tag:<8} tx {c['tx_counter']} rx {c['rx_counter']}")
    print(f"  Local:       {s['local']}   keepalive every {s['keepalive_interval_s']}s")
    print(f"  Counters:    our tx_counter {s['tx_counter']}, peer counter {s['rx_counter']}")
    print(f"  Datagrams:   sent {s['tx_datagrams']}, received {s['rx_datagrams']} "
          f"({s.get('rx_messages', s['rx_datagrams'])} messages, "
          f"{s.get('multi_message_datagrams', 0)} datagrams with several), "
          f"bad {s['bad_datagrams']}, forwarded {s['forwarded']} "
          f"(one per {s.get('forward_mode', 'message')})")
    for n in s.get("notes") or []:
        print(f"  Note:        {n['note'].split(' (message is')[0]} "
              f"[{', '.join(n.get('messages') or [])}] x{n['count']} "
              "(self-consistent; newer dictionary revision)")
    if s.get("peer_status"):
        print(f"  {(s.get('device_noun') or 'device').capitalize() + ' says:':<13}{_peer_status_text(s['peer_status'])} "
              f"(last keepalive {_age(s['peer_status'].get('age_s'))})")
    if s.get("error"):
        print(f"  ERROR:       {s['error']}")
    pr = s.get("peer_request")
    if pr:
        print(f"  {_attention_lines(dict(s, problems=[]))[0]}  (x{pr['count']}, "
              f"last {_age(pr.get('last_seen_age_s'))})")
    ps = s.get("protocol_status") or {}
    disp = ps.get("display") or {}   # the protocol's own lines and tables (Protocol.status)
    for line in disp.get("lines") or []:
        print(f"  {line}")
    ow = s.get("owed_replies") or {}
    if ow.get("answered") or ow.get("missed") or ow.get("waiting"):
        print(f"  Owed replies:   {ow.get('answered', 0)} answered, {ow.get('missed', 0)} missed, "
              f"{ow.get('waiting', 0)} waiting")
    for t in disp.get("tables") or []:
        print()
        print(_table([[("-" if c is None else c) for c in row] for row in t.get("rows") or []],
                     [str(c).upper() for c in t.get("columns") or []]))
    probs = s.get("problems") or []
    if probs:
        print()
        print(_table([[p["problem"], ", ".join(p.get("messages") or []), p["count"],
                       _age(p.get("last_seen_age_s"))] for p in probs],
                     ["PROBLEM", "IN MESSAGES", "COUNT", "LAST SEEN"]))
    names = sorted(set(s["rx_by_name"]) | set(s["tx_by_name"]))
    if names:
        print()
        print(_table([[n, s["tx_by_name"].get(n, 0), s["rx_by_name"].get(n, 0)] for n in names],
                     ["MESSAGE", "SENT", "RECEIVED"]))


def print_events(events):
    if not events:
        print("No events yet.")
    for e in events:
        print(f"{e['time']}  {e.get('source', ''):<4}  {e['kind']:<8}  {e['message']}")


def emit(args, obj, human):
    if args.json:
        print(json.dumps(obj, indent=2, default=str))
    else:
        human(obj)


# ---------------------------------------------------------------- commands
def cmd_serve(args):
    from scapegoat.core import config as cfgmod
    from scapegoat.core.service import run_forever
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    path, note = resolve_config(args.config)
    if note:
        logging.getLogger("scapegoat").warning(note)
    try:
        cfg = cfgmod.load(path, profile=args.profile)
    except cfgmod.ConfigError as exc:
        raise CliError(f"config problem: {exc}")
    if cfg.profile:
        logging.getLogger("scapegoat").info("config %s over profile %s (%s)", cfg.path,
                                          cfg.profile, cfg.get("profile_path"))
    if args.bind:
        cfg.bind = args.bind
        cfg.raw["bind"] = args.bind
    try:
        return run_forever(cfg, only_session=args.session)
    except KeyError as exc:
        raise CliError(str(exc.args[0]))
    except OSError as exc:
        raise CliError(f"cannot start the API on {cfg.bind}: {exc}")


def cmd_status(args):
    if args.session:
        emit(args, call(args.api, "GET", f"/api/sessions/{args.session}"), print_session)
    else:
        sessions = call(args.api, "GET", "/api/sessions")
        try:
            health = call(args.api, "GET", "/api/health")
        except CliError:
            health = None
        node = _node(args.api)
        if args.json:
            print(json.dumps({"health": health, "node": node, "sessions": sessions},
                             indent=2, default=str))
        else:
            print_status(sessions, health, node)


def cmd_events(args):
    if args.session:
        ev = call(args.api, "GET", f"/api/sessions/{args.session}/events?n={args.n}")
    else:
        ev = []
        for s in call(args.api, "GET", "/api/sessions"):
            for e in call(args.api, "GET", f"/api/sessions/{s['id']}/events?n={args.n}"):
                ev.append(dict(e, message=f"[{s['id']}] {e['message']}"))
        ev.extend(call(args.api, "GET", "/api/events"))
        ev = sorted(ev, key=lambda e: e.get("ts", 0))[-args.n:]
    emit(args, ev, print_events)


def cmd_actions(args):
    s = call(args.api, "GET", f"/api/sessions/{args.session}")

    def human(s):
        rows = [[a["name"] + "".join(f" <{p['name']}>" for p in a.get("params", [])),
                 "LOCKED (--arm)" if a["dangerous"] else "",
                 "yes" if a["allowed"] else "no (allow_radiate_control is false)",
                 a["description"]] for a in s["actions"]]
        print(_table(rows, ["ACTION", "", "ALLOWED", "WHAT IT DOES"]))
    emit(args, s, human)


def _action_args(spec: dict, values: list) -> dict:
    """Positional values in the action's parameter order, or name=value."""
    params = [p["name"] for p in spec.get("params", [])]
    out, pos = {}, 0
    for v in values:
        if "=" in v:
            k, _, val = v.partition("=")
            out[k.replace("-", "_")] = val
        else:
            if pos >= len(params):
                raise CliError(f"{spec['name']} takes {len(params)} value(s): "
                               f"{' '.join(params) or 'none'}")
            out[params[pos]] = v
            pos += 1
    missing = [p["name"] for p in spec.get("params", [])
               if p.get("default") is None and p["name"] not in out]
    if missing:
        raise CliError(f"{spec['name']} needs: {' '.join(missing)}")
    return out


def cmd_action(args):
    name = args.name.replace("-", "_")
    s = call(args.api, "GET", f"/api/sessions/{args.session}")
    spec = next((a for a in s.get("actions", []) if a["name"] == name), None)
    if spec is None:  # let the service say why (unknown, or hidden by the feature flag)
        call(args.api, "POST", f"/api/sessions/{args.session}/actions/{name}", {})
        raise CliError(f"no action named {args.name!r}. List them: scapegoat actions {args.session}")
    values = _action_args(spec, args.values)
    base = f"/api/sessions/{args.session}"
    if not spec.get("dangerous"):
        r = call(args.api, "POST", f"{base}/actions/{name}", {"args": values})
        emit(args, r, lambda r: print(f"Sent {r['action']} on {r['session']} ({r['bytes']} bytes)."))
        return
    # Commands the device: the safety latch. One command per arm.
    if not args.arm:
        effect = spec.get("effect") or name
        for k, v in values.items():
            effect = effect.replace("{" + k + "}", str(v))
        raise CliError(f"{name} is locked. It would: {effect}.\n"
                       f"To send it: scapegoat action {args.session} {args.name} "
                       f"{' '.join(args.values)} --arm".rstrip())
    a = call(args.api, "POST", f"{base}/arm/{name}", {"args": values})
    print(f"ARMED for {a['expires_in_s']:g} s: {a['effect']}.")
    typed = args.confirm
    if typed is None:
        try:
            typed = input(f"Type the {a.get('device_noun', 'device')} ID ({a['device_id']}) to send it, "
                          "anything else cancels: ")
        except (EOFError, KeyboardInterrupt):
            typed = ""
    if str(typed).strip() != str(a["device_id"]):
        call(args.api, "POST", f"{base}/disarm/{name}", {})
        raise CliError(f"cancelled: the {a.get('device_noun', 'device')} ID did not match. Re-locked.")
    r = call(args.api, "POST", f"{base}/actions/{name}",
             {"args": values, "token": a["token"], "confirm": str(typed).strip()})
    emit(args, r, lambda r: print(f"Sent {r['action']} on {r['session']}: {r.get('effect')}. Re-locked."))


ARROW = {"tx": "->", "rx": "<-", "fwd": "=>", "wire": "~~", "dgram": "<<"}


def _short(v, n=40):
    s = str(v)
    return s if len(s) <= n else s[:n - 3] + "..."


def key_fields(e) -> str:
    """The protocol's own one-line summary (entry["summary"]), else the first six fields."""
    if e.get("summary") is not None:
        return e["summary"]
    f = e.get("fields") or {}
    return " ".join(f"{k}={_short(f[k], 24)}" for k in list(f)[:6])


def format_entry(e, fields=False, hexdump=False) -> str:
    t = (e.get("time") or "")[11:23]
    if e.get("direction") == "wire":
        who = f"{e.get('src', '?')} > {e.get('dst', '?')}"
    else:
        who = e.get("peer", "")
    line = (f"{t}  {ARROW.get(e.get('direction'), '??')} {who:<21}  "
            f"{e.get('name', 'unknown'):<24} {key_fields(e)}")
    if e.get("direction") == "dgram":
        f = e.get("fields") or {}
        line = (f"{t}  << {who:<21}  datagram {e.get('length')} B = "
                + " + ".join(f.get("messages") or [])
                + (f" + {f['padding_bytes']} B padding" if f.get("padding_bytes") else ""))
    if e.get("notes"):
        line += "  (note: " + "; ".join(n.split(" (message is")[0] for n in e["notes"]) + ")"
    if not e.get("ok") or e.get("problems"):
        line += "  !! " + ("; ".join(e.get("problems") or []) or "failed checks")
    out = [line]
    if fields:
        for k, v in (e.get("fields") or {}).items():
            out.append(f"      {k} = {v}")
    if hexdump:
        h = e.get("hex", "")
        for i in range(0, len(h), 32):
            out.append("      " + " ".join(h[j:j + 2] for j in range(i, min(i + 32, len(h)), 2)))
    return "\n".join(out)


def _show(args, entries):
    for e in entries:
        if args.filter and args.filter.lower() not in (e.get("name") or "").lower():
            continue
        if args.json:
            print(json.dumps(e, default=str))
        else:
            print(format_entry(e, args.fields, args.hex))
    sys.stdout.flush()


def _kind_banner(s) -> str:
    k = s.get("peer_kind")
    if k == "SIMULATOR":
        return "*** SIMULATOR - not a real sensor ***"
    noun = s.get("device_noun") or "device"
    if s.get("peer_is_real") or str(k or "").startswith("REAL "):
        rid = s.get("peer_device_id")
        where = s.get("peer_seen") or s.get("locked") or ""
        return f"### {k} {where}" + (f" ({noun.capitalize()} ID {rid})" if rid is not None else "") + " ###"
    return f"(no {noun} has answered yet)"


class _KindWatch:
    """Prints a banner line at start and whenever the session's peer kind changes."""

    def __init__(self, args, every=4):
        self.args, self.every, self.n, self.last = args, every, 0, None

    def check(self, force=False):
        self.n += 1
        if not force and self.n % self.every:
            return
        try:
            s = call(self.args.api, "GET", f"/api/sessions/{self.args.session}")
        except CliError:
            return
        key = (s.get("peer_kind"), s.get("peer_seen"), s.get("peer_device_id"))
        if key != self.last:
            self.last = key
            if self.args.json:
                print(json.dumps({"type": "peer_kind", "peer_kind": s.get("peer_kind"), "peer": s.get("peer_seen"),
                                  "peer_device_id": s.get("peer_device_id")}))
            else:
                print(f"=== {_kind_banner(s)} ===")
            sys.stdout.flush()


def cmd_watch(args):
    base = f"/api/sessions/{args.session}"
    kinds = _KindWatch(args)
    if args.wire:
        if not args.json:
            print(f"Capturing session {args.session}'s UDP port from the wire, "
                  f"{args.seconds:g} s per round. Ctrl-C stops.")
        while True:
            kinds.check(force=True)
            r = call(args.api, "GET", f"{base}/wire?seconds={args.seconds:g}",
                     timeout=args.seconds + 20)
            if r.get("error"):
                raise CliError(f"wire capture: {r['error']}")
            _show(args, r.get("entries", []))
            for h in r.get("hints") or []:
                print(f"!! {h}")
            if args.once:
                return
    r = call(args.api, "GET", f"{base}/traffic?limit={max(1, args.last)}")
    if not args.json:
        print(f"Watching session {args.session} (-> sent, <- received, => forwarded). "
              "Ctrl-C stops.")
    kinds.check(force=True)
    _show(args, r["entries"][-args.last:] if args.last > 0 else [])
    since = r["last_seq"]
    while not args.once:
        time.sleep(0.5)
        r = call(args.api, "GET", f"{base}/traffic?since={since}&limit=500")
        kinds.check()
        _show(args, r["entries"])
        if r["entries"]:
            since = r["entries"][-1]["seq"]
        elif r["last_seq"] < since:  # service restarted or reset: start over
            since = 0


def cmd_lock(args):
    r = call(args.api, "POST", f"/api/sessions/{args.session}/lock", {"peer": args.peer})
    emit(args, r, lambda r: print(f"Session {r['id']} locked onto {r['locked']}. "
                                  f"`scapegoat reset {r['id']}` goes back to probing all candidates."))


def cmd_profiles(args):
    from scapegoat.core.config import list_profiles, profile_dirs
    profs = list_profiles(args.profiles_dir)

    def human(profs):
        if not profs:
            print("No profiles found in " + ", ".join(profile_dirs(args.profiles_dir)))
            return
        print(_table([[p["name"], p["description"]] for p in profs], ["PROFILE", "WHAT IT IS FOR"]))
        print("\nUse one: put  profile = \"<name>\"  at the top of /etc/scapegoat/scapegoat.toml")
    emit(args, profs, human)


def cmd_lifecycle(args):
    r = call(args.api, "POST", f"/api/sessions/{args.session}/{args.cmd}", {})
    emit(args, r, lambda r: print(f"{args.cmd}: session {r['id']} is now {r['state']}."))


_FIX_RE = re.compile(r"(scapegoat net \S.*?--confirm)")


def _err(section):
    return isinstance(section, dict) and "error" in section


def _yn(v):
    return "yes" if v is True else "no" if v is False else "?"


def _print_net(snap):
    """Human view of the network snapshot. --json gives the raw snapshot."""
    if not isinstance(snap, dict):
        print(snap)
        return
    hints = snap.get("hints") or []
    if hints:
        print("FIX THESE FIRST")
        for n, h in enumerate(hints, 1):
            h = str(h)
            fixes = _FIX_RE.findall(h)
            text = _FIX_RE.sub("(command below)", h) if fixes else h
            print(f"  {n}. {text}")
            for f in fixes:
                print(f"       {f}")
        print()
    else:
        print("No problems found by the network checks.\n")

    topo = snap.get("topology")
    if isinstance(topo, dict) and topo.get("mode"):
        print(f"Topology: {TOPOLOGY_TEXT.get(topo['mode'], topo['mode'])}; "
              f"from {topo.get('source', '?')}")
        if topo.get("note"):
            print(f"  note: {topo['note']}")
        print()
    el = snap.get("expected_local")
    if isinstance(el, dict) and el.get("cidr"):
        if el.get("present"):
            print(f"Node address: [OK] {el['cidr']} present on {', '.join(el.get('on') or [])}")
        else:
            other = ", ".join(f"{o.get('iface')} {o.get('cidr')}" for o in el.get("other_prefix") or [])
            print(f"Node address: [!]  {el['cidr']} MISSING" + (f" (has {other})" if other else ""))
        print()

    ifaces = snap.get("interfaces")
    print("INTERFACES")
    if _err(ifaces):
        print(f"  not available: {ifaces['error']}")
    elif isinstance(ifaces, list):
        rows, hidden = [], 0
        for i in ifaces:
            addrs = [a.get("cidr") for a in i.get("addresses") or []
                     if a.get("cidr") and not str(a.get("cidr")).lower().startswith("fe80")]
            if not addrs and not (i.get("admin_up") and i.get("carrier")):
                hidden += 1
                continue
            state = "up" if i.get("admin_up") else "down" if i.get("admin_up") is False else "?"
            rows.append([i.get("name", "?"), state, _yn(i.get("carrier")),
                         ", ".join(addrs) or "-"])
        if rows:
            print("  " + _table(rows, ["IFACE", "ADMIN", "CABLE", "ADDRESSES"]).replace("\n", "\n  "))
        if hidden:
            print(f"  ({hidden} more without addresses; --json shows all)")
    print()

    sessions = snap.get("sessions")
    print("SENSOR ADDRESSES")
    if _err(sessions):
        print(f"  not available: {sessions['error']}")
    elif isinstance(sessions, list):
        rows, listen = [], []
        for s in sessions:
            sid = s.get("id", "?")
            if s.get("error"):
                rows.append([sid, "-", "-", "-", f"error: {s['error']}"])
                continue
            peers = s.get("peers") or ([{"ip": s.get("peer_ip"), "port": s.get("peer_port"),
                                         "same_subnet": s.get("same_subnet"),
                                         "route": s.get("route"),
                                         "neighbor": s.get("neighbor")}] if s.get("peer_ip") else [])
            for p in peers:
                ss = p.get("same_subnet") or []
                same = ("yes, " + ", ".join(f"{m.get('iface')} {m.get('cidr')}" for m in ss)
                        if ss else "NO")
                r = p.get("route") or {}
                if _err(r):
                    route = "error"
                else:
                    route = f"via {r.get('iface') or '?'}" + (f" gw {r['gateway']}" if r.get("gateway") else "")
                nb = p.get("neighbor") or {}
                st = nb.get("state") or []
                neigh = (" ".join(st) if isinstance(st, list) else str(st)) + (f" {nb['mac']}" if nb.get("mac") else "")
                rows.append([sid, f"{p.get('ip')}:{p.get('port')}", same, route, neigh or "?"])
            ls = s.get("listeners")
            if isinstance(ls, list):
                who = ", ".join(f"{x.get('local')}:{x.get('port')}" + (f" ({x['process']})" if x.get("process") else "")
                                for x in ls) or "NONE"
                listen.append(f"  {sid}: UDP port {s.get('local_port', '?')} listeners: {who}")
        if rows:
            print("  " + _table(rows, ["SESSION", "PEER", "SAME SUBNET", "ROUTE", "NEIGHBOR"]).replace("\n", "\n  "))
        for line in listen:
            print(line)
        for s in sessions:
            for n_ in s.get("notes") or []:
                print(f"  note ({s.get('id', '?')}): {n_}")
    print()

    fw = snap.get("firewall")
    if isinstance(fw, dict):
        tool = fw.get("tool") or "none"
        if fw.get("error"):
            line = f"{tool}: could not read ({fw['error']})"
        elif fw.get("note"):
            line = f"{tool}: {fw['note']}"
        else:
            line = f"{tool}: {'active' if fw.get('active') else 'inactive'}"
            if fw.get("default_incoming"):
                line += f", default incoming {fw['default_incoming']}"
            rules = fw.get("port_rules") or []
            line += f"; rules for the port: {'; '.join(rules[:4]) if rules else 'none'}"
        print(f"FIREWALL  {line}")


def _print_net_result(r):
    """Human view of a ping / capture / control result; unknown shapes print as JSON."""
    if not isinstance(r, dict):
        print(r)
        return
    if "reachable" in r:  # ping
        rtt = f", average {r['rtt_avg_ms']} ms" if r.get("rtt_avg_ms") is not None else ""
        print(f"{r.get('ip')}: {'REACHABLE' if r['reachable'] else 'NOT reachable'} "
              f"({r.get('received', '?')}/{r.get('sent', '?')} replies{rtt})")
        if r.get("error"):
            print(f"  {r['error']}")
        return
    if "packets" in r:  # capture
        print(f"{r.get('count', len(r['packets']))} packets in {r.get('seconds', '?')} s")
        for p in r["packets"]:
            if isinstance(p, dict):
                print(f"  {p.get('time', '')}  {p.get('src', '?')} > {p.get('dst', '?')}  "
                      f"{p.get('length', '?')} bytes")
            else:
                print(f"  {p}")
        if r.get("error"):
            print(f"  problem: {r['error']}")
        return
    if "ok" in r and ("command" in r or "message" in r):  # control action
        print(("Done: " if r.get("ok") else "FAILED: ") + str(r.get("message") or r.get("action") or ""))
        cmd = r.get("command")
        if cmd:
            print("  ran: " + (" ".join(map(str, cmd)) if isinstance(cmd, list) else str(cmd)))
        for k in ("stdout", "stderr"):
            if r.get(k):
                print(f"  {k}: " + str(r[k]).strip().replace("\n", "\n          "))
        return
    print(json.dumps(r, indent=2, default=str))


def cmd_net(args):
    act = args.net_action or "show"
    if act == "show":
        node = _node(args.api)
        snap = call(args.api, "GET", "/api/net", timeout=30)
        if args.json:
            print(json.dumps(dict(snap, node=node) if isinstance(snap, dict) else snap,
                             indent=2, default=str))
        else:
            if node:
                print("THIS NODE")
                print_node(node, indent="  ")
                print()
            _print_net(snap)
        return
    if act == "ping":
        r = call(args.api, "POST", "/api/net/ping", {"ip": args.ip, "count": args.count},
                 timeout=30)
    elif act == "capture":
        body = {"port": args.port, "seconds": args.seconds}
        if args.iface:
            body["iface"] = args.iface
        r = call(args.api, "POST", "/api/net/capture", body, timeout=args.seconds + 20)
    else:
        body = {k: getattr(args, k) for k in ("iface", "cidr", "from_cidr", "port")
                if getattr(args, k, None) is not None}
        body["confirm"] = bool(args.confirm)
        r = call(args.api, "POST", f"/api/net/{act}", body, timeout=30)
    emit(args, r, _print_net_result)


def cmd_sim(args, rest):
    from .core import plugins
    try:
        main = plugins.simulator_main(args.which)
    except (plugins.PluginError, ImportError) as exc:
        raise CliError(str(exc))
    return main(rest)


# ---------------------------------------------------------------- parser
def build_parser():
    # --api / --json work before or after the command: the top-level parser holds the
    # defaults, the per-command copies use SUPPRESS so they never overwrite them.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--api", default=argparse.SUPPRESS, metavar="URL",
                        help=f"address of the scapegoat service (default {DEFAULT_API})")
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="print raw JSON instead of text")

    p = argparse.ArgumentParser(
        prog="scapegoat",
        description="scapegoat plays the C2 side of a sensor link so the sensor starts "
                    "sending data. Run `scapegoat serve` as the service; the other "
                    "commands talk to the running service.",
        epilog="Examples:\n  scapegoat status\n  scapegoat events sensor -n 20\n"
               "  scapegoat action sensor request_keepalive\n  scapegoat net ping 192.0.2.81",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--api", default=DEFAULT_API, metavar="URL",
                   help=f"address of the scapegoat service (default {DEFAULT_API}; env SCAPEGOAT_API)")
    p.add_argument("--json", action="store_true", help="print raw JSON instead of text")
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")

    sp = sub.add_parser("serve", help="run the scapegoat service (normally started by systemd)",
                        description="Run the service: open one UDP socket per session, send "
                                    "keepalives, and serve the API and web page.")
    sp.add_argument("--config", default=None, metavar="PATH",
                    help=f"config file (default {DEFAULT_CONFIG}; env SCAPEGOAT_CONFIG)")
    sp.add_argument("--profile", metavar="NAME",
                    help="profile to layer the config over (overrides `profile` in the file); "
                         "list them with `scapegoat profiles`")
    sp.add_argument("--session", metavar="ID",
                    help="run only this one session from the config (one sensor per process)")
    sp.add_argument("--bind", metavar="IP:PORT", help="override the API address from the config")
    sp.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    sp = sub.add_parser("status", parents=[common], help="show every session's link state",
                        description="Show each session: state, peer, time since last "
                                    "receive/send, datagram counts. Give a session name "
                                    "for detail and per-message counts.")
    sp.add_argument("session", nargs="?", help="session name for detail (e.g. sensor)")

    sp = sub.add_parser("events", parents=[common], help="show recent events",
                        description="Show recent events: state changes, actions with who "
                                    "ran them, errors.")
    sp.add_argument("session", nargs="?", help="session name (default: all sessions)")
    sp.add_argument("-n", type=int, default=50, help="how many events (default 50)")

    sp = sub.add_parser("actions", parents=[common], help="list the manual triggers of a session",
                        description="List the manual triggers a session offers and whether "
                                    "each is allowed.")
    sp.add_argument("session", help="session name (e.g. sensor)")

    sp = sub.add_parser("action", parents=[common], help="send a manual trigger",
                        description="Send one manual trigger to the sensor. Triggers that "
                                    "command the sensor (actions the protocol marks dangerous) "
                                    "are locked: "
                                    "without --arm the command only says what it would do; "
                                    "with --arm it asks you to type the device ID (or give it "
                                    "with --confirm ID). One command per arm.",
                        epilog="Examples:\n  scapegoat action sensor request_keepalive\n"
                               "  scapegoat action sensor <dangerous-action> --arm --confirm <id>",
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    sp.add_argument("session", help="session name (e.g. sensor)")
    sp.add_argument("name", help="trigger name; list them with `scapegoat actions <session>`")
    sp.add_argument("values", nargs="*", help="the trigger's values, in order or name=value "
                                              "(e.g. <action> <value> <value>)")
    sp.add_argument("--arm", action="store_true",
                    help="unlock this one dangerous trigger and send it")
    sp.add_argument("--confirm", metavar="DEVICE_ID",
                    help="the device ID, for scripts (otherwise you are asked to type it)")

    for name, text in (("enable", "start a session (opens its socket, sends keepalives)"),
                       ("disable", "stop a session (closes its socket)"),
                       ("reset", "zero a session's counters and restart the handshake")):
        sp = sub.add_parser(name, parents=[common], help=text, description=text.capitalize() + ".")
        sp.add_argument("session", help="session name (e.g. sensor)")

    sp = sub.add_parser("watch", parents=[common], help="watch every message on a session live",
                        description="Follow every message the session sends, receives and "
                                    "forwards, one line each. Ctrl-C stops. With --wire, "
                                    "capture the session's UDP port from the network instead "
                                    "(also shows traffic scapegoat is not part of, e.g. a real "
                                    "scapegoat talking to the sensor; needs root).",
                        epilog="Arrows: -> sent by scapegoat, <- received, => forwarded copy, "
                               "~~ seen on the wire.  !! marks a message that failed checks.\n"
                               "Examples:\n  scapegoat watch sensor\n  scapegoat watch sensor --filter "
                               "Keep --fields\n  scapegoat watch sensor --wire",
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    sp.add_argument("session", help="session name (e.g. sensor)")
    sp.add_argument("--fields", action="store_true", help="print every decoded field")
    sp.add_argument("--hex", action="store_true", help="print the raw bytes in hex")
    sp.add_argument("--filter", metavar="NAME", help="only messages whose name contains NAME")
    sp.add_argument("--wire", action="store_true",
                    help="capture from the network (tcpdump) instead of the session log")
    sp.add_argument("--seconds", type=float, default=5,
                    help="with --wire: length of each capture round (default 5)")
    sp.add_argument("--last", type=int, default=20,
                    help="messages already in the log to show first (default 20)")
    sp.add_argument("--once", action="store_true", help=argparse.SUPPRESS)

    sp = sub.add_parser("lock", parents=[common], help="lock a session onto one sensor address",
                        description="Stop probing the other peer candidates and talk only to "
                                    "this address. `scapegoat reset <session>` undoes it.")
    sp.add_argument("session", help="session name (e.g. sensor)")
    sp.add_argument("peer", help="sensor address IP:PORT, e.g. 192.0.2.74:47000")

    sp = sub.add_parser("profiles", help="list the config profiles you can use",
                        description="List config profiles (installed in /etc/scapegoat/profiles "
                                    "and shipped with scapegoat) with what each is for.")
    sp.add_argument("--profiles-dir", "--profiles_dir", dest="profiles_dir", metavar="DIR", help="look here first "
                    "(default /etc/scapegoat/profiles)")
    sp.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                    help="print raw JSON instead of text")

    sp = sub.add_parser("net", parents=[common], help="network checks and fixes on this node",
                        description="Show the node's network (interfaces, neighbors, routes, "
                                    "peer reachability, listeners, firewall), ping, capture "
                                    "packets, or change the network. Changes need "
                                    "allow_net_control = true in the config AND --confirm.")
    nsub = sp.add_subparsers(dest="net_action", metavar="ACTION")
    nsub.add_parser("show", parents=[common], help="show the network snapshot (default)")
    np_ = nsub.add_parser("ping", parents=[common], help="ping an address from this node")
    np_.add_argument("ip", help="address to ping, e.g. the sensor address")
    np_.add_argument("--count", type=int, default=3, help="number of pings (default 3)")
    np_ = nsub.add_parser("capture", parents=[common],
                          help="capture UDP packets on a port for a few seconds")
    np_.add_argument("--seconds", type=int, default=10, help="how long (default 10)")
    np_.add_argument("--port", type=int, default=47000, help="UDP port (default 47000)")
    np_.add_argument("--iface", help="interface (default: all)")
    ctl_help = {
        "addr_add": ("add an IP address to an interface", ("iface", "cidr")),
        "addr_del": ("remove an IP address from an interface", ("iface", "cidr")),
        "link_up": ("bring an interface up", ("iface",)),
        "link_down": ("take an interface down", ("iface",)),
        "neigh_flush": ("flush the neighbor (ARP) table of an interface", ("iface",)),
        "fw_allow": ("allow UDP from a network to a port in the firewall",
                     ("iface", "from_cidr", "port")),
    }
    for act, (text, fields) in ctl_help.items():
        np_ = nsub.add_parser(act, parents=[common], help=text + " (needs --confirm)",
                              description=text.capitalize() + ". Needs allow_net_control = "
                                          "true in the config and --confirm.")
        for f in fields:
            if f == "port":
                np_.add_argument("--port", type=int, required=True, help="UDP port, e.g. 47000")
            else:
                flags = [f"--{f}"] + ([f"--{f.replace('_', '-')}"] if "_" in f else [])
                np_.add_argument(*flags, dest=f, required=True, help={
                    "iface": "interface name, e.g. eth0",
                    "cidr": "address with prefix, e.g. 192.0.2.10/24",
                    "from_cidr": "source network, e.g. 192.0.2.0/24"}[f])
        np_.add_argument("--confirm", action="store_true", help="confirm the change")

    sp = sub.add_parser("sim", help="run a sensor simulator (for tests and demos)",
                        description="Run a simulator: `toy` ships with scapegoat; protocol "
                                    "plugins add their own. `scapegoat sim toy --help` shows "
                                    "its options.")
    sp.add_argument("which", help="which simulator, e.g. toy")
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    p = build_parser()
    # `scapegoat sim <name> ...`: everything after the simulator name goes to it untouched.
    if len(argv) >= 2 and argv[0] == "sim" and not argv[1].startswith("-"):
        args, rest = p.parse_args(argv[:2]), argv[2:]
    else:
        args, rest = p.parse_args(argv), []
    if not args.cmd:
        p.print_help()
        return 2
    try:
        if args.cmd == "serve":
            return cmd_serve(args) or 0
        if args.cmd == "sim":
            return cmd_sim(args, rest) or 0
        if args.cmd == "profiles":
            cmd_profiles(args)
            return 0
        if args.cmd == "net" and not getattr(args, "net_action", None):
            args.net_action = "show"
        handler = {"status": cmd_status, "events": cmd_events, "actions": cmd_actions,
                   "action": cmd_action, "enable": cmd_lifecycle, "disable": cmd_lifecycle,
                   "reset": cmd_lifecycle, "net": cmd_net, "lock": cmd_lock,
                   "watch": cmd_watch}[args.cmd]
        handler(args)
        return 0
    except CliError as exc:
        print(f"scapegoat: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
