"""Network control actions for the field: add an address, bring a link up, allow the port.

Safety rule: every action marked dangerous is refused unless the config sets
allow_net_control = true AND the caller passes confirm = true. Arguments are validated before
anything runs; commands are argument lists, never a shell. Every call, refused or run, goes
into an in-memory audit log (last 200) with the exact command and its output.
"""

from __future__ import annotations

import collections
import threading
import time

from . import _common as c
from . import probe

ACTIONS = {
    "addr_add": {"label": "Add address", "dangerous": True, "args": ["iface", "cidr"],
                 "description": "Add an IP address with prefix to an interface "
                                "(ip addr add <cidr> dev <iface>). Put scapegoat in the sensor's subnet."},
    "addr_del": {"label": "Remove address", "dangerous": True, "args": ["iface", "cidr"],
                 "description": "Remove an IP address from an interface (ip addr del <cidr> dev <iface>)."},
    "link_up": {"label": "Link up", "dangerous": True, "args": ["iface"],
                "description": "Bring an interface administratively up (ip link set dev <iface> up)."},
    "link_down": {"label": "Link down", "dangerous": True, "args": ["iface"],
                  "description": "Take an interface down (ip link set dev <iface> down). "
                                 "Cuts every connection on it, including yours if you came in that way."},
    "neigh_flush": {"label": "Flush ARP", "dangerous": True, "args": ["iface"],
                    "description": "Forget learned neighbor/ARP entries on an interface "
                                   "(ip neigh flush dev <iface>), e.g. after the sensor was swapped."},
    "fw_allow": {"label": "Allow UDP port", "dangerous": True, "args": ["iface", "from_cidr", "port"],
                 "description": "Allow incoming UDP to a port from a network on an interface "
                                "(ufw allow in on <iface> from <cidr> to any port <port> proto udp)."},
    "ping": {"label": "Ping", "dangerous": False, "args": ["ip", "count"],
             "description": "Send ICMP echo to an address and report replies and round-trip time."},
    "capture": {"label": "Capture", "dangerous": False, "args": ["port", "seconds", "iface"],
                "description": "Watch UDP packets on a port for a few seconds (tcpdump); sends nothing."},
}

_AUDIT = collections.deque(maxlen=200)
_LOCK = threading.Lock()


def audit_log():
    """Newest last. Each entry: time, action, args, command, ok, returncode, message."""
    with _LOCK:
        return list(_AUDIT)


def _result(ok, action, command=None, stdout="", stderr="", returncode=None, message=""):
    return {"ok": ok, "action": action, "command": command or [], "stdout": stdout,
            "stderr": stderr, "returncode": returncode, "message": message}


def _record(res, args):
    entry = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "action": res["action"],
             "args": {k: v for k, v in (args or {}).items() if k != "confirm"},
             "command": res["command"], "ok": res["ok"], "returncode": res["returncode"],
             "message": res["message"], "stdout": (res.get("stdout") or "")[-2000:],
             "stderr": (res.get("stderr") or "")[-2000:]}
    with _LOCK:
        _AUDIT.append(entry)


def build_command(name, args):
    """Validate args and return the exact command list. Raises ValidationError."""
    a = args or {}

    def need(key):
        if a.get(key) in (None, ""):
            raise c.ValidationError(f"{name} needs '{key}'")
        return a[key]

    if name in ("addr_add", "addr_del"):
        iface = c.validate_iface(need("iface"))
        cidr = c.validate_iface_cidr(need("cidr"))
        return ["ip", "addr", "add" if name == "addr_add" else "del", cidr, "dev", iface]
    if name in ("link_up", "link_down"):
        iface = c.validate_iface(need("iface"))
        return ["ip", "link", "set", "dev", iface, "up" if name == "link_up" else "down"]
    if name == "neigh_flush":
        iface = c.validate_iface(need("iface"))
        return ["ip", "neigh", "flush", "dev", iface]
    if name == "fw_allow":
        iface = c.validate_iface(need("iface"))
        net = c.validate_network(need("from_cidr"))
        port = c.validate_port(need("port"))
        return ["ufw", "allow", "in", "on", iface, "from", net, "to", "any",
                "port", str(port), "proto", "udp"]
    raise c.ValidationError(f"unknown action {name!r}")


def run(name, args, config):
    """Run one action. -> {ok, action, command, stdout, stderr, returncode, message}
    (ping/capture add 'result' with the probe's own dict)."""
    args = dict(args or {})
    if name not in ACTIONS:
        res = _result(False, name, message=f"unknown action {name!r}; known: {', '.join(ACTIONS)}")
        _record(res, args)
        return res
    spec = ACTIONS[name]

    if not spec["dangerous"]:
        try:
            if name == "ping":
                r = probe.ping(c.validate_ip(args.get("ip")), args.get("count", 3))
                msg = (f"{r['ip']}: {r['received']}/{r['sent']} replies"
                       + (f", avg {r['rtt_avg_ms']} ms" if r.get("rtt_avg_ms") is not None else "")
                       + (f" ({r['error']})" if r.get("error") else ""))
                res = _result(r.get("reachable", False), name, r.get("command"),
                              "\n".join(r.get("output_tail", [])), r.get("error", ""),
                              0 if r.get("reachable") else 1, msg)
            else:
                r = probe.capture(args.get("port", 47000), args.get("seconds", 10),
                                  args.get("iface"), args.get("max_packets", 200))
                msg = r.get("error") or r.get("note") or f"{r['count']} packets"
                res = _result("error" not in r, name, r.get("command"), "", r.get("error", ""),
                              0 if "error" not in r else 1, msg)
            res["result"] = r
        except c.ValidationError as exc:
            res = _result(False, name, message=f"refused: {exc}")
        _record(res, args)
        return res

    # dangerous: validate first, so a bad argument is reported even when not allowed
    try:
        cmd = build_command(name, args)
    except c.ValidationError as exc:
        res = _result(False, name, message=f"refused: {exc}")
        _record(res, args)
        return res
    if not c.truthy(c._get(config, "allow_net_control", False)):
        res = _result(False, name, cmd, message=(
            "refused: network control is off on this node. Set allow_net_control = true in "
            "/etc/scapegoat/scapegoat.toml and restart scapegoat to allow it."))
        _record(res, args)
        return res
    if not c.truthy(args.get("confirm")):
        res = _result(False, name, cmd, message=(
            f"refused: {spec['label']} changes this node's network. Re-run with confirm "
            f"(--confirm) to run: {' '.join(cmd)}"))
        _record(res, args)
        return res
    if not c.have(cmd[0]):
        res = _result(False, name, cmd, returncode=127,
                      message=f"{cmd[0]} is not installed on this node")
        _record(res, args)
        return res
    rc, out, err = c.run_cmd(cmd, timeout=10)
    ok = rc == 0
    msg = f"done: {' '.join(cmd)}" if ok else f"failed (exit {rc}): {(err or out).strip()}"
    if not ok and ("Operation not permitted" in err or "need to be root" in err):
        msg += " — scapegoat must run as root to change the network"
    res = _result(ok, name, cmd, out, err, rc, msg)
    _record(res, args)
    return res
