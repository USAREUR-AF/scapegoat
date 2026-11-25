"""This node's own addresses, each with a plain role label. Read-only and fast.

Linux: `ip -j addr` and `ip -j route` only, cached 2 s. macOS (development): ifconfig and
`route -n get default`. Billie identity is read from files when they are readable.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
import subprocess
import threading
import time

CACHE_S = 2.0
MESH_NET = ipaddress.ip_network("100.64.0.0/10")  # release-allow: the CGNAT range constant
BILLIE_IDENTITY = "/etc/billie/identity/node.yml"
BILLIE_FABRIC = "/etc/billie/zenoh/fabric.json"
ROLE_ORDER = ["sensor LAN", "NetBird mesh", "wired", "Wi-Fi", "Billie containers", "other",
              "loopback"]

_cache = {"t": 0.0, "key": None, "val": None}
_lock = threading.Lock()


def _run(args) -> str:
    r = subprocess.run(args, capture_output=True, text=True, timeout=2)
    return r.stdout


# ------------------------------------------------------------------ parsing (testable)
def parse_ip_addr(text: str) -> list:
    """`ip -j addr` -> [{iface, cidr, ip, family, link, cable}]."""
    rows = []
    for i in json.loads(text or "[]"):
        flags = i.get("flags") or []
        oper = (i.get("operstate") or "").upper()
        admin_up = "UP" in flags
        cable = True if "LOWER_UP" in flags else False if "NO-CARRIER" in flags or oper == "DOWN" else None
        link = "up" if admin_up and (cable or oper == "UP" or oper == "UNKNOWN") else "down" if not admin_up else "no cable"
        for a in i.get("addr_info") or []:
            try:
                ifc = ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}")
            except (KeyError, ValueError):
                continue
            rows.append({"iface": i.get("ifname", "?"), "cidr": str(ifc), "ip": str(ifc.ip),
                         "family": "ipv4" if ifc.version == 4 else "ipv6",
                         "link": link, "cable": cable})
    return rows


def parse_ip_route(text: str) -> list:
    """`ip -j route` -> default routes [{iface, gateway, metric}], lowest metric first."""
    out = []
    for r in json.loads(text or "[]"):
        if r.get("dst") == "default":
            out.append({"iface": r.get("dev"), "gateway": r.get("gateway"),
                        "metric": r.get("metric", 0), "src": r.get("prefsrc")})
    return sorted(out, key=lambda r: r["metric"] or 0)


def parse_ifconfig(text: str) -> list:
    rows, iface, up, active = [], "?", False, None
    pending = []

    def close():
        for r in pending:
            r["cable"] = active
            r["link"] = "up" if up and active is not False else "down" if not up else "no cable"
        rows.extend(pending)

    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+): flags=\d+<([^>]*)>", line)
        if m:
            close()
            iface, up, active, pending = m.group(1), "UP" in m.group(2).split(","), None, []
            continue
        m = re.search(r"\binet (\S+) netmask (0x[0-9a-fA-F]+)", line)
        if m:
            ifc = ipaddress.ip_interface(f"{m.group(1)}/{bin(int(m.group(2), 16)).count('1')}")
            pending.append({"iface": iface, "cidr": str(ifc), "ip": str(ifc.ip), "family": "ipv4"})
        m = re.search(r"\binet6 ([0-9a-fA-F:]+)(?:%\S+)? prefixlen (\d+)", line)
        if m:
            ifc = ipaddress.ip_interface(f"{m.group(1)}/{m.group(2)}")
            pending.append({"iface": iface, "cidr": str(ifc), "ip": str(ifc.ip), "family": "ipv6"})
        m = re.search(r"^\s+status: (\w+)", line)
        if m:
            active = m.group(1) == "active"
    close()
    return rows


def role_of(row: dict, sensor_ips: list, expected: str = "") -> str:
    iface, ip = row["iface"], ipaddress.ip_interface(row["cidr"])
    if ip.ip.is_loopback or iface.startswith("lo"):
        return "loopback"
    if expected:
        try:
            if ip == ipaddress.ip_interface(expected):
                return "sensor LAN"
        except ValueError:
            pass
    for r in sensor_ips:
        try:
            if ipaddress.ip_address(r) in ip.network and ip.network.prefixlen > 0:
                return "sensor LAN"
        except ValueError:
            pass
    if iface == "wt0" or (ip.version == 4 and ip.ip in MESH_NET):
        return "NetBird mesh"
    if iface.startswith("podman"):
        return "Billie containers"
    if iface.startswith("wl"):
        return "Wi-Fi"
    if re.match(r"^(eth|en|end)", iface):
        return "wired"
    return "other"


def read_billie(identity_path: str = BILLIE_IDENTITY, fabric_path: str = BILLIE_FABRIC):
    out = {}
    try:
        with open(identity_path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"^\s*node_handle\s*:\s*['\"]?([^'\"#\s]+)", line)
                if m:
                    out["node_handle"] = m.group(1)
                    break
    except OSError:
        pass
    try:
        with open(fabric_path, encoding="utf-8") as f:
            fab = json.load(f)
        stack = [fab]
        while stack:
            d = stack.pop()
            if isinstance(d, dict):
                for k in ("billie_fabric_prefix", "billie_fabric_endpoint", "node_handle"):
                    if k in d and k not in out and isinstance(d[k], (str, int)):
                        out[k] = d[k]
                stack.extend(v for v in d.values() if isinstance(v, dict))
    except (OSError, ValueError):
        pass
    return out or None


def build(rows: list, defaults: list, sensor_ips: list, expected: str, hostname: str,
          billie, include_loopback: bool = False) -> dict:
    # Which address carries each default route: its src, else the first IPv4 address on
    # its interface. The lowest metric is THE default route; others are backups.
    route_note = {}
    for n, d in enumerate(defaults):
        src = d.get("src") or next((r["ip"] for r in rows if r["iface"] == d["iface"]
                                    and r["family"] == "ipv4"), None)
        if src and (d["iface"], src) not in route_note:
            route_note[(d["iface"], src)] = ("default route" if n == 0 else
                                             f"backup default (metric {d.get('metric', '?')})")
    out, hidden = [], 0
    for r in rows:
        if r["family"] == "ipv6" and ipaddress.ip_interface(r["cidr"]).ip.is_link_local:
            continue
        role = role_of(r, sensor_ips, expected)
        if role == "loopback" and not include_loopback:
            hidden += 1
            continue
        note = route_note.get((r["iface"], r["ip"]), "")
        row = dict(r, role=role, default_route=note == "default route", route_note=note)
        if role == "Wi-Fi":
            row["cable"] = None  # no cable on Wi-Fi: link up/down only
        out.append(row)
    out.sort(key=lambda r: (ROLE_ORDER.index(r["role"]), r["iface"], r["family"]))
    return {"hostname": hostname, "addresses": out, "default_route": defaults[0] if defaults else None,
            "loopback_hidden": hidden, "billie": billie}


# ------------------------------------------------------------------ live
def snapshot(config, include_loopback: bool = False) -> dict:
    sensor_ips = []
    for sc in getattr(config, "sessions", {}).values():
        try:
            sensor_ips += [a[0] for a in sc.candidate_addrs]
        except Exception:
            pass
    expected = getattr(config, "expected_local_address", "") or ""
    key = (tuple(sensor_ips), expected, include_loopback)
    with _lock:
        if _cache["key"] == key and time.monotonic() - _cache["t"] < CACHE_S:
            return _cache["val"]
        error = ""
        rows, defaults = [], []
        try:
            if shutil.which("ip"):
                rows = parse_ip_addr(_run(["ip", "-j", "addr"]))
                defaults = parse_ip_route(_run(["ip", "-j", "route"]))
            elif shutil.which("ifconfig"):
                rows = parse_ifconfig(_run(["ifconfig"]))
                rt = _run(["route", "-n", "get", "default"])
                m, g = re.search(r"interface: (\S+)", rt), re.search(r"gateway: (\S+)", rt)
                if m:
                    defaults = [{"iface": m.group(1), "gateway": g.group(1) if g else None,
                                 "metric": 0, "src": None}]
            else:
                error = "neither `ip` nor `ifconfig` is available"
        except Exception as exc:
            error = str(exc)
        get = config.get if hasattr(config, "get") else (lambda k, d=None: d)
        billie = read_billie(get("billie_identity_path", BILLIE_IDENTITY) or BILLIE_IDENTITY,
                             get("billie_fabric_path", BILLIE_FABRIC) or BILLIE_FABRIC)
        val = build(rows, defaults, sensor_ips, expected, socket.gethostname(), billie,
                    include_loopback)
        if error:
            val["error"] = error
        _cache.update(t=time.monotonic(), key=key, val=val)
        return val
