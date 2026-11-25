"""Read-only check: does this node hold the expected local address?

Used for the one-line check in `scapegoat status` and the web page header.
Never changes anything. Linux: `ip -j addr`. macOS: `ifconfig`.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import threading
import time

_CACHE = {"t": 0.0, "key": None, "val": None}
_LOCK = threading.Lock()
CACHE_S = 10.0


def _addresses() -> list:
    """[(iface, ip_interface)] for every IPv4/IPv6 address on the node."""
    out = []
    if shutil.which("ip"):
        r = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=3)
        for i in json.loads(r.stdout or "[]"):
            for a in i.get("addr_info", []):
                try:
                    out.append((i.get("ifname", "?"),
                                ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}")))
                except (KeyError, ValueError):
                    pass
        return out
    if shutil.which("ifconfig"):
        r = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3)
        iface = "?"
        for line in r.stdout.splitlines():
            m = re.match(r"^([A-Za-z0-9_.\-]+):", line)
            if m:
                iface = m.group(1)
            m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", line)
            if m:
                prefix = bin(int(m.group(2), 16)).count("1")
                out.append((iface, ipaddress.ip_interface(f"{m.group(1)}/{prefix}")))
        return out
    raise RuntimeError("neither `ip` nor `ifconfig` is available")


def check(cidr: str) -> dict | None:
    """{cidr, present, on: [iface], other_prefix: [iface cidr], error?, text} or None if unset."""
    if not cidr:
        return None
    with _LOCK:
        if _CACHE["key"] == cidr and time.monotonic() - _CACHE["t"] < CACHE_S:
            return _CACHE["val"]
        try:
            want = ipaddress.ip_interface(cidr)
        except ValueError:
            val = {"cidr": cidr, "present": False, "on": [], "other_prefix": [],
                   "error": "not a valid address/prefix",
                   "text": f"expected_local_address {cidr!r} is not a valid address/prefix"}
        else:
            try:
                addrs = _addresses()
                on = [i for i, a in addrs if a == want]
                other = [f"{i} {a}" for i, a in addrs if a.ip == want.ip and a != want]
                val = {"cidr": str(want), "present": bool(on), "on": on, "other_prefix": other}
                if on:
                    val["text"] = f"{want} present on {', '.join(on)}"
                elif other:
                    val["text"] = f"{want} MISSING (this node has {', '.join(other)}: prefix differs)"
                else:
                    val["text"] = f"{want} MISSING on every interface (see: scapegoat net)"
            except Exception as exc:
                val = {"cidr": str(want), "present": None, "on": [], "other_prefix": [],
                       "error": str(exc), "text": f"{want}: could not check ({exc})"}
        _CACHE.update(t=time.monotonic(), key=cidr, val=val)
        return val
