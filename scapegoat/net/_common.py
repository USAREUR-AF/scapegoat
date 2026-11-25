"""Shared helpers for scapegoat.net: config access, safe subprocess, argument validation.

Every external command goes through run_cmd(): a list of arguments, never a shell, always a
timeout. Every user-supplied value is checked by one of the validate_* functions before it
reaches a command line.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import time

IFACE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,15}$")


class ValidationError(ValueError):
    """An argument failed validation; nothing was run."""


def _get(cfg, key, default=None):
    """Read key from a dict or an object with attributes."""
    if cfg is None:
        return default
    if isinstance(cfg, dict):
        return cfg.get(key, default)
    return getattr(cfg, key, default)


def truthy(value) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1")
    if isinstance(value, int) and not isinstance(value, bool):
        return value == 1
    return False


def iter_sessions(config):
    """Yield (session_id, session_cfg) from config['sessions'] (dict or list)."""
    sessions = _get(config, "sessions", None) or {}
    if isinstance(sessions, dict):
        for sid, s in sessions.items():
            yield str(sid), s
    elif isinstance(sessions, (list, tuple)):
        for i, s in enumerate(sessions):
            sid = _get(s, "id", None) or _get(s, "name", None) or str(i)
            yield str(sid), s


def split_hostport(text):
    """'192.0.2.81:47000' -> ('192.0.2.81', 47000). '[v6]:port' supported."""
    if text is None:
        raise ValidationError("missing address")
    text = str(text).strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest.lstrip(":")
    else:
        host, sep, port = text.rpartition(":")
        if not sep:
            host, port = text, ""
    ip = validate_ip(host)
    return ip, (validate_port(port) if port else None)


# ---- subprocess ---------------------------------------------------------------------------

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run_cmd(args, timeout=3.0):
    """Run a command (list of str). Returns (returncode, stdout, stderr). Never raises for a
    missing binary or a timeout: returncode is 127 / 124 and stderr says why."""
    if not isinstance(args, (list, tuple)) or not all(isinstance(a, str) for a in args):
        raise TypeError("run_cmd needs a list of strings")
    try:
        p = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", f"{args[0]}: command not found"
    except subprocess.TimeoutExpired as exc:
        return 124, _text(exc.stdout), (_text(exc.stderr) + f"\ntimed out after {timeout}s").strip()
    except OSError as exc:
        return 126, "", f"{args[0]}: {exc}"


def _text(v):
    if v is None:
        return ""
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return v


def run_json(args, timeout=3.0):
    rc, out, err = run_cmd(args, timeout)
    if rc != 0:
        raise RuntimeError((err or out or f"exit {rc}").strip())
    try:
        return json.loads(out or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"could not parse output of {' '.join(args)}: {exc}")


def read_sys(path: str):
    """Read a small /sys file; None if absent."""
    try:
        with open(path, "r", encoding="ascii", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return None


def list_interfaces():
    """Names of interfaces that exist on this host."""
    try:
        return sorted(name for _, name in socket.if_nameindex())
    except OSError:
        try:
            return sorted(os.listdir("/sys/class/net"))
        except OSError:
            return []


# ---- validation ---------------------------------------------------------------------------

def validate_iface(name, existing=None):
    if not isinstance(name, str) or not IFACE_RE.match(name):
        raise ValidationError(f"interface name {name!r} is not valid")
    names = list_interfaces() if existing is None else existing
    if name not in names:
        raise ValidationError(
            f"no interface called {name!r} on this host (have: {', '.join(names) or 'none'})")
    return name


def validate_ip(text):
    try:
        return str(ipaddress.ip_address(str(text).strip()))
    except ValueError:
        raise ValidationError(f"{text!r} is not an IP address")


def validate_iface_cidr(text):
    """Address with prefix for an interface, e.g. 192.0.2.10/24. Prefix required."""
    if not isinstance(text, str) or "/" not in text:
        raise ValidationError(f"{text!r} must be an address with a prefix, e.g. 192.0.2.10/24")
    try:
        return str(ipaddress.ip_interface(text.strip()))
    except ValueError:
        raise ValidationError(f"{text!r} is not a valid address/prefix")


def validate_network(text):
    """A network or single address, e.g. 192.0.2.0/24 or 192.0.2.81."""
    if not isinstance(text, str):
        raise ValidationError(f"{text!r} is not a network")
    try:
        return str(ipaddress.ip_network(text.strip(), strict=False))
    except ValueError:
        raise ValidationError(f"{text!r} is not a valid network, e.g. 192.0.2.0/24")


def validate_port(value):
    try:
        if isinstance(value, bool):
            raise ValueError
        port = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValidationError(f"port {value!r} is not a number")
    if not 1 <= port <= 65535:
        raise ValidationError(f"port {port} is outside 1-65535")
    return port


def validate_int(value, name, lo, hi):
    try:
        if isinstance(value, bool):
            raise ValueError
        n = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValidationError(f"{name} {value!r} is not a number")
    if not lo <= n <= hi:
        raise ValidationError(f"{name} {n} is outside {lo}-{hi}")
    return n


class Deadline:
    def __init__(self, seconds):
        self.end = time.monotonic() + seconds

    def left(self, cap=2.0, floor=0.3):
        return max(floor, min(cap, self.end - time.monotonic()))

    def expired(self):
        return time.monotonic() >= self.end
