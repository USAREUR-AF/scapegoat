"""Traffic entries (what the session sent and received) and wire capture.

Entry shape, shared by the session log and wire mode:
  {seq, time, ts, direction "rx"|"tx"|"fwd"|"wire", peer "ip:port", length,
   name, ok, problems, fields, hex}  (+ src, dst for wire entries)
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone

MAX_WIRE_SECONDS = 60
MAX_WIRE_PACKETS = 2000


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def json_safe(v, depth=0):
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).hex()
    if depth > 4:
        return str(v)
    if isinstance(v, dict):
        return {str(k): json_safe(x, depth + 1) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [json_safe(x, depth + 1) for x in v]
    return str(v)


def make_entry(direction: str, peer: str, data: bytes, msg, ts: float | None = None) -> dict:
    ts = time.time() if ts is None else ts
    return {
        "time": _iso(ts), "ts": ts, "direction": direction, "peer": peer,
        "length": len(data),
        "name": (getattr(msg, "name", None) or "unknown") if msg is not None else "unknown",
        "ok": bool(getattr(msg, "ok", False)),
        "problems": [str(p) for p in (getattr(msg, "problems", None) or [])],
        "fields": json_safe(getattr(msg, "fields", None) or {}),
        "hex": bytes(data).hex(),
    }


# --------------------------------------------------------------- tcpdump -x parsing
_TS = re.compile(r"^\d\d:\d\d:\d\d\.\d+\s")
_ICMP_UNREACH = re.compile(
    r"\bIP (\S+) > (\S+): ICMP (?:(?:host|net) )?(\S+?) (?:udp port \d+ )?unreachable")
_HEAD = re.compile(r"^(\d\d:\d\d:\d\d\.\d+)\s.*?\bIP6?\s+(\S+)\.(\d+)\s+>\s+(\S+)\.(\d+):")
_HEXLINE = re.compile(r"^\s+0x[0-9a-fA-F]+:\s+((?:[0-9a-fA-F]{2,4}\s?)+)")


def udp_payload(packet: bytes) -> bytes | None:
    """IP packet (no link header, as `tcpdump -x` prints) -> UDP payload, or None."""
    if not packet:
        return None
    ver = packet[0] >> 4
    if ver == 4:
        ihl = (packet[0] & 0x0F) * 4
        if len(packet) < ihl + 8 or packet[9] != 17:
            return None
        off = ihl
    elif ver == 6:
        if len(packet) < 48 or packet[6] != 17:
            return None
        off = 40
    else:
        return None
    ulen = int.from_bytes(packet[off + 4:off + 6], "big")
    payload = packet[off + 8:]
    if ulen >= 8:
        payload = payload[:ulen - 8]
    return payload


def parse_tcpdump_x(text: str) -> list:
    """Parse `tcpdump -nn -x` output into [{time, src, dst, payload}]."""
    out, cur, hexbuf = [], None, []

    def flush():
        if cur is not None:
            try:
                pkt = bytes.fromhex("".join(hexbuf))
            except ValueError:
                pkt = b""
            p = udp_payload(pkt)
            if p is not None:
                out.append(dict(cur, payload=p))

    for line in text.splitlines():
        m = _HEAD.match(line)
        if m:
            flush()
            cur = {"time": m.group(1), "src": f"{m.group(2)}:{m.group(3)}",
                   "dst": f"{m.group(4)}:{m.group(5)}"}
            hexbuf = []
            continue
        if _TS.match(line):  # another packet (ICMP, no ports): its hex is not ours
            flush()
            cur, hexbuf = None, []
            continue
        h = _HEXLINE.match(line)
        if h and cur is not None:
            hexbuf.append(h.group(1).replace(" ", ""))
    flush()
    return out


def icmp_unreachable(text: str) -> list:
    """[{router, target, hint}] for each distinct ICMP unreachable in tcpdump -nn output."""
    out, seen = [], set()
    for line in (text or "").splitlines():
        m = _ICMP_UNREACH.search(line)
        if m and (m.group(1), m.group(3)) not in seen:
            seen.add((m.group(1), m.group(3)))
            out.append({"router": m.group(1), "target": m.group(3), "line": line.strip(),
                        "hint": f"The router {m.group(1)} cannot find the sensor at {m.group(3)}: "
                                "the sensor link not enabled, wrong address, or the sensor not on that "
                                "segment."})
    return out


def wire_capture(port: int, seconds: float, iface: str = "any") -> tuple:
    """Run tcpdump for `seconds` on UDP `port`. -> (packets, error_text_or_empty)."""
    tcpdump = shutil.which("tcpdump") or ("/usr/sbin/tcpdump" if shutil.which("/usr/sbin/tcpdump")
                                          else None)
    if not tcpdump:
        return [], "tcpdump is not installed (apt install tcpdump)"
    seconds = max(1.0, min(float(seconds), MAX_WIRE_SECONDS))
    cmd = [tcpdump, "-nn", "-l", "-x", "-c", str(MAX_WIRE_PACKETS)]
    if not (iface == "any" and platform.system() == "Darwin"):  # macOS has no "any"
        cmd += ["-i", iface]
    cmd += ["udp", "port", str(int(port)), "or", "icmp"]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError as exc:
        return [], f"cannot run tcpdump: {exc}"
    try:
        out, err = p.communicate(timeout=seconds)
    except subprocess.TimeoutExpired:
        p.terminate()
        try:
            out, err = p.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
    packets = parse_tcpdump_x(out or "")
    unreach = icmp_unreachable(out or "")
    if unreach:
        packets = packets + [{"icmp_unreachable": u} for u in unreach]
    error = ""
    if not packets and p.returncode not in (0, None, -15) and err:
        lines = [x for x in err.strip().splitlines() if "listening on" not in x]
        if lines:
            error = lines[-1]
            if "ermission" in error or "not permitted" in error:
                error += " (wire capture needs root: the systemd service runs as root)"
    return packets, error
