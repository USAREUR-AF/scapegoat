"""Read-only probes: ping, packet capture on a UDP port, and a route/neighbor check.

None of these send anything to the sensor's UDP port. ping sends ICMP echo only.
"""

from __future__ import annotations

import platform
import re

from . import _common as c
from . import visibility

# 12:00:01.123456 eth0  In  IP 192.0.2.81.47000 > 192.0.2.10.47000: UDP, length 16
# 12:00:01.123456 IP 192.0.2.81.47000 > 192.0.2.10.47000: UDP, length 16
# 1700000000.123456 IP6 fe80::1.47000 > fe80::2.47000: UDP, length 16
_TCPDUMP_RE = re.compile(
    r"^(?P<time>\d{1,2}:\d{2}:\d{2}\.\d+|\d+\.\d+)\s+"
    r"(?:(?P<iface>[A-Za-z0-9_.\-]+)\s+(?P<dir>In|Out|M|P|B|\S+)\s+)?"
    r"(?P<proto>IP6?|ARP)\s+"
    r"(?P<src>\S+?)\s+>\s+(?P<dst>\S+?):\s*"
    r"(?P<rest>.*)$")
_LEN_RE = re.compile(r"length[:\s]+(\d+)")


def _split_endpoint(text):
    """'192.0.2.81.47000' -> ('192.0.2.81', 47000); IPv6 'fe80::1.47000' too."""
    host, dot, port = text.rpartition(".")
    if dot and port.isdigit():
        return host, int(port)
    return text, None


def parse_tcpdump_line(line):
    """Parse one tcpdump -nn line. Returns dict or None for lines that are not packets."""
    line = line.rstrip()
    m = _TCPDUMP_RE.match(line)
    if not m:
        return None
    if m.group("rest").lstrip().startswith("ICMP"):  # no ports: whole addresses
        (src, sport), (dst, dport) = (m.group("src"), None), (m.group("dst"), None)
    else:
        src, sport = _split_endpoint(m.group("src"))
        dst, dport = _split_endpoint(m.group("dst"))
    lm = _LEN_RE.search(m.group("rest"))
    pkt = {"time": m.group("time"), "src": src, "src_port": sport, "dst": dst,
           "dst_port": dport, "length": int(lm.group(1)) if lm else None}
    if sport is None and dport is None:
        pkt["icmp"] = m.group("rest").strip()
    if m.group("iface"):
        pkt["iface"] = m.group("iface")
        pkt["direction"] = m.group("dir")
    return pkt


def parse_tcpdump(text, max_packets=200):
    pkts = []
    for line in (text or "").splitlines():
        p = parse_tcpdump_line(line)
        if p:
            pkts.append(p)
            if len(pkts) >= max_packets:
                break
    return pkts


def ping(ip, count=3, timeout_s=5):
    """ICMP echo. -> {reachable, sent, received, rtt_avg_ms, output_tail, command, error?}"""
    ip = c.validate_ip(ip)
    count = c.validate_int(count, "count", 1, 20)
    timeout_s = c.validate_int(timeout_s, "timeout_s", 1, 60)
    v6 = ":" in ip
    if platform.system() == "Darwin":
        cmd = ["ping6" if v6 else "ping", "-c", str(count), "-i", "0.5"]
        if not v6:
            cmd += ["-t", str(timeout_s)]
    else:
        cmd = ["ping", "-n", "-c", str(count), "-i", "0.5", "-W", "1", "-w", str(timeout_s)]
        if v6:
            cmd.insert(1, "-6")
    cmd.append(ip)
    rc, out, err = c.run_cmd(cmd, timeout=timeout_s + 2)
    sent = received = None
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out)
    if m:
        sent, received = int(m.group(1)), int(m.group(2))
    avg = None
    m = re.search(r"= [\d.]+/([\d.]+)/[\d.]+", out)
    if m:
        avg = float(m.group(1))
    res = {"ip": ip, "reachable": bool(received), "sent": sent if sent is not None else count,
           "received": received or 0, "rtt_avg_ms": avg,
           "output_tail": (out.strip().splitlines() or [""])[-3:], "command": cmd}
    if rc in (124, 126, 127) or (sent is None and err.strip()):
        res["error"] = err.strip()
    return res


_ICMP_UNREACH = re.compile(
    r"\bIP (\S+) > (\S+): ICMP (?:(?:host|net) )?(\S+?) (?:udp port \d+ )?unreachable")


def icmp_unreachable(text):
    """ICMP unreachable lines in tcpdump -nn output -> [{router, to, target, line}].
    e.g. 'IP 198.51.100.1 > 198.51.100.212: ICMP host 192.0.2.81 unreachable, length 52'"""
    out, seen = [], set()
    for line in (text or "").splitlines():
        m = _ICMP_UNREACH.search(line)
        if m:
            key = (m.group(1), m.group(3))
            if key not in seen:
                seen.add(key)
                out.append({"router": m.group(1), "to": m.group(2), "target": m.group(3),
                            "line": line.strip()})
    return out


def unreachable_hints(items):
    return [f"The router {u['router']} cannot find the sensor at {u['target']}: the sensor link not enabled, "
            f"wrong address, or the sensor not on that segment." for u in items]


def capture(port, seconds=10, iface=None, max_packets=200):
    """Watch UDP packets on port for up to seconds (stops early at max_packets).
    -> {packets: [{time, iface?, src, src_port, dst, dst_port, length}], count, command, error?}
    Needs root (tcpdump). Read-only: listens, sends nothing."""
    port = c.validate_port(port)
    seconds = c.validate_int(seconds, "seconds", 1, 120)
    max_packets = c.validate_int(max_packets, "max_packets", 1, 5000)
    if iface not in (None, "", "any"):
        iface = c.validate_iface(iface)
    else:
        iface = "any" if platform.system() != "Darwin" else None
    cmd = ["tcpdump", "-nn", "-l", "-c", str(max_packets)]
    if iface:
        cmd += ["-i", iface]
    cmd += ["udp", "port", str(port), "or", "icmp"]
    if not c.have("tcpdump"):
        return {"packets": [], "count": 0, "command": cmd,
                "error": "tcpdump is not installed (apt install tcpdump)"}
    rc, out, err = c.run_cmd(cmd, timeout=seconds)
    pkts = parse_tcpdump(out, max_packets)
    res = {"packets": pkts, "count": len(pkts), "command": cmd, "seconds": seconds}
    unreach = icmp_unreachable(out)
    if unreach:
        res["icmp_unreachable"] = unreach
        res["hints"] = unreachable_hints(unreach)
    # 124 = our timeout fired: the normal way a capture ends.
    if rc not in (0, 124):
        msg = err.strip().splitlines()
        msg = [l for l in msg if "listening on" not in l and "verbose output" not in l]
        res["error"] = " ".join(msg) or f"tcpdump exit {rc}"
        if "ermission" in res["error"] or "Operation not permitted" in res["error"]:
            res["error"] += " (tcpdump needs root)"
    if not pkts and "error" not in res:
        res["note"] = (f"no UDP {port} packets seen in {seconds}s on {iface or 'default iface'}: "
                       f"neither side is sending, or traffic is on another interface")
    return res


def udp_probe(ip, port):
    """Read-only reachability check for a UDP peer. Sends nothing to the peer's port: a UDP
    probe would put bytes on a sensor's control port, and the absence of an ICMP reply proves
    nothing for UDP. Reports route, neighbor (ARP) state and same-subnet status instead.
    -> {ip, port, route, neighbor, same_subnet, note}"""
    ip = c.validate_ip(ip)
    port = c.validate_port(port)
    dl = c.Deadline(4)
    out = {"ip": ip, "port": port,
           "note": "read-only: nothing was sent. Use capture to see whether packets flow, "
                   "and ping for ICMP reachability."}
    try:
        out["route"] = visibility.route_get(ip, dl)
    except Exception as exc:  # noqa: BLE001
        out["route"] = {"error": str(exc)}
    target = out["route"].get("gateway") or ip
    try:
        neigh = visibility.neighbors(dl)
        out["neighbor"] = next((n for n in neigh if n.get("ip") == target), None) \
            if isinstance(neigh, list) else neigh
    except Exception as exc:  # noqa: BLE001
        out["neighbor"] = {"error": str(exc)}
    try:
        ifaces = visibility.interfaces(dl)
        out["same_subnet"] = visibility.same_subnet_addresses(ifaces, ip)
    except Exception as exc:  # noqa: BLE001
        out["same_subnet"] = {"error": str(exc)}
    return out
