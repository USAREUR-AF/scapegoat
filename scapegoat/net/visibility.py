"""Read-only view of the node's network, aimed at "why is the sensor link not coming up".

snapshot(config) -> dict with sections host, interfaces, neighbors, routes, sessions, firewall.
Each section is computed independently; a failure becomes {"error": "..."} for that section.
Nothing here changes the system.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import time

from . import _common as c
from ._common import _get

STAT_KEYS = ("rx_bytes", "rx_packets", "rx_errors", "rx_dropped",
             "tx_bytes", "tx_packets", "tx_errors", "tx_dropped")
NOT_AVAILABLE = {"error": "not available on this OS"}


def _linux_tools():
    return c.have("ip")


# ---- sections -----------------------------------------------------------------------------

def host_info():
    info = {"hostname": socket.gethostname(),
            "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "os": f"{platform.system()} {platform.release()}"}
    up = c.read_sys("/proc/uptime")
    if up:
        try:
            info["uptime_s"] = int(float(up.split()[0]))
        except (ValueError, IndexError):
            pass
    return info


def interfaces(dl=None):
    dl = dl or c.Deadline(5)
    if not _linux_tools():
        return _mac_interfaces(dl)
    addrs = c.run_json(["ip", "-j", "addr"], dl.left())
    links = {l.get("ifname"): l for l in c.run_json(["ip", "-j", "link"], dl.left())}
    out = []
    for a in addrs:
        name = a.get("ifname")
        link = links.get(name, {})
        flags = a.get("flags") or link.get("flags") or []
        carrier_raw = c.read_sys(f"/sys/class/net/{name}/carrier")
        carrier = None if carrier_raw is None else carrier_raw == "1"
        if carrier is None and "NO-CARRIER" in flags:
            carrier = False
        stats = {}
        for k in STAT_KEYS:
            v = c.read_sys(f"/sys/class/net/{name}/statistics/{k}")
            if v is not None and v.isdigit():
                stats[k] = int(v)
        out.append({
            "name": name,
            "operstate": a.get("operstate") or link.get("operstate"),
            "admin_up": "UP" in flags,
            "carrier": carrier,
            "flags": flags,
            "mac": a.get("address") or link.get("address"),
            "mtu": a.get("mtu") or link.get("mtu"),
            "addresses": [
                {"family": ai.get("family"), "address": ai.get("local"),
                 "prefixlen": ai.get("prefixlen"), "cidr": f"{ai.get('local')}/{ai.get('prefixlen')}",
                 "dynamic": bool(ai.get("dynamic"))}
                for ai in a.get("addr_info", []) if ai.get("local")
            ],
            "stats": stats,
        })
    return out


def _mac_interfaces(dl):
    if not c.have("ifconfig"):
        return NOT_AVAILABLE
    rc, out, err = c.run_cmd(["ifconfig", "-a"], dl.left())
    if rc != 0:
        return {"error": err.strip() or f"ifconfig exit {rc}"}
    return parse_ifconfig(out)


def parse_ifconfig(text):
    """Minimal BSD/macOS ifconfig parser: name, flags, mtu, mac, addresses, status."""
    result, cur = [], None
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+): flags=\d+<([^>]*)>.*?mtu (\d+)", line)
        if m:
            flags = m.group(2).split(",") if m.group(2) else []
            cur = {"name": m.group(1), "flags": flags, "admin_up": "UP" in flags,
                   "mtu": int(m.group(3)), "mac": None, "addresses": [], "carrier": None,
                   "operstate": None, "stats": {}}
            result.append(cur)
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("ether "):
            cur["mac"] = s.split()[1]
        elif s.startswith("inet "):
            parts = s.split()
            ip = parts[1]
            prefix = 32
            if "netmask" in parts:
                mask = parts[parts.index("netmask") + 1]
                try:
                    prefix = bin(int(mask, 16)).count("1") if mask.startswith("0x") else \
                        ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
                except ValueError:
                    pass
            cur["addresses"].append({"family": "inet", "address": ip, "prefixlen": prefix,
                                     "cidr": f"{ip}/{prefix}"})
        elif s.startswith("inet6 "):
            parts = s.split()
            ip = parts[1].split("%")[0]
            prefix = int(parts[parts.index("prefixlen") + 1]) if "prefixlen" in parts else 128
            cur["addresses"].append({"family": "inet6", "address": ip, "prefixlen": prefix,
                                     "cidr": f"{ip}/{prefix}"})
        elif s.startswith("status:"):
            st = s.split(":", 1)[1].strip()
            cur["operstate"] = st.upper()
            cur["carrier"] = st == "active"
    return result


def neighbors(dl=None):
    dl = dl or c.Deadline(5)
    if _linux_tools():
        rows = c.run_json(["ip", "-j", "neigh"], dl.left())
        return [{"ip": n.get("dst"), "iface": n.get("dev"), "mac": n.get("lladdr"),
                 "state": (n.get("state") or ["?"])} for n in rows]
    if c.have("arp"):
        rc, out, err = c.run_cmd(["arp", "-an"], dl.left())
        if rc != 0:
            return {"error": err.strip() or f"arp exit {rc}"}
        res = []
        for line in out.splitlines():
            m = re.search(r"\(([\d.]+)\) at (\S+) on (\S+)", line)
            if m:
                inc = m.group(2) == "(incomplete)"
                res.append({"ip": m.group(1), "iface": m.group(3),
                            "mac": None if inc else m.group(2),
                            "state": ["INCOMPLETE"] if inc else ["REACHABLE?"]})
        return res
    return NOT_AVAILABLE


def routes(dl=None):
    dl = dl or c.Deadline(5)
    if _linux_tools():
        rows = c.run_json(["ip", "-j", "route"], dl.left())
        return [{"dst": r.get("dst"), "gateway": r.get("gateway"), "iface": r.get("dev"),
                 "src": r.get("prefsrc"), "protocol": r.get("protocol"),
                 "metric": r.get("metric")} for r in rows]
    if c.have("netstat"):
        rc, out, err = c.run_cmd(["netstat", "-rn", "-f", "inet"], dl.left())
        if rc != 0:
            return {"error": err.strip() or f"netstat exit {rc}"}
        res = []
        for line in out.splitlines():
            p = line.split()
            if len(p) >= 4 and (p[0] == "default" or p[0][0].isdigit()):
                res.append({"dst": p[0], "gateway": p[1], "iface": p[3] if len(p) > 3 else None})
        return res
    return NOT_AVAILABLE


def route_get(ip, dl=None):
    """Which interface/source/gateway the kernel would use to reach ip."""
    dl = dl or c.Deadline(5)
    ip = c.validate_ip(ip)
    if _linux_tools():
        rows = c.run_json(["ip", "-j", "route", "get", ip], dl.left())
        r = rows[0] if rows else {}
        return {"dst": r.get("dst", ip), "iface": r.get("dev"), "src": r.get("prefsrc"),
                "gateway": r.get("gateway"), "type": r.get("type")}
    if c.have("route"):
        rc, out, err = c.run_cmd(["route", "-n", "get", ip], dl.left())
        if rc != 0:
            return {"error": (err or out).strip() or f"route exit {rc}"}
        info = {"dst": ip, "iface": None, "src": None, "gateway": None}
        for line in out.splitlines():
            k, _, v = line.strip().partition(":")
            v = v.strip()
            if k == "interface":
                info["iface"] = v
            elif k == "gateway":
                info["gateway"] = v
        return info
    return NOT_AVAILABLE


def udp_listeners(dl=None):
    """List of {local, port, process} for UDP sockets (ss -uanp)."""
    dl = dl or c.Deadline(5)
    if c.have("ss"):
        rc, out, err = c.run_cmd(["ss", "-uanp"], dl.left())
        if rc != 0:
            raise RuntimeError(err.strip() or f"ss exit {rc}")
        return parse_ss(out)
    if c.have("netstat"):
        rc, out, err = c.run_cmd(["netstat", "-anv", "-p", "udp"], dl.left())
        if rc != 0:
            raise RuntimeError(err.strip() or f"netstat exit {rc}")
        res = []
        for line in out.splitlines():
            p = line.split()
            if p and p[0].startswith("udp") and len(p) >= 4:
                local = p[3]
                host, _, port = local.rpartition(".")
                if port.isdigit():
                    res.append({"local": host, "port": int(port), "process": None})
        return res
    raise RuntimeError("neither ss nor netstat is available")


def parse_ss(text):
    res = []
    for line in text.splitlines():
        p = line.split()
        if len(p) < 5 or p[0] in ("State", "Netid"):
            continue
        # ss -uanp: State Recv-Q Send-Q Local:Port Peer:Port [Process]
        offset = 1 if p[0] in ("udp", "UNCONN", "ESTAB") and p[1] in ("UNCONN", "ESTAB") else 0
        try:
            local = p[3 + offset]
        except IndexError:
            continue
        host, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        proc = " ".join(p[5 + offset:]) or None
        m = re.search(r'\("([^"]+)",pid=(\d+)', proc or "")
        res.append({"local": host.strip("[]"), "port": int(port), "state": p[offset],
                    "process": m.group(1) if m else proc, "pid": int(m.group(2)) if m else None})
    return res


def firewall(ports, dl=None):
    """Firewall summary and lines mentioning any of ports."""
    dl = dl or c.Deadline(5)
    ports = [str(p) for p in ports]
    if c.have("ufw"):
        rc, out, err = c.run_cmd(["ufw", "status", "verbose"], dl.left())
        if rc != 0:
            return {"tool": "ufw", "error": (err or out).strip() or f"ufw exit {rc}"}
        active = bool(re.search(r"^Status:\s*active", out, re.M))
        mentions = [l.strip() for l in out.splitlines()
                    if any(re.search(rf"\b{p}\b", l) for p in ports)]
        default_in = None
        m = re.search(r"^Default:\s*(\w+)\s*\(incoming\)", out, re.M)
        if m:
            default_in = m.group(1)
        return {"tool": "ufw", "active": active, "default_incoming": default_in,
                "port_rules": mentions, "summary": out.strip().splitlines()[:30]}
    if c.have("nft"):
        rc, out, err = c.run_cmd(["nft", "list", "ruleset"], dl.left())
        if rc != 0:
            return {"tool": "nft", "error": (err or out).strip() or f"nft exit {rc}"}
        lines = out.splitlines()
        mentions = [l.strip() for l in lines if any(re.search(rf"\b{p}\b", l) for p in ports)]
        policies = [l.strip() for l in lines if "policy drop" in l or "policy reject" in l]
        return {"tool": "nft", "active": bool(out.strip()), "port_rules": mentions[:40],
                "drop_policies": policies[:10]}
    if c.have("pfctl"):
        return {"tool": "pf", "note": "macOS packet filter; not inspected (needs root)"}
    return {"tool": None, "note": "no ufw or nft found; no host firewall detected"}


# ---- session analysis ---------------------------------------------------------------------

def _iface_index(ifaces):
    return {i["name"]: i for i in ifaces} if isinstance(ifaces, list) else {}


def same_subnet_addresses(ifaces, peer_ip):
    """Interface addresses whose subnet contains peer_ip: [{iface, cidr}]."""
    peer = ipaddress.ip_address(peer_ip)
    hits = []
    for i in ifaces if isinstance(ifaces, list) else []:
        for a in i.get("addresses", []):
            try:
                net = ipaddress.ip_interface(a["cidr"]).network
            except (ValueError, KeyError, TypeError):
                continue
            if net.version == peer.version and peer in net and net.prefixlen < net.max_prefixlen:
                hits.append({"iface": i["name"], "cidr": a["cidr"]})
    return hits


def session_peers(scfg):
    """Peers of a session: `peer` first, then `peer_candidates`, deduplicated.
    -> ([(ip, port)], [problem strings])"""
    texts = []
    if _get(scfg, "peer"):
        texts.append(_get(scfg, "peer"))
    cands = _get(scfg, "peer_candidates", None) or []
    if isinstance(cands, str):
        cands = [cands]
    texts.extend(cands)
    peers, problems, seen = [], [], set()
    for t in texts:
        try:
            ip, port = c.split_hostport(t)
        except c.ValidationError as exc:
            problems.append(f"{t!r}: {exc}")
            continue
        if (ip, port) not in seen:
            seen.add((ip, port))
            peers.append((ip, port))
    return peers, problems


VIRTUAL_IFACE_RE = re.compile(
    r"^(lo|wlan|wl|wt|podman|veth|docker|br-|virbr|tailscale|wg|tun|tap|netbird)")
WIRED_IFACE_RE = re.compile(r"^(eth|en|eno|enp|ens|end|usb)")


def sensor_iface_choice(ifaces, prefer=()):
    """Interface to name in an addr_add hint: carrier up and not wireless/virtual
    (wlan*, wt*, podman*, veth*, lo, docker*, ...). Names in `prefer` win if eligible.
    Returns the name, or the literal "<iface>" when none qualifies."""
    ok = [i["name"] for i in (ifaces if isinstance(ifaces, list) else [])
          if i.get("carrier") is True and not VIRTUAL_IFACE_RE.match(i.get("name") or "")]
    for name in prefer:
        if name in ok:
            return name
    return ok[0] if ok else "<iface>"


def expected_address(config):
    """The configured expected_local_address as an ip_interface, or None."""
    want = _get(config, "expected_local_address", None)
    if not want:
        return None
    try:
        return ipaddress.ip_interface(c.validate_iface_cidr(str(want)))
    except c.ValidationError:
        return None


TOPOLOGIES = ("routed", "same-lan")


def topology(config, ifaces, dl=None):
    """How this node reaches the sensor.
    routed:   through a router (the sensor is on another subnet; nothing to add locally).
    same-lan: on the sensor's own subnet (this node needs an address in it).
    Config `topology` wins; else expected_local_address set to a CIDR means same-lan; else it
    is inferred: routed when the route to the first peer uses a gateway and no local address
    is in the peer's subnet. -> {mode, source, note?}"""
    want = _get(config, "topology", None)
    if want in TOPOLOGIES:
        return {"mode": want, "source": "config"}
    note = (f"topology {want!r} in the config is not one of {', '.join(TOPOLOGIES)}; inferred"
            if want not in (None, "") else None)
    if expected_address(config) is not None:
        out = {"mode": "same-lan", "source": "expected_local_address is set"}
    else:
        out = {"mode": "same-lan", "source": "inferred (no peer to check)"}
        for _, scfg in c.iter_sessions(config):
            peers, _ = session_peers(scfg)
            if not peers:
                continue
            ip = peers[0][0]
            try:
                r = route_get(ip, dl)
            except Exception:  # noqa: BLE001
                r = {}
            routed = bool(r.get("gateway")) and not same_subnet_addresses(ifaces, ip)
            out = {"mode": "routed" if routed else "same-lan",
                   "source": f"inferred from the route to {ip}"
                             + (f" (via gateway {r['gateway']})" if r.get("gateway") else "")}
            break
    if note:
        out["note"] = note
    return out


def default_route_sources(routes_, ifaces):
    """IPs that are the source of a default route (prefsrc, else the interface's first IPv4)."""
    idx = _iface_index(ifaces)
    out = set()
    for r in routes_ if isinstance(routes_, list) else []:
        if r.get("dst") != "default":
            continue
        if r.get("src"):
            out.add(r["src"])
        else:
            first = next((a["address"] for a in (idx.get(r.get("iface")) or {}).get("addresses", [])
                          if a.get("family") == "inet"), None)
            if first:
                out.add(first)
    return out


def check_peer_routed(peer_ip, peer_port, ifaces, neigh, dl, local_ip=None, default_srcs=()):
    """Routed topology: the sensor is on another subnet, reached through a router. No
    same-subnet or addr_add advice; check the path to the router instead."""
    out = {"ip": peer_ip, "port": peer_port, "hints": [], "notes": []}
    hints, notes = out["hints"], out["notes"]
    matches = same_subnet_addresses(ifaces, peer_ip)
    out["same_subnet"] = matches
    try:
        r = route_get(peer_ip, dl)
    except Exception as exc:  # noqa: BLE001
        r = {"error": str(exc)}
        hints.append(f"The kernel has no route to {peer_ip} ({exc}): add a route to the sensor's "
                     f"subnet through the router, or check the default route.")
    out["route"] = r
    idx = _iface_index(ifaces)
    out_iface = r.get("iface") if isinstance(r, dict) else None
    gw = r.get("gateway") if isinstance(r, dict) else None
    for m in matches:
        addr = next((x for x in (idx.get(m["iface"]) or {}).get("addresses", [])
                     if x.get("cidr") == m["cidr"]), {})
        own_ip = m["cidr"].split("/")[0]
        if gw:
            # The route already goes via the router (e.g. a host route wins): the overlap does
            # not break routing. Informational only.
            notes.append(f"{m['cidr']} on {m['iface']} overlaps the sensor's subnet, but traffic to "
                         f"{peer_ip} still goes via gateway {gw} on {out_iface}; no change needed.")
            continue
        # Only suggest removal when the interface keeps another IPv4 address outside the
        # sensor's subnet, and the address is neither DHCP-assigned nor a default route's source.
        others = [x for x in (idx.get(m["iface"]) or {}).get("addresses", [])
                  if x.get("family") == "inet" and x.get("cidr") != m["cidr"]
                  and ipaddress.ip_address(peer_ip) not in
                  ipaddress.ip_interface(x["cidr"]).network]
        protected = addr.get("dynamic") or own_ip in default_srcs
        if others and not protected:
            hints.append(f"This node holds {m['cidr']} in the sensor's subnet, so it looks for "
                         f"the sensor on its own wire instead of through the router — remove it: "
                         f"scapegoat net addr_del --iface {m['iface']} --cidr {m['cidr']} --confirm")
        else:
            hints.append(f"This node's own network {m['cidr']} on {m['iface']} includes the sensor "
                         f"address {peer_ip}, so traffic to it is not sent to a router. Check the "
                         f"sensor address, or whether this site is same-lan (topology).")
    if out_iface:
        i = idx.get(out_iface)
        if i and not i.get("admin_up"):
            hints.append(f"{out_iface} is administratively down — bring it up with: "
                         f"scapegoat net link_up --iface {out_iface} --confirm")
        elif i and i.get("carrier") is False:
            hints.append(_no_carrier_hint(out_iface))
        local_here = bool(local_ip) and any(
            a.get("address") == local_ip for a in (i or {}).get("addresses", []))
        if not WIRED_IFACE_RE.match(out_iface) and not local_here:
            kind = ("NetBird mesh" if out_iface.startswith(("wt", "netbird")) else
                    "Wi-Fi" if out_iface.startswith(("wl", "wlan")) else "a non-wired interface")
            hints.append(f"Traffic to {peer_ip} would leave on {out_iface} ({kind}), not on the "
                         f"wired network toward the sensor's router: check the routes "
                         f"(ip route get {peer_ip}).")
        if not gw and not matches:
            hints.append(f"{peer_ip} is routed directly out of {out_iface} with no gateway, but the "
                         f"topology is routed: the sensor's router should be the next hop.")
    target = gw or peer_ip
    entry = next((n for n in neigh if n.get("ip") == target), None) \
        if isinstance(neigh, list) else None
    out["neighbor"] = entry or {"ip": target, "state": ["NONE"], "mac": None}
    states = [s.upper() for s in entry.get("state", [])] if entry else ["NONE"]
    if entry is None:
        out["neighbor_note"] = f"no ARP/neighbor entry for {target} yet (normal before any traffic)"
    elif "FAILED" in states or "INCOMPLETE" in states:
        hints.append(f"The router {target} does not answer ARP ({'/'.join(states)}): check the "
                     f"cable and the gateway address." if gw else
                     f"{target} does not answer ARP ({'/'.join(states)}).")
    return out


def check_peer(peer_ip, peer_port, ifaces, neigh, dl, expected=None, mode="same-lan",
               local_ip=None, default_srcs=()):
    """Per-peer checks: same subnet, route, interface state, neighbor (ARP).
    -> {ip, port, same_subnet, route, neighbor, neighbor_note?, hints}"""
    if mode == "routed":
        return check_peer_routed(peer_ip, peer_port, ifaces, neigh, dl, local_ip, default_srcs)
    out = {"ip": peer_ip, "port": peer_port, "hints": []}
    hints = out["hints"]
    matches = same_subnet_addresses(ifaces, peer_ip)
    out["same_subnet"] = matches
    if not matches:
        if ":" not in peer_ip:
            hints.append(_subnet_hint([peer_ip], ifaces, expected))
        else:
            hints.append(f"No address on any interface is in the same subnet as peer {peer_ip}.")

    try:
        r = route_get(peer_ip, dl)
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        r = {"error": str(exc)}
        hints.append(f"The kernel has no route to {peer_ip} ({exc}).")
    out["route"] = r
    idx = _iface_index(ifaces)
    out_iface = r.get("iface") if isinstance(r, dict) else None
    if out_iface:
        i = idx.get(out_iface)
        if i:
            if not i.get("admin_up"):
                hints.append(f"{out_iface} is administratively down — bring it up with: "
                             f"scapegoat net link_up --iface {out_iface} --confirm")
            elif i.get("carrier") is False and not r.get("gateway"):
                hints.append(_no_carrier_hint(out_iface))
        if r.get("gateway") and matches:
            hints.append(f"Traffic to {peer_ip} goes via gateway {r['gateway']} on {out_iface}, "
                         f"although {matches[0]['cidr']} on {matches[0]['iface']} is in its subnet; "
                         f"check for a conflicting route.")
        elif r.get("gateway"):
            hints.append(f"{peer_ip} is reached through gateway {r['gateway']} on {out_iface}, "
                         f"not directly; the sensor normally needs to be on the same subnet.")
        if matches and out_iface not in [m["iface"] for m in matches]:
            hints.append(f"Traffic to {peer_ip} leaves on {out_iface}, not on "
                         f"{matches[0]['iface']} which holds the matching subnet.")
    for m in matches:
        i = idx.get(m["iface"])
        if i and i.get("carrier") is False and m["iface"] != out_iface:
            hints.append(_no_carrier_hint(m["iface"]))

    target = (r.get("gateway") if isinstance(r, dict) else None) or peer_ip
    entry = next((n for n in neigh if n.get("ip") == target), None) \
        if isinstance(neigh, list) else None
    out["neighbor"] = entry or {"ip": target, "state": ["NONE"], "mac": None}
    states = [s.upper() for s in entry.get("state", [])] if entry else ["NONE"]
    if entry is None:
        out["neighbor_note"] = f"no ARP/neighbor entry for {target} yet (normal before any traffic)"
    elif "FAILED" in states or "INCOMPLETE" in states:
        hints.append(f"{target} does not answer ARP ({'/'.join(states)}): the sensor is not on "
                     f"this wire, is off, or its address is not {target}.")
    return out


def _no_carrier_hint(iface):
    return f"{iface} has no carrier: check the cable to the sensor network switch"


def _subnet_hint(peer_ips, ifaces, expected=None):
    net24 = ipaddress.ip_network(f"{peer_ips[0]}/24", strict=False)
    who = f"peer {peer_ips[0]}" if len(peer_ips) == 1 else "peers " + ", ".join(peer_ips)
    iface = sensor_iface_choice(ifaces)
    if expected is not None and ipaddress.ip_address(peer_ips[0]) in expected.network:
        return (f"No address on any interface is in {expected.network}, the subnet of {who} — "
                f"add the expected address with: scapegoat net addr_add --iface {iface} "
                f"--cidr {expected} --confirm")
    return (f"No address on any interface is in {net24}, the subnet of {who} — "
            f"add one with: scapegoat net addr_add --iface {iface} "
            f"--cidr {_suggest_host(net24, peer_ips)}/24 --confirm  (use the subnet and free "
            f"address the sensor operator gives you; the sensor only talks to its own subnet)")


def _dedupe(items):
    seen, out = set(), []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def analyze_session(sid, scfg, ifaces, neigh, listeners, fw, dl, expected=None,
                    mode="same-lan", default_srcs=()):
    """Session checks. `peers` holds one check_peer() result per peer/candidate; the top-level
    peer_ip/peer_port/same_subnet/route/neighbor repeat the first peer's result."""
    out = {"id": sid, "hints": []}
    hints = out["hints"]
    peers, problems = session_peers(scfg)
    for p in problems:
        hints.append(f"Session {sid}: a peer address in the config is not usable ({p}).")
    if not peers:
        out["error"] = "no usable peer address in config (peer / peer_candidates)"
        if not problems:
            hints.append(f"Session {sid}: no peer or peer_candidates set in the config.")
        return out
    try:
        local_ip, local_port = c.split_hostport(_get(scfg, "local", "0.0.0.0:47000"))
    except c.ValidationError:
        local_ip, local_port = None, None
    out.update(local_ip=local_ip, local_port=local_port, protocol=_get(scfg, "protocol"))

    out["topology"] = mode
    out["peers"] = [check_peer(ip, port, ifaces, neigh, dl, expected, mode,
                               local_ip if local_ip not in (None, "0.0.0.0", "::") else None,
                               default_srcs)
                    for ip, port in peers]
    out["notes"] = _dedupe([n for p in out["peers"] for n in p.get("notes", [])])
    first = out["peers"][0]
    out.update(peer_ip=first["ip"], peer_port=first["port"], same_subnet=first["same_subnet"],
               route=first["route"], neighbor=first["neighbor"])
    if "neighbor_note" in first:
        out["neighbor_note"] = first["neighbor_note"]
    # one "no address in subnet" hint per /24, naming every candidate in it
    by_net = {}
    for p in out["peers"] if mode != "routed" else []:
        if not p["same_subnet"] and ":" not in p["ip"]:
            by_net.setdefault(str(ipaddress.ip_network(f"{p['ip']}/24", strict=False)),
                              []).append(p["ip"])
    merged = {_subnet_hint([ip], ifaces, expected): _subnet_hint(ips, ifaces, expected)
              for ips in by_net.values() for ip in ips}
    for p in out["peers"]:
        hints.extend(merged.get(h, h) for h in p["hints"])

    if local_ip and local_ip not in ("0.0.0.0", "::"):
        have_local = any(a.get("address") == local_ip
                         for i in (ifaces if isinstance(ifaces, list) else [])
                         for a in i.get("addresses", []))
        if not have_local:
            hints.append(f"The config binds to {local_ip}, but no interface has that address; "
                         f"the session socket cannot open until it does.")

    port = local_port or first["port"]
    if isinstance(listeners, list) and port:
        mine = [l for l in listeners if l.get("port") == port]
        out["listeners"] = mine
        if not mine:
            hints.append(f"Nothing is listening on UDP {port}: the scapegoat session is not running "
                         f"or not enabled (scapegoat status).")
        elif not any((l.get("process") or "").startswith("python") or l.get("process") in
                     ("scapegoat", None) for l in mine):
            names = ", ".join(sorted({str(l.get('process')) for l in mine}))
            hints.append(f"UDP {port} is held by another program ({names}); scapegoat cannot bind it.")
    elif isinstance(listeners, dict):
        out["listeners"] = listeners

    if isinstance(fw, dict) and fw.get("active") and port:
        rules = [l for l in fw.get("port_rules", []) if re.search(rf"\b{port}\b", l)]
        out["firewall_rules"] = rules
        if fw.get("tool") == "ufw" and not rules and \
                (fw.get("default_incoming") or "").lower() in ("deny", "reject"):
            nets = _dedupe([str(ipaddress.ip_network(f"{p['ip']}/24", strict=False))
                            if ":" not in p["ip"] else p["ip"] for p in out["peers"]])
            ifc = (first["same_subnet"][0]["iface"] if first["same_subnet"] else
                   (first["route"] or {}).get("iface")) or sensor_iface_choice(ifaces)
            for net in nets:
                hints.append(f"ufw is active, denies incoming by default, and has no rule for "
                             f"UDP {port}; replies from the sensor will be dropped — allow with: "
                             f"scapegoat net fw_allow --iface {ifc} --from_cidr {net} --port {port} "
                             f"--confirm")
    out["hints"] = _dedupe(hints)
    return out


def expected_local(config, ifaces, session_results):
    """Is the top-level expected_local_address present on an interface? Read-only.
    -> {cidr, present, on: [iface], other_prefix: [{iface, cidr}], hints} or None if unset."""
    want = _get(config, "expected_local_address", None)
    if not want:
        return None
    try:
        want_if = ipaddress.ip_interface(c.validate_iface_cidr(str(want)))
    except c.ValidationError as exc:
        return {"cidr": want, "present": False, "error": str(exc),
                "hints": [f"expected_local_address in the config is not usable ({exc})."]}
    cidr = str(want_if)
    res = {"cidr": cidr, "present": False, "on": [], "other_prefix": [], "hints": []}
    for i in ifaces if isinstance(ifaces, list) else []:
        for a in i.get("addresses", []):
            if a.get("address") != str(want_if.ip):
                continue
            if a.get("prefixlen") == want_if.network.prefixlen:
                res["on"].append(i["name"])
            else:
                res["other_prefix"].append({"iface": i["name"], "cidr": a.get("cidr")})
    res["present"] = bool(res["on"])
    if res["present"]:
        return res
    if res["other_prefix"]:
        o = res["other_prefix"][0]
        res["hints"].append(
            f"This node holds {o['cidr']} on {o['iface']}, but the config expects {cidr}; the "
            f"prefix differs. Replace it: scapegoat net addr_del --iface {o['iface']} --cidr "
            f"{o['cidr']} --confirm, then scapegoat net addr_add --iface {o['iface']} --cidr "
            f"{cidr} --confirm")
        return res
    res["hints"].append(
        f"This node should hold {cidr} on the interface toward the sensor (the sensor learns our "
        f"address from our keepalives). Add it: scapegoat net addr_add --iface "
        f"{sensor_iface_choice(ifaces, _toward_sensor(ifaces, session_results))} --cidr {cidr} "
        f"--confirm")
    return res


def _toward_sensor(ifaces, session_results, expected_on=()):
    """Interfaces that evidently face the sensor: holding the expected address, holding an
    address in a peer's subnet, or carrying a direct (gateway-less) route to a peer."""
    names = {i["name"] for i in (ifaces if isinstance(ifaces, list) else [])}
    found = list(expected_on)
    for s in session_results if isinstance(session_results, list) else []:
        for p in s.get("peers", []):
            found.extend(m["iface"] for m in p.get("same_subnet") or [])
    for s in session_results if isinstance(session_results, list) else []:
        for p in s.get("peers", []):
            r = p.get("route") or {}
            if r.get("iface") in names and not r.get("gateway") \
                    and not VIRTUAL_IFACE_RE.match(r["iface"]):
                found.append(r["iface"])
    return _dedupe([n for n in found if n in names])


def carrier_hints(ifaces, session_results, expected_on=()):
    """'<iface> has no carrier' for the interface(s) that should face the sensor. When none is
    evident yet, and no wired interface has carrier, name every wired interface."""
    idx = _iface_index(ifaces)
    facing = _toward_sensor(ifaces, session_results, expected_on)
    if not facing:
        wired = [i for i in idx.values() if WIRED_IFACE_RE.match(i["name"])]
        if wired and not any(i.get("carrier") is True for i in wired):
            facing = [i["name"] for i in wired]
    return [_no_carrier_hint(n) for n in facing if idx.get(n, {}).get("carrier") is False]


def _suggest_host(net24, peer_ips):
    """A plausible host address in the peers' /24 for the hint text (not checked as free)."""
    if isinstance(peer_ips, str):
        peer_ips = [peer_ips]
    hosts = [str(h) for h in net24.hosts()]
    for cand in (hosts[9], hosts[-2], hosts[1]):
        if cand not in peer_ips:
            return cand
    return hosts[0]


def sessions(config, ifaces, neigh, dl=None, fw=None, mode=None, routes_=None):
    expected = expected_address(config)
    if routes_ is None:
        try:
            routes_ = routes(dl)
        except Exception:  # noqa: BLE001
            routes_ = []
    default_srcs = default_route_sources(routes_, ifaces)
    if mode is None:
        mode = topology(config, ifaces, dl)["mode"]
    dl = dl or c.Deadline(5)
    try:
        listeners = udp_listeners(dl)
    except Exception as exc:  # noqa: BLE001
        listeners = {"error": str(exc)}
    if fw is None:
        fw = _section(firewall, session_ports(config), dl)
    result = []
    for sid, scfg in c.iter_sessions(config):
        try:
            result.append(analyze_session(sid, scfg, ifaces, neigh, listeners, fw, dl,
                                          expected, mode, default_srcs))
        except Exception as exc:  # noqa: BLE001
            result.append({"id": sid, "error": str(exc), "hints": []})
    return result


def session_ports(config):
    ports = set()
    for _, s in c.iter_sessions(config):
        try:
            _, p = c.split_hostport(_get(s, "local"))
            if p:
                ports.add(p)
        except c.ValidationError:
            pass
        ports.update(p for _, p in session_peers(s)[0] if p)
    return sorted(ports) or [47000]


# ---- top level ----------------------------------------------------------------------------

def _section(fn, *a):
    try:
        return fn(*a)
    except Exception as exc:  # noqa: BLE001 - each section degrades independently
        return {"error": str(exc) or exc.__class__.__name__}


def snapshot(config) -> dict:
    """Full read-only picture. Never raises. Bounded to about 5 seconds."""
    dl = c.Deadline(5.0)
    snap = {"host": _section(host_info)}
    snap["interfaces"] = _section(interfaces, dl)
    snap["neighbors"] = _section(neighbors, dl)
    snap["routes"] = _section(routes, dl)
    ifaces = snap["interfaces"] if isinstance(snap["interfaces"], list) else []
    neigh = snap["neighbors"] if isinstance(snap["neighbors"], list) else []
    snap["firewall"] = _section(firewall, session_ports(config), dl)
    snap["topology"] = _section(topology, config, ifaces, dl)
    mode = snap["topology"].get("mode", "same-lan") if isinstance(snap["topology"], dict) \
        else "same-lan"
    snap["sessions"] = _section(sessions, config, ifaces, neigh, dl, snap["firewall"], mode,
                                snap["routes"] if isinstance(snap["routes"], list) else [])
    snap["expected_local"] = _section(expected_local, config, ifaces, snap["sessions"])
    el = snap["expected_local"]
    if el is None:
        snap["expected_local_address"] = None
    elif isinstance(el, dict) and "cidr" in el:
        snap["expected_local_address"] = {"cidr": el["cidr"],
                                          "present_on": (el.get("on") or [None])[0]}
    else:
        snap["expected_local_address"] = el
    hints = []
    expected_on = (el.get("on") or []) if isinstance(el, dict) else []
    ch = _section(carrier_hints, ifaces, snap["sessions"], expected_on)
    hints.extend(ch if isinstance(ch, list) else [])
    if isinstance(el, dict):
        hints.extend(el.get("hints", []))
    if isinstance(snap["sessions"], list):
        for s in snap["sessions"]:
            hints.extend(s.get("hints", []))
    snap["hints"] = _dedupe(hints)
    return snap
