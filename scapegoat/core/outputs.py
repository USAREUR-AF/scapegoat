"""C2 outputs: tracks a protocol plugin yields, re-published in standard formats.

A protocol plugin turns its sensor's messages into normalized tracks (the `tracks(msg)`
hook). This module turns each track into a canonical track (canonical-track-v2) and, for
every enabled output, encodes it with goat-transformers (ASTERIX CAT062, CoT XML, SAPIENT)
and sends it to that output's destinations:

    udp://host:port            unicast or multicast (224.0.0.0/4) datagram
    zenoh:<key expression>     HTTP PUT to the Zenoh REST plugin at `island_rest`

No format is hand-encoded here: the goat-transformers Python engine (standard library only)
and its published packs do the encoding. Without goat-transformers the outputs are off and
status says why.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import queue
import socket
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone

log = logging.getLogger("scapegoat.outputs")

CANONICAL = "canonical-track-v2"
FORMATS = {
    # format -> (wire is hex text, context keys the output may set)
    "asterix-cat062": True,
    "sapient": True,
    "cot-xml": False,
}
TRANSFORMERS_DIRS = ("/opt/goat-transformers", "/usr/share/goat-transformers")

# WGS-84
_A = 6378137.0
_F = 1 / 298.257223563
_E2 = _F * (2 - _F)


def ecef_to_geodetic(x: float, y: float, z: float) -> tuple:
    """ECEF metres -> (latitude deg, longitude deg, height above the WGS-84 ellipsoid m)."""
    lon = math.atan2(y, x)
    p = math.hypot(x, y)
    lat = math.atan2(z, p * (1 - _E2))
    h = 0.0
    for _ in range(10):
        n = _A / math.sqrt(1 - _E2 * math.sin(lat) ** 2)
        h = p / math.cos(lat) - n if abs(math.cos(lat)) > 1e-12 else abs(z) - n * (1 - _E2)
        new = math.atan2(z, p * (1 - _E2 * n / (n + h)))
        if abs(new - lat) < 1e-13:
            lat = new
            break
        lat = new
    return math.degrees(lat), math.degrees(lon), h


def geodetic_to_ecef(lat_deg: float, lon_deg: float, h: float) -> tuple:
    lat, lon = math.radians(lat_deg), math.radians(lon_deg)
    n = _A / math.sqrt(1 - _E2 * math.sin(lat) ** 2)
    return ((n + h) * math.cos(lat) * math.cos(lon), (n + h) * math.cos(lat) * math.sin(lon),
            (n * (1 - _E2) + h) * math.sin(lat))


def ecef_velocity_to_enu(vx: float, vy: float, vz: float, lat_deg: float, lon_deg: float) -> tuple:
    """ECEF velocity -> (east, north, up) m/s at the given position."""
    lat, lon = math.radians(lat_deg), math.radians(lon_deg)
    sl, cl, so, co = math.sin(lat), math.cos(lat), math.sin(lon), math.cos(lon)
    east = -so * vx + co * vy
    north = -sl * co * vx - sl * so * vy + cl * vz
    up = cl * co * vx + cl * so * vy + sl * vz
    return east, north, up


def canonical_track(t: dict) -> dict:
    """A normalized track (keys below) -> a canonical-track-v2 object.

    Normalized track keys: track_id (str or int; CAT062 needs a number), source_id, time
    (epoch seconds), lat, lon, hae (optional), vel_east/vel_north/vel_up (optional),
    confirmed, coasting, final, simulated (bools), classification (optional, one of the
    canonical classes), generation (optional)."""
    ts = float(t["time"])
    obs = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{int(round((ts % 1) * 1000)) % 1000:03d}Z"
    out = {"apiVersion": "billie.dev/track-v2", "kind": "Track",
           "trackId": str(t["track_id"]), "sourceId": str(t.get("source_id") or "scapegoat"),
           "trackGeneration": str(t.get("generation") or "scapegoat-1"),
           "testData": False, "headerSimulated": False,
           "simulated": bool(t.get("simulated", False)),
           "confirmed": bool(t.get("confirmed", True)),
           "coasting": bool(t.get("coasting", False)),
           "finalUpdate": bool(t.get("final", False)),
           "observedAt": obs,
           "position": {"latitudeDeg": float(t["lat"]), "longitudeDeg": float(t["lon"])}}
    if t.get("hae") is not None:
        out["position"]["altitudeM"] = float(t["hae"])
    vel = {k: float(t[s]) for k, s in (("eastMps", "vel_east"), ("northMps", "vel_north"),
                                        ("upMps", "vel_up")) if t.get(s) is not None}
    if vel:
        out["velocity"] = vel
    if t.get("classification"):
        out["classification"] = str(t["classification"])
    return out


# ---------------------------------------------------------------- encoder
class TransformersUnavailable(Exception):
    pass


def find_transformers(path: str | None = None) -> str:
    """A goat-transformers tree holding engines/python/src, packs and model."""
    cands = [path] if path else []
    cands += [os.environ.get("GOAT_TRANSFORMERS_PATH", "")] + list(TRANSFORMERS_DIRS)
    for c in cands:
        if c and os.path.isdir(os.path.join(c, "packs")) and \
                os.path.isdir(os.path.join(c, "engines", "python", "src")):
            return c
    raise TransformersUnavailable(
        "goat-transformers not found (set [transformers] path, or GOAT_TRANSFORMERS_PATH, to a "
        "checkout of USAREUR-AF/goat-transformers; looked in "
        + ", ".join(c for c in cands if c) + ")")


class Encoder:
    """goat-transformers engine with the canonical track pack and the output packs."""

    def __init__(self, root: str, formats):
        src = os.path.join(root, "engines", "python", "src")
        if src not in sys.path:
            sys.path.insert(0, src)
        try:
            from goat_transformers import Engine, load_pack
            from goat_transformers.engine import _model_order
            from goat_transformers.modeldef import load_model_file
        except ImportError as exc:
            raise TransformersUnavailable(f"goat-transformers engine not importable: {exc}")
        eng = Engine()
        models = os.path.join(root, "model")
        for p in _model_order(models):
            eng.add_model(load_model_file(p, models=eng.models))
        for fmt in [CANONICAL] + sorted(set(formats)):
            d = os.path.join(root, "packs", fmt)
            if not os.path.isfile(os.path.join(d, "pack.def")):
                raise TransformersUnavailable(f"goat-transformers has no pack {fmt!r} in {root}")
            eng.add(load_pack(d))
        self.engine = eng
        self.root = root
        self.lock = threading.Lock()

    def encode(self, fmt: str, track: dict, context: dict) -> bytes:
        with self.lock:
            out = self.engine.convert(CANONICAL, fmt, json.dumps(track),
                                      {k: str(v) for k, v in context.items()})
        return bytes.fromhex(out.decode()) if FORMATS.get(fmt) else bytes(out)

    def decode(self, fmt: str, data: bytes):
        """Fields of an encoded message (for tests and checks)."""
        with self.lock:
            text = data.hex().encode() if FORMATS.get(fmt) else data
            return self.engine.decode(fmt, text).fields


# ---------------------------------------------------------------- destinations
def parse_destination(text: str, island_rest: str = "") -> dict:
    text = str(text).strip()
    if text.startswith("udp://"):
        host, _, port = text[6:].rpartition(":")
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            p = int(port)
        except ValueError:
            raise ValueError(f"output destination {text!r}: expected udp://IP:PORT") from None
        if not 0 < p < 65536:
            raise ValueError(f"output destination {text!r}: port out of range")
        return {"kind": "udp", "text": text, "addr": (str(ip), p), "multicast": ip.is_multicast}
    if text.startswith("zenoh:"):
        key = text[6:].strip("/")
        if not key or " " in key:
            raise ValueError(f"output destination {text!r}: expected zenoh:<key expression>")
        return {"kind": "zenoh", "text": text, "key": key}
    raise ValueError(f"output destination {text!r}: use udp://IP:PORT or zenoh:<key>")


class Output:
    def __init__(self, name: str, spec: dict, island_rest: str):
        self.name = name
        self.format = spec["format"]
        self.enabled = bool(spec.get("enabled", True))
        self.sessions = list(spec.get("sessions") or [])
        self.dests = [parse_destination(d, island_rest) for d in spec.get("to", [])]
        self.ttl = int(spec.get("multicast_ttl", 1))
        self.context = dict(spec.get("context", {}))
        self.stale_s = float(spec.get("stale_s", 30))
        # CAT062 needs the numeric track number; CoT/SAPIENT ids get a prefix so tracks of
        # different sensors stay apart (default: "<source id>-").
        self.uid_prefix = spec.get("uid_prefix")
        self.island_rest = island_rest.rstrip("/")
        self.sent = 0
        self.errors = 0
        self.last_error = ""
        self.last_sent = None
        self.dropped = 0
        self.sock = None
        self.http_q: queue.Queue = queue.Queue(maxsize=1000)

    def wants(self, session_id: str) -> bool:
        return self.enabled and (not self.sessions or session_id in self.sessions)

    def _udp(self):
        if self.sock is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.ttl)
            self.sock = s
        return self.sock

    def send(self, data: bytes):
        for d in self.dests:
            try:
                if d["kind"] == "udp":
                    self._udp().sendto(data, d["addr"])
                    self.sent += 1
                    self.last_sent = time.time()
                else:
                    self.http_q.put_nowait((d, data))
            except queue.Full:
                self.dropped += 1
            except OSError as exc:
                self.errors += 1
                self.last_error = f"{d['text']}: {exc}"
                try:
                    if self.sock:
                        self.sock.close()
                except OSError:
                    pass
                self.sock = None

    def http_worker(self, stop: threading.Event):
        while not stop.is_set():
            try:
                d, data = self.http_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if not self.island_rest:
                self.errors += 1
                self.last_error = f"{d['text']}: island_rest is not set (Zenoh REST address)"
                continue
            ctype = "application/xml" if self.format == "cot-xml" else "application/octet-stream"
            req = urllib.request.Request(f"{self.island_rest}/{d['key']}", data=data,
                                         method="PUT", headers={"Content-Type": ctype})
            try:
                with urllib.request.urlopen(req, timeout=3) as r:
                    r.read()
                self.sent += 1
                self.last_sent = time.time()
            except Exception as exc:
                self.errors += 1
                self.last_error = f"{d['text']}: {exc}"

    def status(self) -> dict:
        return {"name": self.name, "format": self.format, "enabled": self.enabled,
                "to": [d["text"] for d in self.dests], "sessions": self.sessions or "all",
                "sent": self.sent, "errors": self.errors, "dropped": self.dropped,
                "last_error": self.last_error,
                "last_sent_age_s": None if self.last_sent is None
                else round(time.time() - self.last_sent, 1),
                "context": self.context}


class OutputLayer:
    """Every configured output. publish() is called with each session's normalized tracks."""

    def __init__(self, specs: dict, island_rest: str = "", transformers_path: str = ""):
        self.outputs = [Output(n, s, island_rest) for n, s in (specs or {}).items()]
        self.error = ""
        self.encoder = None
        self.tracks_in = 0
        self.encode_errors = 0
        self.last_encode_error = ""
        self.stop_flag = threading.Event()
        self.threads = []
        active = [o for o in self.outputs if o.enabled]
        if active:
            try:
                self.encoder = Encoder(find_transformers(transformers_path or None),
                                       [o.format for o in active])
            except TransformersUnavailable as exc:
                self.error = str(exc)
                log.warning("outputs are off: %s", exc)

    def start(self):
        for o in self.outputs:
            if o.enabled and any(d["kind"] == "zenoh" for d in o.dests):
                t = threading.Thread(target=o.http_worker, args=(self.stop_flag,),
                                     name=f"scapegoat-output-{o.name}", daemon=True)
                t.start()
                self.threads.append(t)

    def stop(self):
        self.stop_flag.set()

    def publish(self, session_id: str, tracks: list):
        if not tracks or self.encoder is None:
            return
        for t in tracks:
            self.tracks_in += 1
            try:
                canon = canonical_track(t)
            except (KeyError, TypeError, ValueError) as exc:
                self.encode_errors += 1
                self.last_encode_error = f"track not usable: {exc}"
                continue
            for o in self.outputs:
                if not o.wants(session_id):
                    continue
                track, ctx = canon, dict(o.context)
                if o.format != "asterix-cat062":
                    prefix = o.uid_prefix if o.uid_prefix is not None else f"{canon['sourceId']}-"
                    track = dict(canon, trackId=f"{prefix}{canon['trackId']}")
                if o.format == "cot-xml":
                    ctx["stale_ms"] = int((float(t["time"]) + o.stale_s) * 1000)
                try:
                    data = self.encoder.encode(o.format, track, ctx)
                except Exception as exc:
                    self.encode_errors += 1
                    o.errors += 1
                    self.last_encode_error = o.last_error = f"encode {o.format}: {exc}"
                    continue
                o.send(data)

    def status(self) -> dict:
        return {"error": self.error,
                "transformers": self.encoder.root if self.encoder else None,
                "tracks_in": self.tracks_in, "encode_errors": self.encode_errors,
                "last_encode_error": self.last_encode_error,
                "outputs": [o.status() for o in self.outputs]}
