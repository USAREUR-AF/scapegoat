"""C2 outputs: geodesy, canonical tracks, config, and encoding with goat-transformers
(skipped when no goat-transformers tree is found: GOAT_TRANSFORMERS_PATH or the usual checkout)."""

import glob
import http.server
import json
import math
import os
import socket
import threading
import time
import unittest

from scapegoat.core import config as cfgmod
from scapegoat.core import outputs as out
from scapegoat.core.service import Service
from scapegoat.core.session import Session
from tests.fakeproto import FakeProtocol, FakeSensor
from tests.helpers import free_udp_port, make_config, wait_for

GT = os.environ.get("GOAT_TRANSFORMERS_PATH") or os.path.expanduser(
    "~/src/github.com/USAREUR-AF/goat-transformers")
try:
    GT_ROOT = out.find_transformers(GT)
except out.TransformersUnavailable:
    GT_ROOT = ""
SKIP = "goat-transformers not found; set GOAT_TRANSFORMERS_PATH"


def sample_track(**kw):
    t = {"track_id": 1203, "source_id": "sensor-7", "time": 1700000000.25,
         "lat": 44.4268, "lon": 26.1025, "hae": 150.0, "vel_east": -12.5, "vel_north": 4.25,
         "vel_up": 0.0, "confirmed": True}
    t.update(kw)
    return t


def udp_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(2)
    return s, s.getsockname()[1]


class TestGeodesy(unittest.TestCase):
    def test_round_trip(self):
        for lat, lon, h in ((44.4268, 26.1025, 150.0), (-33.9, 151.2, 30.0), (0.0, 0.0, 0.0),
                            (89.9, -179.9, 10000.0)):
            x, y, z = out.geodetic_to_ecef(lat, lon, h)
            la, lo, hh = out.ecef_to_geodetic(x, y, z)
            self.assertAlmostEqual(la, lat, places=9)
            self.assertAlmostEqual(lo, lon, places=9)
            self.assertAlmostEqual(hh, h, places=3)

    def test_velocity_enu(self):
        lat, lon = 44.4268, 26.1025
        la, lo = math.radians(lat), math.radians(lon)
        # a pure "north" ECEF velocity of 10 m/s built from the ENU basis
        n = (-math.sin(la) * math.cos(lo), -math.sin(la) * math.sin(lo), math.cos(la))
        e, nn, u = out.ecef_velocity_to_enu(10 * n[0], 10 * n[1], 10 * n[2], lat, lon)
        self.assertAlmostEqual(e, 0, places=9)
        self.assertAlmostEqual(nn, 10, places=9)
        self.assertAlmostEqual(u, 0, places=9)


class TestCanonical(unittest.TestCase):
    def test_canonical_track(self):
        c = out.canonical_track(sample_track())
        self.assertEqual((c["trackId"], c["observedAt"]), ("1203", "2023-11-14T22:13:20.250Z"))
        self.assertEqual(c["velocity"], {"eastMps": -12.5, "northMps": 4.25, "upMps": 0.0})
        c = out.canonical_track(sample_track(hae=None, vel_east=None, vel_north=None,
                                             vel_up=None, classification="uas"))
        self.assertNotIn("altitudeM", c["position"])
        self.assertNotIn("velocity", c)
        self.assertEqual(c["classification"], "uas")


class TestConfig(unittest.TestCase):
    def base(self, outputs, **kw):
        d = {"outputs": outputs}
        d.update(kw)
        return d

    def test_parse(self):
        cfg = cfgmod.from_dict(self.base({
            "cat062": {"format": "asterix-cat062", "to": ["udp://239.255.62.1:8600"],
                       "sac": 1, "sic": 7},
            "cot": {"format": "cot-xml", "to": ["udp://127.0.0.1:6969"], "enabled": False}}))
        self.assertEqual(cfg.outputs["cat062"]["context"], {"cat062.sac": 1, "cat062.sic": 7})
        self.assertFalse(cfg.outputs["cot"]["enabled"])

    def test_refusals(self):
        for bad, msg in (
                ({"x": {"format": "cat048", "to": ["udp://127.0.0.1:1"]}}, "format"),
                ({"x": {"format": "asterix-cat062", "to": ["udp://127.0.0.1:1"]}}, "sac"),
                ({"x": {"format": "asterix-cat062", "to": ["udp://127.0.0.1:1"], "sac": 1,
                        "sic": 300}}, "sic"),
                ({"x": {"format": "cot-xml", "to": ["tcp://127.0.0.1:1"]}}, "udp://"),
                ({"x": {"format": "cot-xml", "to": []}}, "destinations"),
                ({"x": {"format": "cot-xml", "to": ["zenoh:a/b"]}}, "island_rest"),
                ({"x": {"format": "sapient", "to": ["udp://127.0.0.1:1"]}}, "node_id")):
            with self.assertRaisesRegex(cfgmod.ConfigError, msg):
                cfgmod.from_dict(self.base(bad))

    def test_missing_transformers_turns_outputs_off(self):
        from unittest import mock
        with mock.patch.dict(os.environ, {"GOAT_TRANSFORMERS_PATH": ""}), \
                mock.patch.object(out, "TRANSFORMERS_DIRS", ()):
            layer = out.OutputLayer({"c": {"format": "cot-xml", "to": ["udp://127.0.0.1:9"],
                                           "enabled": True, "context": {"how": "m-g"}}},
                                    transformers_path="/nonexistent")
        self.assertIsNone(layer.encoder)
        self.assertIn("goat-transformers not found", layer.status()["error"])
        layer.publish("s", [sample_track()])          # off: nothing happens, nothing raises
        self.assertEqual(layer.status()["outputs"][0]["sent"], 0)


@unittest.skipUnless(GT_ROOT, SKIP)
class TestEncoding(unittest.TestCase):
    def test_conformance_with_goat_transformers_vectors(self):
        """A normalized track equal to each to-asterix-cat062 vector input encodes to the
        vector's bytes."""
        enc = out.Encoder(GT_ROOT, ["asterix-cat062"])
        n = 0
        for f in sorted(glob.glob(os.path.join(GT_ROOT, "packs", "canonical-track-v2",
                                               "vectors", "*-to-asterix-cat062-*.json"))):
            v = json.load(open(f))
            if not v.get("expect") or "error" in v or not v.get("context"):
                continue
            i = json.loads(v["input"])
            try:
                ts = time.mktime(time.strptime(i["observedAt"][:19], "%Y-%m-%dT%H:%M:%S")) - \
                    time.timezone + float("0." + i["observedAt"][20:23])
            except ValueError:
                continue
            p, vel = i["position"], i.get("velocity") or {}
            t = {"track_id": i["trackId"], "source_id": i["sourceId"],
                 "generation": i["trackGeneration"], "time": ts, "lat": p["latitudeDeg"],
                 "lon": p["longitudeDeg"], "hae": p.get("altitudeM"),
                 "vel_east": vel.get("eastMps"), "vel_north": vel.get("northMps"),
                 "vel_up": vel.get("upMps"), "confirmed": i.get("confirmed", True),
                 "coasting": i.get("coasting", False), "final": i.get("finalUpdate", False),
                 "simulated": i.get("simulated", False) or i.get("headerSimulated", False)}
            if i.get("headerSimulated") and not i.get("simulated"):
                continue          # a header-only flag the normalized track does not carry
            got = enc.encode("asterix-cat062", out.canonical_track(t), v["context"])
            self.assertEqual(got.hex(), v["expect"], os.path.basename(f))
            n += 1
        self.assertGreaterEqual(n, 4)

    def test_cat062_to_udp_round_trip(self):
        rx, port = udp_listener()
        try:
            layer = out.OutputLayer({"cat062": {
                "format": "asterix-cat062", "to": [f"udp://127.0.0.1:{port}"], "enabled": True,
                "context": {"cat062.sac": 1, "cat062.sic": 7}}}, transformers_path=GT_ROOT)
            layer.publish("sensor", [sample_track()])
            data = rx.recvfrom(4096)[0]
        finally:
            rx.close()
        self.assertEqual(data[0], 62)
        f = layer.encoder.decode("asterix-cat062", data)
        self.assertEqual((f["cat062.sac"], f["cat062.sic"], f["cat062.track_number"]), (1, 7, 1203))
        self.assertAlmostEqual(f["lat"], 44.4268, places=5)
        self.assertAlmostEqual(f["lon"], 26.1025, places=5)
        self.assertAlmostEqual(f["track.vel_east_ms"], -12.5)
        self.assertEqual(layer.status()["outputs"][0]["sent"], 1)

    def test_cot_to_udp_and_disabled_output(self):
        rx, port = udp_listener()
        rx2, port2 = udp_listener()
        try:
            layer = out.OutputLayer({
                "cot": {"format": "cot-xml", "to": [f"udp://127.0.0.1:{port}"], "enabled": True,
                        "context": {"how": "m-r"}, "stale_s": 30},
                "off": {"format": "cot-xml", "to": [f"udp://127.0.0.1:{port2}"],
                        "enabled": False, "context": {"how": "m-r"}}}, transformers_path=GT_ROOT)
            layer.publish("sensor", [sample_track(classification="uas")])
            xml = rx.recvfrom(8192)[0].decode()
            rx2.settimeout(0.3)
            with self.assertRaises(socket.timeout):
                rx2.recvfrom(100)
        finally:
            rx.close()
            rx2.close()
        self.assertIn('uid="sensor-7-1203"', xml)
        self.assertIn('type="a-u-A-M-F-Q"', xml)
        self.assertIn('stale="2023-11-14T22:13:50.250Z"', xml)
        self.assertIn('how="m-r"', xml)

    def test_zenoh_destination_puts_to_island_rest(self):
        got = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_PUT(self):
                n = int(self.headers.get("Content-Length") or 0)
                got.append((self.path, self.rfile.read(n)))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            layer = out.OutputLayer({"cat062": {
                "format": "asterix-cat062", "to": ["zenoh:site/sensor/cat062"], "enabled": True,
                "context": {"cat062.sac": 1, "cat062.sic": 7}}},
                island_rest=f"http://127.0.0.1:{srv.server_address[1]}", transformers_path=GT_ROOT)
            layer.start()
            layer.publish("sensor", [sample_track()])
            self.assertTrue(wait_for(lambda: got, 3))
            layer.stop()
        finally:
            srv.shutdown()
        self.assertEqual(got[0][0], "/site/sensor/cat062")
        self.assertEqual(got[0][1][0], 62)

    def test_session_tracks_hook_feeds_outputs(self):
        class TrackingProto(FakeProtocol):
            def tracks(self, msg):
                return [sample_track(track_id=7)] if msg.name == "Data" else []

        sensor = FakeSensor(0.2).start()
        rx, port = udp_listener()
        cfg = make_config(sensor.port, free_udp_port(), extra={
            "transformers": {"path": GT_ROOT},
            "outputs": {"cat062": {"format": "asterix-cat062", "to": [f"udp://127.0.0.1:{port}"],
                                   "sac": 1, "sic": 7}}})
        svc = Service(cfg, sessions={"sensor": Session(cfg.sessions["sensor"], TrackingProto({}))})
        try:
            svc.start(http=False)
            self.assertTrue(wait_for(lambda: sensor.peer is not None, 3))
            sensor.send(b"DTtrack")
            data = rx.recvfrom(4096)[0]
            f = svc.outputs.encoder.decode("asterix-cat062", data)
            self.assertEqual(f["cat062.track_number"], 7)
            self.assertEqual(svc.health()["outputs"]["outputs"][0]["sent"], 1)
        finally:
            svc.stop()
            sensor.stop()
            rx.close()
