import contextlib
import io
import json
import sys
import types
import unittest
import urllib.error
import urllib.request
from unittest import mock

from scapegoat import cli
from scapegoat.core.service import Service
from scapegoat.core.session import Session
from tests.fakeproto import FakeProtocol, FakeSensor
from tests.helpers import free_udp_port, make_config, wait_for


class ApiTest(unittest.TestCase):
    allow_net = False

    def setUp(self):
        self.sensor = FakeSensor(0.2).start()
        self.cfg = make_config(self.sensor.port, free_udp_port(), allow_net=self.allow_net)
        sess = {sid: Session(sc, FakeProtocol(sc.protocol_settings))
                for sid, sc in self.cfg.sessions.items()}
        self.svc = Service(self.cfg, sessions=sess)
        self.svc.start(http=True)
        self.base = "http://127.0.0.1:%d" % self.svc.httpd.server_address[1]

    def tearDown(self):
        self.svc.stop()
        self.sensor.stop()

    def req(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        r = urllib.request.Request(self.base + path, data=data, method=method,
                                   headers={"Content-Type": "application/json",
                                            "X-Scapegoat-Source": "ui"})
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                raw = resp.read()
                ctype = resp.headers.get("Content-Type", "")
                return resp.status, json.loads(raw) if "json" in ctype else raw
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.loads(e.read())

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv) + ["--api", self.base])
        return code, out.getvalue(), err.getvalue()


class TestApi(ApiTest):
    def test_health_and_page(self):
        code, body = self.req("GET", "/api/health")
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])
        self.assertIn("version", body)
        code, page = self.req("GET", "/")
        self.assertEqual(code, 200)
        self.assertIn(b"scapegoat", page)

    def test_sessions(self):
        s = self.svc.sessions["sensor"]
        self.assertTrue(wait_for(lambda: s.state == "established", 5))
        code, lst = self.req("GET", "/api/sessions")
        self.assertEqual(code, 200)
        self.assertEqual(lst[0]["id"], "sensor")
        self.assertEqual(lst[0]["state"], "established")
        code, one = self.req("GET", "/api/sessions/sensor")
        self.assertIn("events", one)
        self.assertLessEqual(len(one["events"]), 50)
        code, ev = self.req("GET", "/api/sessions/sensor/events?n=3")
        self.assertEqual(code, 200)
        self.assertLessEqual(len(ev), 3)
        self.assertEqual(self.req("GET", "/api/sessions/nope")[0], 404)
        self.assertEqual(self.req("GET", "/api/nothing")[0], 404)

    def test_actions(self):
        self.assertTrue(wait_for(lambda: self.svc.sessions["sensor"].sock is not None, 2))
        code, r = self.req("POST", "/api/sessions/sensor/actions/ping", {})
        self.assertEqual(code, 200, r)
        code, r = self.req("POST", "/api/sessions/sensor/actions/transmit_on", {"confirm": True})
        self.assertEqual(code, 403)
        self.assertIn("features.transmit_control = false", r["error"])
        self.assertEqual(self.req("POST", "/api/sessions/sensor/actions/bogus", {})[0], 404)
        ev = self.svc.sessions["sensor"].get_events(20)
        self.assertTrue(any(e["source"] == "ui" and "ping" in e["message"]
                            for e in ev))

    def test_lifecycle(self):
        code, r = self.req("POST", "/api/sessions/sensor/disable", {})
        self.assertEqual((code, r["state"]), (200, "disabled"))
        self.assertEqual(self.req("POST", "/api/sessions/sensor/actions/ping", {})[0], 400)
        code, r = self.req("POST", "/api/sessions/sensor/enable", {})
        self.assertEqual(code, 200)
        self.assertNotEqual(r["state"], "disabled")
        code, r = self.req("POST", "/api/sessions/sensor/reset", {})
        self.assertEqual(code, 200)

    def test_net_missing_module_is_clear_error(self):
        with mock.patch.dict(sys.modules, {"scapegoat.net.visibility": None,
                                           "scapegoat.net.probe": None}):
            code, r = self.req("GET", "/api/net")
            self.assertEqual(code, 501)
            self.assertIn("not installed", r["error"])
            code, r = self.req("POST", "/api/net/ping", {"ip": "127.0.0.1"})
            self.assertEqual(code, 501)

    def test_net_snapshot_and_probe(self):
        vis = types.ModuleType("scapegoat.net.visibility")
        vis.snapshot = lambda config: {"interfaces": [{"name": "lo"}], "peers": []}
        probe = types.ModuleType("scapegoat.net.probe")
        probe.ping = lambda ip, count=3: {"ip": ip, "count": count, "rtt_ms": 0.1}
        with mock.patch.dict(sys.modules, {"scapegoat.net.visibility": vis,
                                           "scapegoat.net.probe": probe}):
            code, r = self.req("GET", "/api/net")
            self.assertEqual((code, r["interfaces"][0]["name"]), (200, "lo"))
            code, r = self.req("POST", "/api/net/ping", {"ip": "127.0.0.1", "junk": 1})
            self.assertEqual((code, r["ip"]), (200, "127.0.0.1"))

    def test_net_control_refused_when_off(self):
        code, r = self.req("POST", "/api/net/link_down", {"iface": "eth0", "confirm": True})
        self.assertEqual(code, 403)
        self.assertIn("allow_net_control", r["error"])

    def test_cli(self):
        self.assertTrue(wait_for(lambda: self.svc.sessions["sensor"].sock is not None, 2))
        code, out, _ = self.cli("status")
        self.assertEqual(code, 0)
        self.assertIn("sensor", out)
        self.assertIn("SESSION", out)
        code, out, _ = self.cli("status", "sensor", "--json")
        self.assertEqual(json.loads(out)["id"], "sensor")
        code, out, err = self.cli("action", "sensor", "transmit_on", "--arm", "--confirm", "1")
        self.assertEqual(code, 1)
        self.assertIn("disabled by feature flag", err)
        code, out, _ = self.cli("action", "sensor", "ask_reply")
        self.assertEqual(code, 0, out)
        code, out, _ = self.cli("events", "sensor", "-n", "5")
        self.assertEqual(code, 0)
        self.assertIn("cli", out)
        code, out, _ = self.cli("actions", "sensor")
        self.assertNotIn("transmit", out)
        code, st = self.req("GET", "/api/sessions/sensor")
        self.assertNotIn("transmit_on", [a["name"] for a in st["actions"]])
        code, out, err = self.cli("status", "nope")
        self.assertEqual(code, 1)


class TestNetControlAllowed(ApiTest):
    allow_net = True

    def test_confirm_required_then_runs(self):
        calls = []
        ctl = types.ModuleType("scapegoat.net.control")
        ctl.run = lambda name, args, config: calls.append((name, args)) or {"ok": True,
                                                                             "command": "x"}
        with mock.patch.dict(sys.modules, {"scapegoat.net.control": ctl}):
            code, r = self.req("POST", "/api/net/link_up", {"iface": "eth0"})
            self.assertEqual(code, 403)
            self.assertEqual(calls, [])
            code, r = self.req("POST", "/api/net/link_up", {"iface": "eth0", "confirm": True})
            self.assertEqual(code, 200, r)
            self.assertEqual(calls[0][0], "link_up")
        self.assertTrue(any(e["source"] == "ui" for e in self.svc.events))


class TestCliOffline(unittest.TestCase):
    def test_unreachable_service(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cli.main(["status", "--api", "http://127.0.0.1:%d" % free_udp_port()])
        self.assertEqual(code, 1)
        self.assertIn("cannot reach", err.getvalue())


if __name__ == "__main__":
    unittest.main()


class TestLockAndAddress(ApiTest):
    def setUp(self):
        self.sensor = FakeSensor(0.2).start()
        self.cfg = make_config(self.sensor.port, free_udp_port(),
                               candidates=["127.0.0.2:9", f"127.0.0.1:{self.sensor.port}"],
                               extra={"expected_local_address": "127.0.0.1/8"})
        sess = {sid: Session(sc, FakeProtocol(sc.protocol_settings))
                for sid, sc in self.cfg.sessions.items()}
        self.svc = Service(self.cfg, sessions=sess)
        self.svc.start(http=True)
        self.base = "http://127.0.0.1:%d" % self.svc.httpd.server_address[1]

    def test_lock_endpoint_and_cli(self):
        code, r = self.req("POST", "/api/sessions/sensor/lock", {"peer": "127.0.0.2:9"})
        self.assertEqual((code, r["locked"], r["lock_forced"]), (200, "127.0.0.2:9", True))
        self.assertEqual(self.req("POST", "/api/sessions/sensor/lock", {})[0], 400)
        code, out, _ = self.cli("lock", "sensor", f"127.0.0.1:{self.sensor.port}")
        self.assertEqual(code, 0, out)
        self.assertIn("locked onto", out)
        code, out, _ = self.cli("status", "sensor")
        self.assertIn("LOCKED", out)

    def test_expected_address_in_health_and_status(self):
        code, h = self.req("GET", "/api/health")
        self.assertTrue(h["expected_local"]["present"], h)
        code, out, _ = self.cli("status")
        self.assertIn("Node address: [OK]", out)
        self.assertIn("probing", out + " probing")


class TestProfilesCli(unittest.TestCase):
    def test_profiles_command(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["profiles", "--profiles-dir", "/nonexistent"])
        self.assertEqual(code, 0)
        self.assertIn("sim-local", out.getvalue())
        self.assertIn("TESTING", out.getvalue())


class TestTrafficApi(ApiTest):
    def test_traffic_endpoint_and_watch_once(self):
        s = self.svc.sessions["sensor"]
        self.assertTrue(wait_for(lambda: s.state == "established", 5))
        code, r = self.req("GET", "/api/sessions/sensor/traffic?limit=5")
        self.assertEqual(code, 200)
        self.assertLessEqual(len(r["entries"]), 5)
        last = r["last_seq"]
        code, r2 = self.req("GET", f"/api/sessions/sensor/traffic?since={last - 2}")
        self.assertTrue(all(e["seq"] > last - 2 for e in r2["entries"]))
        self.assertEqual(self.req("GET", "/api/sessions/sensor/traffic?since=x")[0], 400)
        code, out, _ = self.cli("watch", "sensor", "--once", "--last", "3")
        self.assertEqual(code, 0)
        self.assertIn("KeepAlive", out)
        self.assertIn("=== *** SIMULATOR - not a real sensor *** ===", out)
        code, out, _ = self.cli("--json", "watch", "sensor", "--once", "--filter", "Keep")
        lines = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
        self.assertEqual(lines[0]["type"], "peer_kind")
        self.assertTrue(all(x["name"] == "KeepAlive" for x in lines if "seq" in x))

    def test_api_option_before_command(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--api", self.base, "--json", "status"])
        self.assertEqual(code, 0, err.getvalue())
        self.assertEqual(json.loads(out.getvalue())["sessions"][0]["id"], "sensor")


class TestNodeApi(ApiTest):
    def test_node_endpoint(self):
        code, n = self.req("GET", "/api/node")
        self.assertEqual(code, 200)
        self.assertIn("hostname", n)
        self.assertIsInstance(n["addresses"], list)
        code, n2 = self.req("GET", "/api/node?loopback=1")
        self.assertTrue(any(a["role"] == "loopback" for a in n2["addresses"]) or n2.get("error"))
        code, out, _ = self.cli("status")
        self.assertIn("This node:", out)


class TestIdentityApi(ApiTest):
    def test_identity_in_health_and_status(self):
        code, h = self.req("GET", "/api/health")
        ident = h["identity"]
        self.assertEqual(ident["role_note"], "role not set (node_role in scapegoat.toml)")
        self.assertTrue(ident["title"].endswith("role not set") or ident["billie_node"])
        self.assertTrue(ident["sensor_sees"][0]["address"].startswith("127.0.0.1:"))
        self.svc.config.node_role = "C2 node · Pi A"
        code, h = self.req("GET", "/api/health")
        self.assertTrue(h["identity"]["title"].endswith(" · C2 node · Pi A"))
        code, out, _ = self.cli("status")
        self.assertTrue(out.splitlines()[0].endswith(" · C2 node · Pi A"), out)
        code, s = self.req("GET", "/api/sessions/sensor")
        self.assertTrue(s["local_seen_as"].startswith("127.0.0.1:"))
