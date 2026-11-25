# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
"""The Python API and CLI tests of tests/test_api.py and tests/test_latch.py, run against the
Rust binary over the wire.

    cargo build --example fake_node
    SCAPEGOAT_BIN=target/debug/examples/fake_node python3 -m unittest wire_tests.test_binary -v

The binary is a node built the way a plugin crate builds one: the open core plus the `fake`
test protocol of tests/fakeproto.py. The Python fake sensor stays Python. Each test is the
Python test, unchanged; only setUp (start the binary) and cli() (run the binary) differ.
Tests that replace Python modules with mocks have Rust equivalents and are skipped here.
Skipped entirely when SCAPEGOAT_BIN is not set.
"""

import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.request

from tests import test_api, test_latch
from tests.fakeproto import FakeSensor
from tests.helpers import free_udp_port

BIN = os.environ.get("SCAPEGOAT_BIN", "")
MOCKED = "replaces Python modules with mocks; the Rust suite has the equivalent"


def free_tcp_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def config_dict(sensor_port, local_port, allow_transmit=False, interval=0.2, allow_net=False,
                candidates=None, extra=None):
    """tests/helpers.make_config, as the dict it builds."""
    data = {
        "bind": f"127.0.0.1:{free_tcp_port()}",
        "allow_net_control": allow_net,
        "node_name": "test-node",
        "sessions": {"sensor": {
            "protocol": "fake", "enabled": True,
            "local": f"127.0.0.1:{local_port}", "peer": f"127.0.0.1:{sensor_port}",
            "forward": [], "allow_transmit_control": allow_transmit,
            "protocol_settings": {"keepalive_interval_s": interval, "establish_after": 3,
                                  "device_id": 1},
        }},
    }
    if candidates is not None:
        s = data["sessions"]["sensor"]
        s["peer"] = ""
        s["peer_candidates"] = list(candidates)
    data.update(extra or {})
    return data


def get(base, path):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return json.loads(r.read())


class _Session:
    """What the Python tests read from a Session, read over the API."""

    def __init__(self, base, sid):
        self.base, self.sid = base, sid

    def status(self):
        return get(self.base, f"/api/sessions/{self.sid}")

    @property
    def state(self):
        return self.status()["state"]

    @property
    def sock(self):
        st = self.status()
        return object() if st["enabled"] and not st["error"] else None

    def get_events(self, n=200):
        return get(self.base, f"/api/sessions/{self.sid}/events?n={n}")


class _Service:
    """The Rust binary running `serve`, with the attributes the Python tests read."""

    def __init__(self, cfg):
        self.dir = tempfile.TemporaryDirectory()
        path = os.path.join(self.dir.name, "scapegoat.json")
        with open(path, "w") as f:
            json.dump(cfg, f)
        self.base = "http://" + cfg["bind"]
        self.proc = subprocess.Popen([BIN, "serve", "--config", path],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.monotonic() + 10
        while True:
            try:
                get(self.base, "/api/health")
                break
            except OSError:
                if time.monotonic() > end or self.proc.poll() is not None:
                    raise RuntimeError("the binary did not start")
                time.sleep(0.05)
        self.sessions = {sid: _Session(self.base, sid) for sid in cfg["sessions"]}

    @property
    def events(self):
        return get(self.base, "/api/events")

    def stop(self):
        self.proc.terminate()
        self.proc.wait(10)
        self.dir.cleanup()


def run_bin(argv):
    p = subprocess.run([BIN] + list(argv), capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout, p.stderr


@unittest.skipUnless(BIN, "SCAPEGOAT_BIN is not set")
class BinaryApiTest(test_api.ApiTest):
    config_kwargs = {}

    def setUp(self):
        self.sensor = FakeSensor(0.2).start()
        self.svc = _Service(config_dict(self.sensor.port, free_udp_port(), **self.config_kwargs))
        self.base = self.svc.base

    def cli(self, *argv):
        return run_bin(list(argv) + ["--api", self.base])


class TestApi(BinaryApiTest, test_api.TestApi):
    allow_net = False

    @unittest.skip(MOCKED)
    def test_net_missing_module_is_clear_error(self):
        pass

    @unittest.skip(MOCKED)
    def test_net_snapshot_and_probe(self):
        pass


@unittest.skipUnless(BIN, "SCAPEGOAT_BIN is not set")
class TestCliOffline(unittest.TestCase):
    def test_unreachable_service(self):
        code, _, err = run_bin(["status", "--api", "http://127.0.0.1:%d" % free_udp_port()])
        self.assertEqual(code, 1)
        self.assertIn("cannot reach", err)


class TestLockAndAddress(BinaryApiTest, test_api.TestLockAndAddress):
    def setUp(self):
        self.sensor = FakeSensor(0.2).start()
        self.svc = _Service(config_dict(
            self.sensor.port, free_udp_port(),
            candidates=["127.0.0.2:9", f"127.0.0.1:{self.sensor.port}"],
            extra={"expected_local_address": "127.0.0.1/8"}))
        self.base = self.svc.base


@unittest.skipUnless(BIN, "SCAPEGOAT_BIN is not set")
class TestProfilesCli(unittest.TestCase):
    def test_profiles_command(self):
        code, out, _ = run_bin(["profiles", "--profiles-dir", "/nonexistent"])
        self.assertEqual(code, 0)
        self.assertIn("sim-local", out)
        self.assertIn("TESTING", out)


class TestTrafficApi(BinaryApiTest, test_api.TestTrafficApi):
    def test_api_option_before_command(self):
        code, out, err = run_bin(["--api", self.base, "--json", "status"])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["sessions"][0]["id"], "sensor")


class TestNodeApi(BinaryApiTest, test_api.TestNodeApi):
    pass


class TestIdentityApi(BinaryApiTest, test_api.TestIdentityApi):
    def test_identity_in_health_and_status(self):
        # As the Python test, with node_role set in the config instead of on the live object.
        code, h = self.req("GET", "/api/health")
        ident = h["identity"]
        self.assertEqual(ident["role_note"], "role not set (node_role in scapegoat.toml)")
        self.assertTrue(ident["title"].endswith("role not set") or ident["billie_node"])
        self.assertTrue(ident["sensor_sees"][0]["address"].startswith("127.0.0.1:"))
        self.svc.stop()
        self.svc = _Service(config_dict(self.sensor.port, free_udp_port(),
                                        extra={"node_role": "C2 node · Pi A"}))
        self.base = self.svc.base
        code, h = self.req("GET", "/api/health")
        self.assertTrue(h["identity"]["title"].endswith(" · C2 node · Pi A"))
        code, out, _ = self.cli("status")
        self.assertTrue(out.splitlines()[0].endswith(" · C2 node · Pi A"), out)
        code, s = self.req("GET", "/api/sessions/sensor")
        self.assertTrue(s["local_seen_as"].startswith("127.0.0.1:"))


class TestNetControlAllowed(BinaryApiTest, test_api.TestNetControlAllowed):
    config_kwargs = {"allow_net": True}

    @unittest.skip(MOCKED)
    def test_confirm_required_then_runs(self):
        pass


class TestLatchCli(BinaryApiTest, test_latch.TestLatchCli):
    config_kwargs = {"allow_transmit": True, "extra": {"features": {"transmit_control": True}}}

    def setUp(self):
        BinaryApiTest.setUp(self)
        self.assertTrue(test_api.wait_for(lambda: self.svc.sessions["sensor"].sock is not None, 2))


if __name__ == "__main__":
    unittest.main()
