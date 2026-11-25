"""Forwarding survives a forward target going away and coming back (no restart)."""

import socket
import time
import unittest
from unittest import mock

from scapegoat.core import session as sm
from scapegoat.core.session import Session
from tests.fakeproto import FakeProtocol, FakeSensor
from tests.helpers import free_udp_port, make_config, wait_for


class TestForwardRecovers(unittest.TestCase):
    def setUp(self):
        self.sensor = FakeSensor(0.2).start()
        self.fport = free_udp_port()
        cfg = make_config(self.sensor.port, free_udp_port(), forward=[f"127.0.0.1:{self.fport}"])
        self.s = Session(cfg.sessions["sensor"], FakeProtocol({}))
        self.s.start()
        self.assertTrue(wait_for(lambda: self.s.sock is not None, 2))
        self.addr = ("127.0.0.1", self.sensor.port)
        self.target = ("127.0.0.1", self.fport)

    def tearDown(self):
        self.s.stop()
        self.sensor.stop()

    def listen(self):
        r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        r.bind(self.target)
        r.settimeout(1)
        return r

    def test_target_down_then_up_resumes_without_restart(self):
        # target down: copies go nowhere
        for _ in range(20):
            self.s._handle(b"DTdown", self.addr)
            time.sleep(0.01)
        r = self.listen()
        try:
            got = set()
            end = time.monotonic() + 3
            while b"DTup" not in got and time.monotonic() < end:
                self.s._handle(b"DTup", self.addr)
                try:
                    got.add(r.recvfrom(64)[0])
                except socket.timeout:
                    pass
            self.assertIn(b"DTup", got, "forwards resume once the target listens again")
        finally:
            r.close()

    def test_send_error_counts_logs_and_replaces_the_socket(self):
        class Refusing:
            def __init__(self):
                self.calls = 0

            def sendto(self, data, addr):
                self.calls += 1
                raise ConnectionRefusedError(111, "Connection refused")

            def close(self):
                pass

        bad = Refusing()
        self.s.fwd_sock = bad
        before = self.s.forwarded
        self.s._handle(b"DTx", self.addr)
        self.assertEqual(self.s.forwarded, before + 1, "the retry on a new socket went out")
        self.assertEqual(self.s.forward_errors, 1)
        self.assertIsNot(self.s.fwd_sock, bad)
        self.assertEqual(self.s.status()["forward_socket_replaced"], 1)
        self.assertTrue(any(e["kind"] == "forward" for e in self.s.events))
        fails = [e for e in self.s.get_traffic(None, 50)["entries"]
                 if e["direction"] == "fwd" and e["problems"]]
        self.assertTrue(fails and "Connection refused" in fails[0]["problems"][0])

    def test_refusing_for_more_than_10_s_is_a_problem(self):
        class AlwaysRefusing:
            def sendto(self, data, addr):
                raise ConnectionRefusedError(111, "Connection refused")

            def close(self):
                pass

        with mock.patch.object(Session, "_new_fwd_sock", staticmethod(lambda: AlwaysRefusing())):
            self.s.fwd_sock = AlwaysRefusing()
            before = self.s.forwarded
            self.s._handle(b"DTx", self.addr)
            self.assertEqual(self.s.forwarded, before, "a refused copy is not counted")
            t0 = time.monotonic()
            for st in self.s.fwd_state.values():     # refusals kept arriving for 11 s
                st["refused_since"], st["last_refused"] = t0 - 11, t0
            self.s._check_forwards(t0)
        probs = [p["problem"] for p in self.s.status()["problems"]]
        self.assertTrue(any(p.startswith(f"forward target 127.0.0.1:{self.fport}: receiver not "
                                         "receiving") and "billie kid activate" in p
                            for p in probs), probs)
        t = self.s.status()["forward_targets"][f"127.0.0.1:{self.fport}"]
        self.assertGreaterEqual(t["errors"], 2)


    def test_refusals_stop_streak_clears(self):
        st = {"refused_since": time.monotonic() - 30, "last_refused": time.monotonic() - 20,
              "last_ok": time.monotonic(), "errors": 3, "last_error": "x"}
        self.s.fwd_state[self.target] = st
        self.s._check_forwards(time.monotonic())
        self.assertIsNone(st["refused_since"])
        self.assertEqual(self.s.status()["problems"], [])


    def test_periodic_rotation_gives_a_new_source_port(self):
        old = self.s.fwd_sock
        self.s._check_forwards(time.monotonic() + sm.FORWARD_ROTATE_S + 1)
        self.assertIsNot(self.s.fwd_sock, old)
        self.assertEqual(self.s.status()["forward_socket_replaced"], 0, "rotation is not an error")
