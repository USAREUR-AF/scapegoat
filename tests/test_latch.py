"""The safety latch on sensor-commanding controls, and the owed-reply ledger (no protocol plugin needed)."""

import contextlib
import io
import time
import unittest
from unittest import mock

from scapegoat import cli
from scapegoat.core import session as sm
from scapegoat.core.session import ActionRefused, Session
from scapegoat.core.service import Service
from tests.fakeproto import FakeProtocol, FakeSensor
from tests.helpers import free_udp_port, make_config, wait_for
from tests.test_api import ApiTest


def armed_session(sensor):
    cfg = make_config(sensor.port, free_udp_port(), allow_transmit=True,
                      extra={"features": {"transmit_control": True}})
    s = Session(cfg.sessions["sensor"], FakeProtocol({}))
    svc = Service(cfg, sessions={"sensor": s})
    svc.start(http=False)
    return svc, s


class TestLatch(unittest.TestCase):
    def setUp(self):
        self.sensor = FakeSensor(0.2).start()
        self.svc, self.s = armed_session(self.sensor)
        self.assertTrue(wait_for(lambda: self.s.sock is not None, 2))

    def tearDown(self):
        self.svc.stop()
        self.sensor.stop()

    def transmit_sent(self):
        return sum(1 for d in self.sensor.received if d[:2] == b"KA" and d[6] == 5)

    def test_locked_control_does_nothing(self):
        with self.assertRaisesRegex(ActionRefused, "locked"):
            self.s.run_action("transmit_on", confirm="1", source="ui")
        time.sleep(0.3)
        self.assertEqual(self.transmit_sent(), 0)

    def test_arm_send_relocks(self):
        a = self.s.arm("transmit_on", source="ui", who="10.0.0.9")
        self.assertIn("START TRANSMITTING", a["effect"]) if "START" in a["effect"] else None
        r = self.s.run_action("transmit_on", confirm="1", token=a["token"], source="ui", who="10.0.0.9")
        self.assertTrue(r["ok"])
        self.assertTrue(wait_for(lambda: self.transmit_sent() == 1, 2))
        with self.assertRaisesRegex(ActionRefused, "locked"):   # one shot
            self.s.run_action("transmit_on", confirm="1", token=a["token"])
        kinds = [e["kind"] for e in self.s.events]
        self.assertIn("arm", kinds)
        self.assertIn("fire", kinds)
        ctl = [e for e in self.s.get_traffic(None, 100)["entries"] if e["direction"] == "ctl"]
        self.assertEqual([e["fields"]["what"] for e in ctl][:2], ["arm", "fire"])
        self.assertEqual(ctl[0]["fields"]["who"], "10.0.0.9")

    def test_arm_expires(self):
        with mock.patch.object(sm, "ARM_WINDOW_S", 0.2):
            a = self.s.arm("transmit_on", source="cli", who="op@host")
            self.assertTrue(wait_for(lambda: any(e["kind"] == "timeout" for e in self.s.events), 2))
            with self.assertRaisesRegex(ActionRefused, "locked"):
                self.s.run_action("transmit_on", confirm="1", token=a["token"])
        self.assertEqual(self.transmit_sent(), 0)

    def test_wrong_device_id_refuses_and_relocks(self):
        a = self.s.arm("transmit_on")
        with self.assertRaisesRegex(ActionRefused, "device ID"):
            self.s.run_action("transmit_on", confirm="2", token=a["token"])
        with self.assertRaisesRegex(ActionRefused, "locked"):
            self.s.run_action("transmit_on", confirm="1", token=a["token"])
        self.assertTrue(any(e["kind"] == "cancel" for e in self.s.events))
        self.assertEqual(self.transmit_sent(), 0)

    def test_disarm(self):
        self.s.arm("transmit_on")
        self.s.disarm("transmit_on", source="ui", who="10.0.0.9")
        self.assertEqual(self.s.arms, {})
        self.assertTrue(any(e["kind"] == "cancel" for e in self.s.events))

    def test_feature_false_hides(self):
        self.s.cfg.transmit_feature = False
        self.assertNotIn("transmit_on", self.s.actions())
        with self.assertRaisesRegex(ActionRefused, "feature flag"):
            self.s.arm("transmit_on")


class TestLatchCli(ApiTest):
    def setUp(self):
        self.sensor = FakeSensor(0.2).start()
        self.cfg = make_config(self.sensor.port, free_udp_port(), allow_transmit=True,
                               extra={"features": {"transmit_control": True}})
        self.svc = Service(self.cfg, sessions={
            sid: Session(sc, FakeProtocol({})) for sid, sc in self.cfg.sessions.items()})
        self.svc.start(http=True)
        self.base = "http://127.0.0.1:%d" % self.svc.httpd.server_address[1]
        self.assertTrue(wait_for(lambda: self.svc.sessions["sensor"].sock is not None, 2))

    def test_cli_without_arm_refuses_and_says_what_it_would_do(self):
        code, out, err = self.cli("action", "sensor", "transmit_on")
        self.assertEqual(code, 1)
        self.assertIn("locked", err)
        self.assertIn("--arm", err)

    def test_cli_arm_with_confirm(self):
        code, out, err = self.cli("action", "sensor", "transmit_on", "--arm", "--confirm", "1")
        self.assertEqual(code, 0, err)
        self.assertIn("ARMED", out)
        self.assertIn("Re-locked", out)
        code, out, err = self.cli("action", "sensor", "transmit_on", "--arm", "--confirm", "7")
        self.assertEqual(code, 1)
        self.assertIn("did not match", err)
        ev = self.svc.sessions["sensor"].get_events(50)
        self.assertTrue(any(e["kind"] == "fire" and e["source"] == "cli" for e in ev))

    def test_api_fire_without_token_refused(self):
        code, r = self.req("POST", "/api/sessions/sensor/actions/transmit_on", {"confirm": "1"})
        self.assertEqual(code, 403)
        code, a = self.req("POST", "/api/sessions/sensor/arm/transmit_on", {})
        self.assertEqual(code, 200)
        code, r = self.req("POST", "/api/sessions/sensor/actions/transmit_on",
                           {"confirm": "1", "token": a["token"]})
        self.assertEqual(code, 200, r)


class OwingProto(FakeProtocol):
    """Owes an answer to every Data message and never gives one."""

    def owes(self, msg):
        return "answer" if msg.name == "Data" else None


class TestOwedReplies(unittest.TestCase):
    def test_unanswered_message_becomes_a_problem(self):
        sensor = FakeSensor(0.2).start()
        cfg = make_config(sensor.port, free_udp_port())
        s = Session(cfg.sessions["sensor"], OwingProto({}))
        svc = Service(cfg, sessions={"sensor": s})
        try:
            with mock.patch.object(sm, "OWED_REPLY_S", 0.3):
                svc.start(http=False)
                self.assertTrue(wait_for(lambda: sensor.peer is not None, 2))
                sensor.send(b"DTx")
                self.assertTrue(wait_for(lambda: s.status()["problems"], 3))
            p = s.status()["problems"][0]["problem"]
            self.assertRegex(p, r"^owed: answer for Data from the device at \d\d:\d\d:\d\dZ, unanswered$")
            self.assertEqual(s.status()["owed_replies"]["missed"], 1)
        finally:
            svc.stop()
            sensor.stop()
