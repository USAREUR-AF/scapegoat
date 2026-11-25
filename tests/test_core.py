import socket
import tempfile
import unittest
from pathlib import Path

from scapegoat.core import config as cfgmod
from scapegoat.core.protocol import LinkState, ProtocolError, load_protocol
from scapegoat.core.service import Service
from scapegoat.core.session import ActionFailed, ActionRefused, ActionUnknown, Session
from tests.fakeproto import FakeProtocol, FakeSensor
from tests.helpers import free_udp_port, make_config, wait_for


def start(cfg, sensor):
    sess = {sid: Session(sc, FakeProtocol(sc.protocol_settings))
            for sid, sc in cfg.sessions.items()}
    svc = Service(cfg, sessions=sess)
    svc.start(http=False)
    return svc, sess["sensor"]


class TestLinkState(unittest.TestCase):
    def test_counter_wraps_to_one(self):
        link = LinkState(tx_counter=65534)
        self.assertEqual(link.next_tx(), 65535)
        self.assertEqual(link.next_tx(), 1)
        self.assertEqual(LinkState().next_tx(), 1)


class TestConfig(unittest.TestCase):
    def test_toml_and_mapping_access(self):
        if cfgmod.tomllib is None:
            self.skipTest("no tomllib")
        text = Path(__file__).resolve().parent.parent.joinpath(
            "deploy", "scapegoat.example.toml").read_text()
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write(text)
        cfg = cfgmod.load(f.name)
        self.assertEqual(cfg.sessions["sensor"].peer_addr, ("127.0.0.1", 47001))
        self.assertFalse(cfg.sessions["sensor"].allow_transmit_control)
        self.assertEqual(cfg["sessions"]["sensor"]["protocol"], "toy")
        self.assertEqual(cfg.get("bind"), "127.0.0.1:8730")

    def test_json_config(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"sessions": {"a": {"protocol": "toy", "peer": "10.0.0.1:47000"}}}')
        sc = cfgmod.load(f.name).sessions["a"]
        self.assertEqual((sc.local, sc.local_addr), ("", ("0.0.0.0", 0)))   # protocol port at bind

    def test_errors_are_plain(self):
        with self.assertRaisesRegex(cfgmod.ConfigError, "peer is required"):
            cfgmod.from_dict({"sessions": {"a": {"protocol": "toy"}}})
        with self.assertRaisesRegex(cfgmod.ConfigError, "IP:PORT"):
            cfgmod.from_dict({"sessions": {"a": {"protocol": "toy", "peer": "10.0.0.1"}}})

    def test_missing_package(self):
        with self.assertRaises(ProtocolError):
            load_protocol("nosuchpkg", {})


class TestSession(unittest.TestCase):
    def setUp(self):
        self.sensor = FakeSensor(0.2).start()
        self.fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.fwd.bind(("127.0.0.1", 0))
        self.fwd.settimeout(2)
        fport = self.fwd.getsockname()[1]
        self.local = free_udp_port()
        self.cfg = make_config(self.sensor.port, self.local, [f"127.0.0.1:{fport}"])
        self.svc, self.s = start(self.cfg, self.sensor)

    def tearDown(self):
        self.svc.stop()
        self.sensor.stop()
        self.fwd.close()

    def test_handshake_degrade_lose_recover(self):
        s = self.s
        self.assertTrue(wait_for(lambda: s.state == "established", 5), s.status())
        states = [e["message"] for e in s.events if e["kind"] == "state"]
        self.assertTrue(any("handshaking -> establishing" in m for m in states), states)
        self.assertGreaterEqual(s.ka_rx_total, 3)
        # keepalives were sent FROM the session socket (the sensor replies to that address)
        self.assertEqual(self.sensor.peer, ("127.0.0.1", self.local))
        self.assertGreater(s.link.tx_counter, 0)
        self.assertGreater(s.link.rx_counter, 0)
        self.sensor.silent = True
        self.assertTrue(wait_for(lambda: s.state == "degraded", 2), s.state)
        self.assertTrue(wait_for(lambda: s.state == "lost", 2), s.state)
        n = len(self.sensor.received)
        self.assertTrue(wait_for(lambda: len(self.sensor.received) > n + 1, 2),
                        "lost must keep sending keepalives")
        self.sensor.silent = False
        self.assertTrue(wait_for(lambda: s.state == "established", 5), s.state)

    def test_forwarding_and_counts(self):
        self.assertTrue(wait_for(lambda: self.sensor.peer is not None, 3))
        self.sensor.send(b"DThello")
        got = set()
        while b"DThello" not in got:
            got.add(self.fwd.recvfrom(2048)[0])
        st = self.s.status()
        self.assertGreaterEqual(st["rx_by_name"].get("Data", 0), 1)
        self.assertGreaterEqual(st["tx_by_name"].get("KeepAlive", 0), 1)
        self.assertEqual(st["peer_seen"], f"127.0.0.1:{self.sensor.port}")
        self.assertGreater(st["forwarded"], 0)

    def test_bad_datagram_counted(self):
        self.assertTrue(wait_for(lambda: self.sensor.peer is not None, 3))
        self.sensor.send(b"KA\x00\x01\x00\x00\x00\xff")
        self.assertTrue(wait_for(lambda: self.s.bad_datagrams >= 1, 2))

    def test_actions_and_safety(self):
        self.assertTrue(wait_for(lambda: self.s.sock is not None, 2))
        r = self.s.run_action("ask_reply", source="cli")
        self.assertTrue(r["ok"])
        with self.assertRaises(ActionRefused):
            self.s.run_action("transmit_on", confirm=True, source="cli")
        with self.assertRaises(ActionUnknown):
            self.s.run_action("nope")
        ev = [e for e in self.s.events if e["kind"] in ("action", "refused")]
        self.assertTrue(any(e["source"] == "cli" and "ask_reply" in e["message"]
                            for e in ev))
        self.assertTrue(any("transmit_on refused" in e["message"] for e in ev))

    def test_feature_off_hides_and_refuses_even_with_allow_and_confirm(self):
        self.s.cfg.allow_transmit_control = True
        self.assertTrue(wait_for(lambda: self.s.sock is not None, 2))
        self.assertNotIn("transmit_on", self.s.actions())
        self.assertNotIn("transmit_on", [a["name"] for a in self.s.status()["actions"]])
        for name in ("transmit_on", "transmit_off"):
            with self.assertRaisesRegex(ActionRefused, r"features\.transmit_control = false"):
                self.s.run_action(name, confirm=True)

    def test_transmit_needs_allow_and_confirm(self):
        self.s.cfg.transmit_feature = True
        self.assertIn("transmit_on", self.s.actions())
        self.s.cfg.allow_transmit_control = True
        self.assertTrue(wait_for(lambda: self.s.sock is not None, 2))
        with self.assertRaisesRegex(ActionRefused, "locked"):
            self.s.run_action("transmit_on", confirm="1")
        tok = self.s.arm("transmit_on", source="cli", who="tester")["token"]
        self.assertTrue(self.s.run_action("transmit_on", confirm="1", token=tok)["ok"])

    def test_disable_enable_reset(self):
        s = self.s
        self.assertTrue(wait_for(lambda: s.state == "established", 5))
        s.disable(source="ui")
        self.assertEqual(s.state, "disabled")
        with self.assertRaises(ActionFailed):
            s.run_action("ping")
        s.enable(source="ui")
        self.assertTrue(wait_for(lambda: s.state == "established", 5), s.state)
        s.reset(source="ui")
        self.assertIn(s.state, ("handshaking", "establishing"))
        self.assertLessEqual(s.ka_rx_total, 1)
        self.assertTrue(wait_for(lambda: s.state == "established", 5), s.state)


if __name__ == "__main__":
    unittest.main()


SILENT = "127.0.0.2:9"  # never answers; traffic stays on this machine


class TestPeerCandidates(unittest.TestCase):
    def setUp(self):
        self.sensor = FakeSensor(0.2).start()
        self.cfg = make_config(self.sensor.port, free_udp_port(),
                               candidates=[SILENT, f"127.0.0.1:{self.sensor.port}"])
        self.svc, self.s = start(self.cfg, self.sensor)

    def tearDown(self):
        self.svc.stop()
        self.sensor.stop()

    def silent_link(self):
        return self.s.links[("127.0.0.2", 9)]

    def test_probe_all_then_lock_first_answer(self):
        s = self.s
        self.assertTrue(wait_for(lambda: s.locked is not None, 3))
        self.assertEqual(s.locked, ("127.0.0.1", self.sensor.port))
        self.assertTrue(any(e["kind"] == "lock" and "locked onto 127.0.0.1" in e["message"]
                            for e in s.events))
        self.assertGreaterEqual(self.silent_link().tx_counter, 1, "silent candidate was probed")
        before = self.silent_link().tx_counter
        self.assertTrue(wait_for(lambda: s.state == "established", 5))
        self.assertEqual(self.silent_link().tx_counter, before, "no keepalives to others once locked")
        st = s.status()
        self.assertEqual(st["locked"], f"127.0.0.1:{self.sensor.port}")
        self.assertEqual([c["locked"] for c in st["candidates"]], [False, True])
        # each candidate keeps its own counters
        self.assertGreater(st["candidates"][1]["rx_counter"], 0)
        self.assertEqual(st["candidates"][0]["rx_counter"], 0)

    def test_force_lock_and_reset_unlocks(self):
        s = self.s
        self.assertTrue(wait_for(lambda: s.state == "established", 5))
        s.force_lock(SILENT, source="cli")
        self.assertEqual(s.locked, ("127.0.0.2", 9))
        self.assertTrue(wait_for(lambda: s.state in ("handshaking",), 1))
        n = len(self.sensor.received)
        import time
        time.sleep(0.5)
        self.assertLessEqual(len(self.sensor.received), n + 1, "real sensor no longer probed")
        s.reset(source="cli")
        self.assertIsNone(s.locked)
        self.assertTrue(wait_for(lambda: s.locked == ("127.0.0.1", self.sensor.port), 3))
        with self.assertRaises(ActionFailed):
            s.force_lock("not-an-address")


class TestProfiles(unittest.TestCase):
    def write(self, d, name, text):
        p = Path(d) / name
        p.write_text(text)
        return str(p)

    def test_shipped_profiles_parse_and_list(self):
        if cfgmod.tomllib is None:
            self.skipTest("no tomllib")
        profs = {p["name"]: p for p in cfgmod.list_profiles("/nonexistent")}
        self.assertIn("sim-local", profs)
        self.assertTrue(profs["sim-local"]["description"])
        cfg = cfgmod.from_dict(cfgmod._read(profs["sim-local"]["path"]))
        self.assertEqual(cfg.sessions["sensor"].protocol, "toy")
        with self.assertRaisesRegex(cfgmod.ConfigError, "topology"):
            cfgmod.from_dict({"topology": "bridged"})

    def test_site_overrides_profile(self):
        if cfgmod.tomllib is None:
            self.skipTest("no tomllib")
        with tempfile.TemporaryDirectory() as d:
            self.write(d, "base.toml", '# base\nnode_name = "p"\n[sessions.sensor]\n'
                       'protocol = "fake"\npeer_candidates = ["10.0.0.1:47000"]\n'
                       '[sessions.sensor.protocol_settings]\ndevice_id = 1\ninterface = "A"\n')
            site = self.write(d, "site.toml", f'profile = "base"\nprofiles_dir = "{d}"\n'
                              'node_name = "site"\n[sessions.sensor.protocol_settings]\ndevice_id = 7\n')
            cfg = cfgmod.load(site)
            ps = cfg.sessions["sensor"].protocol_settings
            self.assertEqual((cfg.node_name, ps["device_id"], ps["interface"]), ("site", 7, "A"))
            self.assertEqual(cfg.profile, "base")
            # CLI --profile wins over the file's profile key
            self.write(d, "other.toml", '[sessions.sensor]\nprotocol = "fake"\npeer = "10.0.0.9:1"\n')
            other = cfgmod.load(site, profile="other").sessions["sensor"]
            self.assertEqual(other.candidate_addrs, [("10.0.0.9", 1)])
            with self.assertRaisesRegex(cfgmod.ConfigError, "Available"):
                cfgmod.load(site, profile="nope")

    def test_only_session(self):
        cfg = cfgmod.from_dict({"sessions": {
            "a": {"protocol": "fake", "peer": "127.0.0.1:1", "enabled": False},
            "b": {"protocol": "fake", "peer": "127.0.0.1:2", "enabled": False}}})
        self.assertEqual(list(Service(cfg, only_session="b").sessions), ["b"])
        with self.assertRaises(KeyError):
            Service(cfg, only_session="zzz")


class TestSurfacing(unittest.TestCase):
    """Problems and peer requests with a stand-in decoded message (no protocol plugin needed)."""

    def make(self):
        cfg = make_config(free_udp_port(), free_udp_port())
        s = Session(cfg.sessions["sensor"], FakeProtocol({}))
        return s

    def test_problem_rate_limit(self):
        from scapegoat.core import session as sm
        s = self.make()
        for i in range(5):
            s._note_problem("KeepAlive: device_id 9 does not match configured device_id 7", 100.0 + i)
        ev = [e for e in s.events if e["kind"] == "problem"]
        self.assertEqual(len(ev), 1)
        s._note_problem("KeepAlive: device_id 9 does not match configured device_id 7",
                        100.0 + sm.REPEAT_LOG_EVERY_S + 1)
        ev = [e for e in s.events if e["kind"] == "problem"]
        self.assertEqual(len(ev), 2)
        self.assertIn("seen 6 times", ev[-1]["message"])
        self.assertEqual(s.status()["problems"][0]["count"], 6)

    def test_peer_request_and_status(self):
        from types import SimpleNamespace
        s = self.make()
        s.protocol.actions = lambda: {"transmit_on": __import__(
            "scapegoat.core.protocol", fromlist=["ActionSpec"]).ActionSpec("transmit_on", "On", True)}
        msg = SimpleNamespace(fields={"request": "Peer asks to transmit",
                                      "sensor_status": "Not transmitting"},
                              values={"request": 4})
        s._on_peer_keepalive_fields(msg, 10.0)
        st = s.status()
        self.assertIsNone(st["peer_request"]["suggested_action"], "feature off: no button")
        self.assertEqual(st["peer_request"]["disabled_reason"],
                         "transmit control is disabled on this node")
        s.cfg.transmit_feature = True
        st = s.status()
        self.assertEqual(st["peer_request"]["suggested_action"], "transmit_on")
        self.assertEqual(st["peer_request"]["disabled_reason"], "")
        self.assertEqual(st["peer_status"]["sensor_status"], "Not transmitting")
        msg.fields["request"] = "None"
        msg.values["request"] = 0
        s._on_peer_keepalive_fields(msg, 11.0)
        self.assertIsNone(s.status()["peer_request"])
        self.assertEqual(len([e for e in s.events if e["message"].startswith("peer requests")]), 1)

    def test_status_cli_line_feature_off(self):
        from scapegoat import cli
        st = {"id": "sensor", "actions": [], "problems": [],
              "peer_request": {"label": "Peer asks to transmit", "code": 4, "count": 1,
                               "suggested_action": None,
                               "disabled_reason": "transmit control is disabled on this node"}}
        self.assertEqual(cli._attention_lines(st), [
            "DEVICE IS ASKING: Peer asks to transmit  (transmit control is disabled on this node)"])

    def test_features_config(self):
        self.assertFalse(cfgmod.from_dict({"sessions": {"a": {"protocol": "x", "peer": "203.0.113.4:1"}}}
                                          ).sessions["a"].transmit_feature)
        on = cfgmod.from_dict({"features": {"transmit_control": True},
                               "sessions": {"a": {"protocol": "x", "peer": "203.0.113.4:1"}}})
        self.assertTrue(on.sessions["a"].transmit_feature)
        with self.assertRaises(cfgmod.ConfigError):
            cfgmod.from_dict({"features": {"transmit_control": "yes"}})
        for p in cfgmod.list_profiles("/nonexistent"):
            if cfgmod.tomllib is not None:
                self.assertIs(cfgmod._read(p["path"])["features"]["transmit_control"], True, p)

    def test_status_cli_lines(self):
        from scapegoat import cli
        st = {"id": "sensor", "actions": [{"name": "transmit_on", "dangerous": True, "allowed": False}],
              "peer_request": {"label": "Peer asks to transmit", "code": 4, "count": 3,
                               "suggested_action": "transmit_on"},
              "problems": [{"problem": "x", "count": 2}]}
        lines = cli._attention_lines(st)
        self.assertEqual(lines[0], "DEVICE IS ASKING: Peer asks to transmit  -> scapegoat "
                                   "action sensor transmit_on --confirm  (needs allow_transmit_control = true)")
        self.assertEqual(lines[1], "PROBLEM: x (x2)")


class TestPeerKind(unittest.TestCase):
    def make(self, peer="192.0.2.81:47000"):
        cfg = cfgmod.from_dict({"sessions": {"sensor": {"protocol": "fake", "peer": peer,
                                                     "local": "127.0.0.1:0"}}})
        return Session(cfg.sessions["sensor"], FakeProtocol({}))

    def ka(self, urn, rid=3):
        from types import SimpleNamespace
        return SimpleNamespace(fields={"sim_tag": urn, "device_id": rid},
                               values={"sim_tag": urn, "device_id": rid})

    def test_a_protocol_names_its_device(self):
        """The core knows no device type: a protocol names it, the setting holding its ID
        and the keepalive field carrying the peer's ID."""
        class PumpProtocol(FakeProtocol):
            device_noun, device_id_setting, peer_id_field = "pump", "pump_no", "unit"
        cfg = cfgmod.from_dict({"sessions": {"sensor": {"protocol": "fake", "peer": "192.0.2.81:47000",
                                                     "local": "127.0.0.1:0",
                                                     "protocol_settings": {"pump_no": 12}}}})
        s = Session(cfg.sessions["sensor"], PumpProtocol({}))
        self.assertEqual((s.kind_none, s.kind_real, s.device_id), ("no pump yet", "REAL PUMP", 12))
        from types import SimpleNamespace
        s.peer_seen = ("192.0.2.81", 47000)
        s._on_peer_keepalive_fields(SimpleNamespace(fields={"sim_tag": 0, "unit": 5},
                                                    values={"sim_tag": 0, "unit": 5}), 1.0)
        st = s.status()
        self.assertEqual((st["peer_kind"], st["peer_is_real"], st["peer_device_id"], st["device_noun"]),
                         ("REAL PUMP", True, 5, "pump"))

    def test_kinds(self):
        from scapegoat.core.session import KIND_SIM
        s = self.make()
        self.assertEqual((s.kind_none, s.kind_real), ("no device yet", "REAL DEVICE"))
        self.assertEqual(s.peer_kind(), s.kind_none)
        s.peer_seen = ("192.0.2.81", 47000)
        s._on_peer_keepalive_fields(self.ka(0), 1.0)
        self.assertEqual(s.peer_kind(), s.kind_real)
        st = s.status()
        self.assertEqual((st["peer_kind"], st["peer_device_id"]), ("REAL DEVICE", 3))
        s._on_peer_keepalive_fields(self.ka(0xFFFFFF), 2.0)
        self.assertEqual(s.peer_kind(), KIND_SIM, "simulator mark wins on any address")
        s2 = self.make("127.0.0.1:47001")
        s2.peer_seen = ("127.0.0.1", 47001)
        s2._on_peer_keepalive_fields(self.ka(0), 1.0)
        self.assertEqual(s2.peer_kind(), KIND_SIM, "loopback peer is a simulator")
        s2._log_kind()
        self.assertTrue(any(e["kind"] == "kind" and "SIMULATOR" in e["message"] for e in s2.events))

    def test_cli_banner_and_column(self):
        from scapegoat import cli
        self.assertEqual(cli._kind_banner({"peer_kind": "REAL DEVICE", "peer_seen": "192.0.2.81:47000",
                                           "peer_device_id": 3}),
                         "### REAL DEVICE 192.0.2.81:47000 (Device ID 3) ###")
        self.assertIn("SIMULATOR", cli._kind_banner({"peer_kind": "SIMULATOR"}))


class TestLocalSeenAs(unittest.TestCase):
    def test_wildcard_bind_uses_source_toward_peer(self):
        cfg = cfgmod.from_dict({"sessions": {"sensor": {"protocol": "fake", "peer": "127.0.0.1:47001",
                                                     "local": "0.0.0.0:47000"}}})
        self.assertEqual(Session(cfg.sessions["sensor"], FakeProtocol({})).local_seen_as(),
                         "127.0.0.1:47000")
        cfg = cfgmod.from_dict({"sessions": {"sensor": {"protocol": "fake", "peer": "127.0.0.1:47001",
                                                     "local": "198.51.100.105:47000"}}})
        self.assertEqual(Session(cfg.sessions["sensor"], FakeProtocol({})).local_seen_as(),
                         "198.51.100.105:47000")
        self.assertEqual(cfgmod.from_dict({"node_role": " C2 node "}).node_role, "C2 node")




class TestConfigAliases(unittest.TestCase):
    """A plugin's CONFIG_ALIASES keeps its old key names working."""

    def setUp(self):
        from scapegoat.core import plugins
        self.plugins = plugins
        self.saved = plugins.config_aliases
        table = {"session": {"old_allow": "allow_transmit_control"},
                 "features": {"old_feature": "transmit_control"}}
        plugins.config_aliases = lambda section, protocol=None: dict(table.get(section, {}))

    def tearDown(self):
        self.plugins.config_aliases = self.saved

    def test_old_names_are_read(self):
        from scapegoat.core import config as cfgmod
        cfg = cfgmod.from_dict({"features": {"old_feature": True},
                                "sessions": {"a": {"protocol": "toy", "peer": "127.0.0.1:47001",
                                                   "old_allow": True}}})
        self.assertTrue(cfg.sessions["a"].transmit_feature)
        self.assertTrue(cfg.sessions["a"].allow_transmit_control)

    def test_both_names_is_an_error(self):
        from scapegoat.core import config as cfgmod
        with self.assertRaisesRegex(cfgmod.ConfigError, "not both"):
            cfgmod.from_dict({"sessions": {"a": {"protocol": "toy", "peer": "127.0.0.1:47001",
                                                 "old_allow": True, "allow_transmit_control": True}}})
