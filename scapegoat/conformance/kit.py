"""The conformance checks (see __init__.py)."""

from __future__ import annotations

import random

from scapegoat.core.protocol import LinkState

FUZZ_CASES = 400
FUZZ_SEED = 20261121


class ProtocolConformance:
    """Mix into a unittest.TestCase and define make_protocol()."""

    def make_protocol(self):  # pragma: no cover - provided by the test
        raise NotImplementedError

    def setUp(self):
        super().setUp()
        self.proto = self.make_protocol()

    # ---- decode ------------------------------------------------------------
    def test_decode_never_raises(self):
        rnd = random.Random(FUZZ_SEED)
        samples = [b"", b"\x00", b"\xff" * 3, bytes(range(256))]
        samples += [bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 300)))
                    for _ in range(FUZZ_CASES)]
        ka = self.proto.keepalive(LinkState())
        samples += [ka[:i] for i in range(len(ka))] + [ka + b"\x00" * 7, bytes(len(ka))]
        for data in samples:
            msg = self.proto.decode(data)
            self.assertIsInstance(msg.name, str)
            self.assertIsInstance(msg.problems, list)
            self.assertIsInstance(msg.ok, bool)

    # ---- keepalive ---------------------------------------------------------
    def test_keepalive_round_trip(self):
        link = LinkState()
        ka = self.proto.keepalive(link)
        self.assertIsInstance(ka, (bytes, bytearray))
        self.assertGreater(len(ka), 0)
        self.assertEqual(link.tx_counter, 1, "keepalive() must advance the sequence number once")
        msg = self.proto.decode(bytes(ka))
        self.assertTrue(msg.is_keepalive, msg.problems)
        self.assertTrue(msg.ok, msg.problems)
        self.assertEqual(msg.peer_tx_counter, link.tx_counter)

    def test_sequence_wraps_to_one(self):
        link = LinkState(tx_counter=65535)
        msg = self.proto.decode(bytes(self.proto.keepalive(link)))
        self.assertEqual(link.tx_counter, 1)
        self.assertEqual(msg.peer_tx_counter, 1)

    def test_peer_sequence_echoed(self):
        link = LinkState(rx_counter=4321)
        msg = self.proto.decode(bytes(self.proto.keepalive(link)))
        self.assertIn(4321, [v for v in (msg.fields or {}).values() if isinstance(v, int)]
                      + [v for v in (getattr(msg, "values", None) or {}).values() if isinstance(v, int)],
                      "a keepalive should carry the last peer sequence number we saw")

    # ---- actions -------------------------------------------------------------
    def test_actions_are_well_formed(self):
        acts = self.proto.actions()
        self.assertIsInstance(acts, dict)
        for name, spec in acts.items():
            self.assertEqual(spec.name, name)
            self.assertTrue(spec.label)
            if not spec.dangerous:
                data = self.proto.build_action(LinkState(), name)
                self.assertIsInstance(data, (bytes, bytearray))

    def test_on_receive_returns_bytes(self):
        link = LinkState()
        msg = self.proto.decode(bytes(self.proto.keepalive(LinkState())))
        out = self.proto.on_receive(link, msg)
        self.assertIsInstance(out, list)
        for d in out:
            self.assertIsInstance(d, (bytes, bytearray))

    # ---- optional hooks ------------------------------------------------------
    def test_split_two_keepalives(self):
        split = getattr(self.proto, "split", None)
        if not callable(split):
            self.skipTest("protocol has no split()")
        a = bytes(self.proto.keepalive(LinkState()))
        b = bytes(self.proto.keepalive(LinkState(tx_counter=7)))
        r = split(a + b)
        parts = list(r[0] if isinstance(r, tuple) else r)
        self.assertEqual(parts, [a, b])

    def test_hook_types(self):
        p = self.proto
        self.assertIsInstance(getattr(p, "peer_request_actions", {}) or {}, dict)
        self.assertIsInstance(tuple(getattr(p, "peer_status_fields", ()) or ()), tuple)
        self.assertTrue(all(isinstance(a, str) for a in (getattr(p, "transmit_actions", ()) or ())))
        marker = getattr(p, "sim_marker", None)
        self.assertTrue(marker is None or (isinstance(marker, tuple) and len(marker) == 2))
        msg = p.decode(bytes(p.keepalive(LinkState())))
        self.assertIsInstance(p.summarize(msg), str)
        self.assertGreater(float(getattr(p, "keepalive_interval_s", 0)), 0)
