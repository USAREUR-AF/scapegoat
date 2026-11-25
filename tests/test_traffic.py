import unittest

from scapegoat import cli
from scapegoat.core import traffic
from scapegoat.core.session import Session
from scapegoat.core.service import Service
from tests.fakeproto import FakeProtocol, FakeSensor
from tests.helpers import free_udp_port, make_config, wait_for

# `tcpdump -nn -l -x -i any udp port 47000` on Ubuntu 24.04 (tcpdump 4.99): a keepalive
# out, and one back padded to the 46-byte Ethernet minimum (padding must be cut).
SAMPLE = """\
tcpdump: data link type LINUX_SLL2
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
12:00:01.123456 eth0  Out IP 192.0.2.177.47000 > 192.0.2.81.47000: UDP, length 16
\t0x0000:  4500 002c 1c46 4000 4011 0000 c000 02b1
\t0x0010:  c000 0251 b798 b798 0018 0000 4b41 1000
\t0x0020:  0001 0000 0000 0000 0000 00d1
12:00:01.130021 eth0  In  IP 192.0.2.81.47000 > 192.0.2.177.47000: UDP, length 16
\t0x0000:  4500 002c 0000 4000 4011 0000 c000 0251
\t0x0010:  c000 02b1 b798 b798 0018 0000 4b41 1001
\t0x0020:  0001 0001 0000 0000 0000 00d3 0000
2 packets captured
"""


class TestTcpdumpParser(unittest.TestCase):
    def test_parse_sample(self):
        pk = traffic.parse_tcpdump_x(SAMPLE)
        self.assertEqual(len(pk), 2)
        self.assertEqual(pk[0]["src"], "192.0.2.177:47000")
        self.assertEqual(pk[0]["dst"], "192.0.2.81:47000")
        self.assertEqual(pk[0]["payload"].hex(), "4b41100000010000000000000000" + "00d1")
        self.assertEqual(pk[1]["time"], "12:00:01.130021")
        self.assertEqual(len(pk[1]["payload"]), 16, "Ethernet padding is cut by UDP length")

    def test_non_udp_ignored(self):
        tcp = ("12:00:02.000000 IP 10.0.0.1.22 > 10.0.0.2.5000: Flags [S]\n"
               "\t0x0000:  4500 0028 0000 4000 4006 0000 0a00 0001\n"
               "\t0x0010:  0a00 0002 0016 1388 0000 0000 0000 0000\n")
        self.assertEqual(traffic.parse_tcpdump_x(tcp), [])

    def test_json_safe(self):
        self.assertEqual(traffic.json_safe({"a": b"\x01", "b": (1, 2), 3: object}),
                         {"a": "01", "b": [1, 2], "3": str(object)})


class TestTrafficLog(unittest.TestCase):
    def setUp(self):
        self.sensor = FakeSensor(0.2).start()
        self.cfg = make_config(self.sensor.port, free_udp_port(), forward=["127.0.0.1:9"])
        self.s = Session(self.cfg.sessions["sensor"], FakeProtocol({}))
        self.svc = Service(self.cfg, sessions={"sensor": self.s})
        self.svc.start(http=False)

    def tearDown(self):
        self.svc.stop()
        self.sensor.stop()

    def test_every_datagram_logged_and_since_paging(self):
        self.assertTrue(wait_for(lambda: self.s.state == "established", 5))
        all_ = self.s.get_traffic(None, 2000)
        dirs = {e["direction"] for e in all_["entries"]}
        self.assertEqual(dirs, {"tx", "rx", "fwd"})
        e = all_["entries"][0]
        for k in ("seq", "time", "direction", "peer", "length", "name", "ok", "problems",
                  "fields", "hex"):
            self.assertIn(k, e)
        seqs = [x["seq"] for x in all_["entries"]]
        self.assertEqual(seqs, sorted(seqs))
        mid = seqs[len(seqs) // 2]
        page = self.s.get_traffic(mid, 3)
        self.assertEqual([x["seq"] for x in page["entries"]], [mid + 1, mid + 2, mid + 3])
        self.assertEqual(self.s.get_traffic(all_["last_seq"] + 1000)["entries"], [])
        ka = next(x for x in all_["entries"] if x["direction"] == "rx")
        self.assertEqual(ka["name"], "KeepAlive")
        self.assertEqual(ka["length"], 8)


class TestWatchFormat(unittest.TestCase):
    KA = {"seq": 7, "time": "2026-11-21T11:00:50.099Z", "direction": "rx",
          "peer": "192.0.2.81:47000", "length": 10, "name": "KeepAlive",
          "ok": True, "problems": [], "hex": "4b410a000c000b000000",
          "fields": {"transmit_counter": 12, "receive_counter": 11, "action": 0, "flags": 0},
          "summary": "tx=12 rx=11"}

    def test_line_uses_the_protocol_summary(self):
        line = cli.format_entry(self.KA)
        self.assertTrue(line.startswith("11:00:50.099  <- 192.0.2.81:47000"), line)
        self.assertIn("KeepAlive", line)
        self.assertIn("tx=12 rx=11", line)
        self.assertNotIn("!!", line)

    def test_bad_fields_hex(self):
        e = dict(self.KA, ok=False, problems=["bad checksum"], direction="tx")
        out = cli.format_entry(e, fields=True, hexdump=True)
        self.assertIn("-> 192.0.2.81", out)
        self.assertIn("!! bad checksum", out)
        self.assertIn("      transmit_counter = 12", out)
        self.assertIn("      4b 41 0a 00", out)

    def test_no_summary_shows_up_to_six_fields(self):
        e = dict(self.KA, name="Data", fields={f"f{i}": i for i in range(9)})
        e.pop("summary")
        line = cli.format_entry(e)
        self.assertIn("f5=5", line)
        self.assertNotIn("f6=", line)


ICMP_SAMPLE = """\
12:00:01.123456 eth0  Out IP 198.51.100.212.47000 > 192.0.2.81.47000: UDP, length 16
\t0x0000:  4500 002c 1c46 4000 4011 0000 c633 64d4
\t0x0010:  c000 0251 b798 b798 0018 0000 4b41 1000
\t0x0020:  0001 0000 0000 0000 0000 00d1
12:00:01.125000 eth0  In  IP 198.51.100.1 > 198.51.100.212: ICMP host 192.0.2.81 unreachable, length 52
\t0x0000:  4500 0048 0000 0000 4001 0000 c633 6401
\t0x0010:  c633 64d4 0301 0000 0000 0000 4500 002c
"""


class TestIcmp(unittest.TestCase):
    def test_icmp_hex_not_glued_to_udp_packet(self):
        pk = traffic.parse_tcpdump_x(ICMP_SAMPLE)
        self.assertEqual(len(pk), 1)
        self.assertEqual(len(pk[0]["payload"]), 16)

    def test_unreachable_hint(self):
        u = traffic.icmp_unreachable(ICMP_SAMPLE)
        self.assertEqual(len(u), 1)
        self.assertEqual(u[0]["hint"], "The router 198.51.100.1 cannot find the sensor at "
                         "192.0.2.81: the sensor link not enabled, wrong address, or the sensor not on "
                         "that segment.")
