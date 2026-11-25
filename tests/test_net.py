"""Tests for scapegoat.net. subprocess is mocked throughout: nothing touches the real network."""

import json
import subprocess
import unittest
from unittest import mock

from scapegoat.net import _common, control, probe, visibility

IP_ADDR = json.loads("""[
 {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"operstate":"UNKNOWN",
  "link_type":"loopback","address":"00:00:00:00:00:00",
  "addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host","label":"lo"}]},
 {"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,
  "operstate":"UP","link_type":"ether","address":"dc:a6:32:00:00:01",
  "addr_info":[{"family":"inet","local":"10.10.0.5","prefixlen":24,"scope":"global","dynamic":true,
                "label":"eth0","valid_life_time":86000,"preferred_life_time":86000},
               {"family":"inet6","local":"fe80::dea6:32ff:fe00:1","prefixlen":64,"scope":"link"}]},
 {"ifindex":3,"ifname":"wlan0","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,
  "operstate":"DOWN","link_type":"ether","address":"dc:a6:32:00:00:02","addr_info":[]}
]""")
IP_LINK = [{k: v for k, v in i.items() if k != "addr_info"} for i in IP_ADDR]
IP_NEIGH = json.loads("""[
 {"dst":"10.10.0.1","dev":"eth0","lladdr":"00:11:22:33:44:55","state":["REACHABLE"]},
 {"dst":"192.0.2.81","dev":"eth0","state":["FAILED"]}
]""")
IP_ROUTE = json.loads("""[
 {"dst":"default","gateway":"10.10.0.1","dev":"eth0","protocol":"dhcp","prefsrc":"10.10.0.5","metric":100},
 {"dst":"10.10.0.0/24","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"10.10.0.5"}
]""")
ROUTE_GET_VIA_GW = [{"dst": "192.0.2.81", "gateway": "10.10.0.1", "dev": "eth0",
                     "prefsrc": "10.10.0.5", "flags": [], "uid": 0, "cache": []}]
ROUTE_GET_DIRECT = [{"dst": "192.0.2.81", "dev": "eth0", "prefsrc": "192.0.2.10",
                     "flags": [], "uid": 0, "cache": []}]
SS_EMPTY = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" \
           "UNCONN 0      0      127.0.0.53%lo:53      0.0.0.0:*     users:((\"systemd-resolve\",pid=500,fd=13))\n"
SS_SCAPEGOAT = SS_EMPTY + \
    "UNCONN 0      0            0.0.0.0:47000   0.0.0.0:*     users:((\"python3\",pid=900,fd=5))\n"
UFW_ACTIVE = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
"""

TCPDUMP_OUT = """\
12:00:01.123456 eth0  Out IP 192.0.2.10.47000 > 192.0.2.81.47000: UDP, length 16
12:00:01.130001 eth0  In  IP 192.0.2.81.47000 > 192.0.2.10.47000: UDP, length 16
12:00:02.000000 IP 192.0.2.81.47000 > 192.0.2.10.47000: UDP, length 48
12:00:03.000000 IP6 fe80::1.47000 > fe80::2.47000: UDP, length 16
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
"""

CONFIG = {"allow_net_control": False, "node_name": "t", "topology": "same-lan",
          "sessions": {"sensor": {"protocol": "toy", "local": "0.0.0.0:47000",
                               "peer": "192.0.2.81:47000"}}}


def completed(args, out="", rc=0, err=""):
    return subprocess.CompletedProcess(args, rc, out, err)


class FakeHost:
    """Answers subprocess.run for a Linux-shaped host."""

    def __init__(self, addr=IP_ADDR, route_get=ROUTE_GET_VIA_GW, ss=SS_EMPTY, ufw=UFW_ACTIVE,
                 tools=("ip", "ss", "ufw", "tcpdump", "ping")):
        self.addr, self.route_get, self.ss, self.ufw = addr, route_get, ss, ufw
        self.tools = set(tools)
        self.carriers = {}
        self.calls = []

    def run(self, args, **kw):
        assert isinstance(args, list), "must pass a list, never a string"
        assert not kw.get("shell"), "shell=True is forbidden"
        assert "timeout" in kw, "every call needs a timeout"
        self.calls.append(args)
        if args[:3] == ["ip", "-j", "addr"]:
            return completed(args, json.dumps(self.addr))
        if args[:3] == ["ip", "-j", "link"]:
            return completed(args, json.dumps(IP_LINK))
        if args[:3] == ["ip", "-j", "neigh"]:
            return completed(args, json.dumps(IP_NEIGH))
        if args[:4] == ["ip", "-j", "route", "get"]:
            return completed(args, json.dumps(self.route_get))
        if args[:3] == ["ip", "-j", "route"]:
            return completed(args, json.dumps(getattr(self, "routes", IP_ROUTE)))
        if args[0] == "ss":
            return completed(args, self.ss)
        if args[:2] == ["ufw", "status"]:
            return completed(args, self.ufw)
        if args[0] == "tcpdump":
            raise subprocess.TimeoutExpired(args, kw["timeout"], output=TCPDUMP_OUT, stderr="")
        if args[0] == "ping":
            return completed(args, "PING 10.10.0.1 56(84) bytes of data.\n"
                                   "64 bytes from 10.10.0.1: icmp_seq=1 ttl=64 time=0.41 ms\n\n"
                                   "--- 10.10.0.1 ping statistics ---\n"
                                   "3 packets transmitted, 3 received, 0% packet loss, time 1002ms\n"
                                   "rtt min/avg/max/mdev = 0.380/0.412/0.450/0.029 ms\n")
        return completed(args, "", 0)

    def which(self, name):
        return f"/usr/bin/{name}" if name in self.tools else None

    def sysfs(self, path):
        if path.endswith("/carrier"):
            name = path.split("/")[4]
            return self.carriers.get(name, "0" if name == "wlan0" else "1")
        if "/statistics/" in path:
            return "42"
        return None

    def patches(self):
        return [mock.patch.object(_common.subprocess, "run", side_effect=self.run),
                mock.patch.object(_common.shutil, "which", side_effect=self.which),
                mock.patch.object(_common, "read_sys", side_effect=self.sysfs),
                mock.patch.object(_common, "list_interfaces", return_value=["eth0", "lo", "wlan0"]),
                mock.patch.object(probe.platform, "system", return_value="Linux")]


class Base(unittest.TestCase):
    host = None

    def setUp(self):
        self.host = self.make_host()
        for p in self.host.patches():
            p.start()
            self.addCleanup(p.stop)
        control._AUDIT.clear()

    def make_host(self):
        return FakeHost()


class TestSnapshot(Base):
    def test_sections_and_interfaces(self):
        s = visibility.snapshot(CONFIG)
        for key in ("host", "interfaces", "neighbors", "routes", "sessions", "firewall", "hints"):
            self.assertIn(key, s)
        eth0 = next(i for i in s["interfaces"] if i["name"] == "eth0")
        self.assertTrue(eth0["carrier"])
        self.assertEqual(eth0["mac"], "dc:a6:32:00:00:01")
        self.assertIn("10.10.0.5/24", [a["cidr"] for a in eth0["addresses"]])
        self.assertEqual(eth0["stats"]["rx_bytes"], 42)
        wlan = next(i for i in s["interfaces"] if i["name"] == "wlan0")
        self.assertFalse(wlan["carrier"])

    def test_subnet_hint_when_not_in_peer_subnet(self):
        s = visibility.snapshot(CONFIG)
        sess = s["sessions"][0]
        self.assertEqual(sess["same_subnet"], [])
        text = " ".join(sess["hints"])
        self.assertIn("192.0.2.0/24", text)
        self.assertIn("scapegoat net addr_add --iface eth0", text)
        self.assertIn("gateway 10.10.0.1", text)
        self.assertIn("Nothing is listening on UDP 47000", text)
        self.assertIn("ufw is active", text)

    def test_neighbor_failed_on_direct_route(self):
        addr = json.loads(json.dumps(IP_ADDR))
        addr[1]["addr_info"].append({"family": "inet", "local": "192.0.2.10", "prefixlen": 24})
        self.host.addr, self.host.route_get, self.host.ss = addr, ROUTE_GET_DIRECT, SS_SCAPEGOAT
        sess = visibility.snapshot(CONFIG)["sessions"][0]
        self.assertEqual(sess["same_subnet"], [{"iface": "eth0", "cidr": "192.0.2.10/24"}])
        text = " ".join(sess["hints"])
        self.assertNotIn("No address on any interface", text)
        self.assertNotIn("Nothing is listening", text)
        self.assertIn("does not answer ARP", text)

    def test_no_carrier_hint(self):
        rg = [{"dst": "192.0.2.81", "dev": "wlan0", "prefsrc": "192.0.2.10"}]
        addr = json.loads(json.dumps(IP_ADDR))
        addr[2]["addr_info"].append({"family": "inet", "local": "192.0.2.10", "prefixlen": 24})
        self.host.addr, self.host.route_get = addr, rg
        hints = visibility.snapshot(CONFIG)["sessions"][0]["hints"]
        self.assertTrue(any("wlan0 has no carrier" in h for h in hints), hints)

    def test_section_failure_is_isolated(self):
        orig = self.host.run

        def broken(args, **kw):
            if args[:3] == ["ip", "-j", "neigh"]:
                return completed(args, "", 1, "RTNETLINK answers: boom")
            return orig(args, **kw)
        self.host.run = broken
        with mock.patch.object(_common.subprocess, "run", side_effect=broken):
            s = visibility.snapshot(CONFIG)
        self.assertIn("error", s["neighbors"])
        self.assertIsInstance(s["interfaces"], list)
        self.assertIsInstance(s["sessions"], list)

    def test_attribute_config_and_bad_peer(self):
        class S:
            local, peer, protocol = "0.0.0.0:47000", "not-an-ip:1", "toy"

        class C:
            allow_net_control = False
            sessions = {"x": S()}
        s = visibility.snapshot(C())
        self.assertIn("error", s["sessions"][0])

    def test_no_tools_never_crashes(self):
        self.host.tools = set()
        s = visibility.snapshot(CONFIG)
        self.assertIn("error", s["interfaces"])
        self.assertIsInstance(s["sessions"], list)


class TestCandidatesAndExpectedLocal(Base):
    CANDS = {"allow_net_control": False,
             "sessions": {"sensor": {"protocol": "toy", "local": "0.0.0.0:47000",
                                  "peer_candidates": ["192.0.2.81:47000",
                                                      "192.0.2.74:47000"]}}}

    def route_gets(self):
        return [c[-1] for c in self.host.calls if c[:4] == ["ip", "-j", "route", "get"]]

    def test_every_candidate_checked(self):
        sess = visibility.snapshot(dict(self.CANDS, topology="same-lan"))["sessions"][0]
        self.assertEqual([p["ip"] for p in sess["peers"]], ["192.0.2.81", "192.0.2.74"])
        self.assertEqual(sess["peer_ip"], "192.0.2.81")
        self.assertEqual(self.route_gets()[-2:], ["192.0.2.81", "192.0.2.74"])
        for p in sess["peers"]:
            self.assertIn("neighbor", p)
            self.assertEqual(p["same_subnet"], [])
        # both candidates share one /24: one subnet hint naming both
        sub = [h for h in sess["hints"] if "No address on any interface is in 192.0.2.0/24" in h]
        self.assertEqual(len(sub), 1)
        self.assertIn("peers 192.0.2.81, 192.0.2.74", sub[0])
        self.assertEqual(len(sess["hints"]), len(set(sess["hints"])))

    def test_peer_and_candidates_deduplicated(self):
        cfg = {"sessions": {"sensor": {"local": "0.0.0.0:47000", "peer": "192.0.2.81:47000",
                                    "peer_candidates": ["192.0.2.81:47000",
                                                        "192.0.2.74:47000", "bogus"]}}}
        sess = visibility.snapshot(cfg)["sessions"][0]
        self.assertEqual(len(sess["peers"]), 2)
        self.assertTrue(any("'bogus'" in h for h in sess["hints"]))

    def test_expected_local_missing(self):
        cfg = dict(self.CANDS, expected_local_address="192.0.2.177/24")
        s = visibility.snapshot(cfg)
        self.assertFalse(s["expected_local"]["present"])
        self.assertIn("This node should hold 192.0.2.177/24 on the interface toward the sensor "
                      "(the sensor learns our address from our keepalives). Add it: scapegoat net "
                      "addr_add --iface eth0 --cidr 192.0.2.177/24 --confirm", s["hints"])
        self.assertFalse(any(c[:3] == ["ip", "addr", "add"] for c in self.host.calls))

    def test_expected_local_present(self):
        addr = json.loads(json.dumps(IP_ADDR))
        addr[1]["addr_info"].append({"family": "inet", "local": "192.0.2.177", "prefixlen": 24})
        self.host.addr, self.host.route_get = addr, ROUTE_GET_DIRECT
        cfg = dict(self.CANDS, expected_local_address="192.0.2.177/24")
        s = visibility.snapshot(cfg)
        self.assertEqual(s["expected_local"]["on"], ["eth0"])
        self.assertTrue(s["expected_local"]["present"])
        self.assertFalse(any("should hold" in h for h in s["hints"]))

    def test_expected_local_wrong_prefix(self):
        addr = json.loads(json.dumps(IP_ADDR))
        addr[1]["addr_info"].append({"family": "inet", "local": "192.0.2.177", "prefixlen": 16})
        self.host.addr = addr
        cfg = dict(self.CANDS, expected_local_address="192.0.2.177/24")
        el = visibility.snapshot(cfg)["expected_local"]
        self.assertFalse(el["present"])
        self.assertIn("prefix differs", el["hints"][0])

    def test_expected_local_unset_and_bad(self):
        self.assertIsNone(visibility.snapshot(self.CANDS)["expected_local"])
        el = visibility.snapshot(dict(self.CANDS, expected_local_address="nonsense"))["expected_local"]
        self.assertIn("error", el)


class TestSensorFacing(Base):
    EXP = dict(TestCandidatesAndExpectedLocal.CANDS, expected_local_address="192.0.2.177/24")

    def test_expected_key_missing_then_present(self):
        s = visibility.snapshot(self.EXP)
        self.assertEqual(s["expected_local_address"], {"cidr": "192.0.2.177/24",
                                                       "present_on": None})
        addr = json.loads(json.dumps(IP_ADDR))
        addr[1]["addr_info"].append({"family": "inet", "local": "192.0.2.177", "prefixlen": 24})
        self.host.addr, self.host.route_get = addr, ROUTE_GET_DIRECT
        s = visibility.snapshot(self.EXP)
        self.assertEqual(s["expected_local_address"], {"cidr": "192.0.2.177/24",
                                                       "present_on": "eth0"})
        self.assertIsNone(visibility.snapshot(TestCandidatesAndExpectedLocal.CANDS)
                          ["expected_local_address"])

    def test_iface_choice_skips_wireless_and_virtual(self):
        ifaces = [{"name": "lo", "carrier": True}, {"name": "wlan0", "carrier": True},
                  {"name": "wt0", "carrier": True}, {"name": "veth12", "carrier": True},
                  {"name": "podman0", "carrier": True}, {"name": "eth1", "carrier": False},
                  {"name": "eth0", "carrier": True}]
        self.assertEqual(visibility.sensor_iface_choice(ifaces), "eth0")
        self.assertEqual(visibility.sensor_iface_choice(ifaces[:6]), "<iface>")

    def test_no_eligible_iface_writes_placeholder(self):
        self.host.carriers = {"eth0": "0"}
        s = visibility.snapshot(self.EXP)
        self.assertIn("This node should hold 192.0.2.177/24 on the interface toward the sensor "
                      "(the sensor learns our address from our keepalives). Add it: scapegoat net "
                      "addr_add --iface <iface> --cidr 192.0.2.177/24 --confirm", s["hints"])

    def test_subnet_hint_suggests_expected_address(self):
        hints = visibility.snapshot(self.EXP)["sessions"][0]["hints"]
        sub = [h for h in hints if h.startswith("No address on any interface")]
        self.assertEqual(len(sub), 1)
        self.assertIn("--cidr 192.0.2.177/24", sub[0])
        self.assertNotIn("192.0.2.10/24", sub[0])

    def test_sensor_facing_no_carrier(self):
        addr = json.loads(json.dumps(IP_ADDR))
        addr[1]["addr_info"].append({"family": "inet", "local": "192.0.2.177", "prefixlen": 24})
        self.host.addr, self.host.route_get = addr, ROUTE_GET_DIRECT
        self.host.carriers = {"eth0": "0"}
        hints = visibility.snapshot(self.EXP)["hints"]
        self.assertIn("eth0 has no carrier: check the cable to the sensor network switch", hints)
        self.assertEqual(sum("has no carrier" in h for h in hints), 1)
        self.assertFalse(any(h.startswith("wlan0 has no carrier") for h in hints))

    def test_no_carrier_before_any_address(self):
        # sensor subnet not configured yet and the only wired port is dark
        self.host.carriers = {"eth0": "0"}
        hints = visibility.snapshot(TestCandidatesAndExpectedLocal.CANDS)["hints"]
        self.assertIn("eth0 has no carrier: check the cable to the sensor network switch", hints)


class TestParsers(unittest.TestCase):
    def test_tcpdump(self):
        pkts = probe.parse_tcpdump(TCPDUMP_OUT)
        self.assertEqual(len(pkts), 4)
        self.assertEqual(pkts[0], {"time": "12:00:01.123456", "src": "192.0.2.10",
                                   "src_port": 47000, "dst": "192.0.2.81", "dst_port": 47000,
                                   "length": 16, "iface": "eth0", "direction": "Out"})
        self.assertNotIn("iface", pkts[2])
        self.assertEqual(pkts[2]["length"], 48)
        self.assertEqual(pkts[3]["src"], "fe80::1")
        self.assertIsNone(probe.parse_tcpdump_line("garbage line"))
        self.assertEqual(len(probe.parse_tcpdump(TCPDUMP_OUT, max_packets=2)), 2)

    def test_ss(self):
        rows = visibility.parse_ss(SS_SCAPEGOAT)
        mine = [r for r in rows if r["port"] == 47000]
        self.assertEqual(mine[0]["process"], "python3")
        self.assertEqual(mine[0]["pid"], 900)

    def test_ifconfig(self):
        text = ("en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
                "\tether aa:bb:cc:dd:ee:ff\n"
                "\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n"
                "\tstatus: active\n")
        r = visibility.parse_ifconfig(text)
        self.assertEqual(r[0]["addresses"][0]["cidr"], "192.0.2.10/24")
        self.assertTrue(r[0]["carrier"])

    def test_split_hostport(self):
        self.assertEqual(_common.split_hostport("192.0.2.81:47000"), ("192.0.2.81", 47000))
        self.assertEqual(_common.split_hostport("[fe80::1]:47000"), ("fe80::1", 47000))
        with self.assertRaises(_common.ValidationError):
            _common.split_hostport("192.0.2.81:99999")


class TestProbe(Base):
    def test_ping(self):
        r = probe.ping("10.10.0.1")
        self.assertTrue(r["reachable"])
        self.assertEqual((r["sent"], r["received"]), (3, 3))
        self.assertAlmostEqual(r["rtt_avg_ms"], 0.412)

    def test_ping_rejects_bad_ip(self):
        with self.assertRaises(_common.ValidationError):
            probe.ping("10.0.0.1; reboot")
        self.assertEqual(self.host.calls, [])

    def test_capture(self):
        r = probe.capture(47000, seconds=2)
        self.assertEqual(r["count"], 4)
        self.assertEqual(r["command"][-5:], ["udp", "port", "47000", "or", "icmp"])
        self.assertIn("any", r["command"])
        self.assertNotIn("error", r)

    def test_capture_validates(self):
        with self.assertRaises(_common.ValidationError):
            probe.capture(70000)
        with self.assertRaises(_common.ValidationError):
            probe.capture(47000, iface="eth9")
        self.assertEqual(self.host.calls, [])

    def test_udp_probe_sends_nothing(self):
        r = probe.udp_probe("192.0.2.81", 47000)
        self.assertEqual(r["route"]["gateway"], "10.10.0.1")
        self.assertIn("nothing was sent", r["note"])
        self.assertFalse(any(c[0] in ("nc", "socat", "tcpdump") for c in self.host.calls))


class TestControl(Base):
    ALLOW = dict(CONFIG, allow_net_control=True)

    def mutating_calls(self):
        return [c for c in self.host.calls if c[:2] in (["ip", "addr"], ["ip", "link"], ["ip", "neigh"])
                or c[:2] == ["ufw", "allow"]]

    def test_actions_table(self):
        for name in ("addr_add", "addr_del", "link_up", "link_down", "neigh_flush", "fw_allow",
                     "ping", "capture"):
            self.assertIn(name, control.ACTIONS)
            self.assertEqual(set(control.ACTIONS[name]) >= {"label", "dangerous", "args",
                                                            "description"}, True)
        self.assertFalse(control.ACTIONS["ping"]["dangerous"])
        self.assertTrue(control.ACTIONS["link_down"]["dangerous"])

    def test_refused_when_not_allowed(self):
        r = control.run("addr_add", {"iface": "eth0", "cidr": "192.0.2.10/24", "confirm": True},
                        CONFIG)
        self.assertFalse(r["ok"])
        self.assertIn("allow_net_control", r["message"])
        self.assertEqual(self.mutating_calls(), [])

    def test_refused_without_confirm(self):
        r = control.run("addr_add", {"iface": "eth0", "cidr": "192.0.2.10/24"}, self.ALLOW)
        self.assertFalse(r["ok"])
        self.assertIn("confirm", r["message"])
        self.assertEqual(r["command"], ["ip", "addr", "add", "192.0.2.10/24", "dev", "eth0"])
        self.assertEqual(self.mutating_calls(), [])

    def test_runs_when_allowed_and_confirmed(self):
        r = control.run("addr_add", {"iface": "eth0", "cidr": "192.0.2.10/24", "confirm": True},
                        self.ALLOW)
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.mutating_calls(),
                         [["ip", "addr", "add", "192.0.2.10/24", "dev", "eth0"]])
        log = control.audit_log()
        self.assertEqual(log[-1]["action"], "addr_add")
        self.assertNotIn("confirm", log[-1]["args"])

    def test_fw_allow_command(self):
        r = control.run("fw_allow", {"iface": "eth0", "from_cidr": "192.0.2.0/24",
                                     "port": 47000, "confirm": True}, self.ALLOW)
        self.assertEqual(r["command"], ["ufw", "allow", "in", "on", "eth0", "from",
                                        "192.0.2.0/24", "to", "any", "port", "47000",
                                        "proto", "udp"])

    def test_injection_and_bad_args_refused(self):
        bad = [
            ("link_up", {"iface": "eth0; rm -rf /"}),
            ("link_up", {"iface": "eth9"}),
            ("link_down", {"iface": "$(reboot)"}),
            ("addr_add", {"iface": "eth0", "cidr": "192.0.2.10"}),
            ("addr_add", {"iface": "eth0", "cidr": "192.0.2.10/24 dev lo"}),
            ("addr_add", {"iface": "eth0", "cidr": "999.1.1.1/24"}),
            ("fw_allow", {"iface": "eth0", "from_cidr": "any", "port": 47000}),
            ("fw_allow", {"iface": "eth0", "from_cidr": "10.0.0.0/8", "port": "47000; ls"}),
            ("fw_allow", {"iface": "eth0", "from_cidr": "10.0.0.0/8", "port": 0}),
            ("neigh_flush", {}),
            ("ping", {"ip": "203.0.113.8 -f"}),
            ("capture", {"port": "abc"}),
        ]
        for name, args in bad:
            args = dict(args, confirm=True)
            r = control.run(name, args, self.ALLOW)
            self.assertFalse(r["ok"], (name, args))
            self.assertTrue(r["message"].startswith("refused"), (name, r["message"]))
        self.assertEqual(self.host.calls, [])
        self.assertEqual(len(control.audit_log()), len(bad))

    def test_unknown_action(self):
        r = control.run("format_disk", {}, self.ALLOW)
        self.assertFalse(r["ok"])
        self.assertEqual(self.host.calls, [])

    def test_ping_passthrough_needs_no_permission(self):
        r = control.run("ping", {"ip": "10.10.0.1"}, CONFIG)
        self.assertTrue(r["ok"])
        self.assertEqual(r["result"]["received"], 3)

    def test_string_confirm_false_is_refused(self):
        r = control.run("link_up", {"iface": "eth0", "confirm": "false"}, self.ALLOW)
        self.assertFalse(r["ok"])

    def test_audit_capped(self):
        for _ in range(250):
            control.run("link_up", {"iface": "eth0"}, CONFIG)
        self.assertEqual(len(control.audit_log()), 200)


if __name__ == "__main__":
    unittest.main()


# The field setup: Pi 198.51.100.212/16 on eth0, sensor 192.0.2.81 behind router 198.51.100.1.
FIELD_ADDR = json.loads(json.dumps(IP_ADDR))
FIELD_ADDR[1]["addr_info"][0].update(local="198.51.100.212", prefixlen=16)
FIELD_ROUTE_GET = [{"dst": "192.0.2.81", "gateway": "198.51.100.1", "dev": "eth0",
                    "prefsrc": "198.51.100.212", "flags": [], "uid": 0, "cache": []}]
FIELD_CFG = {"node_name": "t", "expected_local_address": "",
             "sessions": {"sensor": {"protocol": "toy", "local": "0.0.0.0:47000",
                                  "peer_candidates": ["192.0.2.81:47000",
                                                      "192.0.2.74:47000"]}}}


class TestRoutedTopology(Base):
    def make_host(self):
        return FakeHost(addr=FIELD_ADDR, route_get=FIELD_ROUTE_GET, ss=SS_SCAPEGOAT)

    def test_inferred_routed_gives_no_subnet_advice(self):
        s = visibility.snapshot(FIELD_CFG)
        self.assertEqual(s["topology"]["mode"], "routed")
        self.assertIn("198.51.100.1", s["topology"]["source"])
        text = " ".join(s["hints"])
        self.assertNotIn("addr_add", text)
        self.assertNotIn("same subnet", text)
        self.assertNotIn("No address on any interface", text)
        self.assertEqual(s["sessions"][0]["topology"], "routed")

    def test_explicit_config_wins(self):
        self.assertEqual(visibility.snapshot(dict(FIELD_CFG, topology="same-lan"))["topology"],
                         {"mode": "same-lan", "source": "config"})
        cfg = dict(FIELD_CFG, expected_local_address="192.0.2.177/24")
        self.assertEqual(visibility.snapshot(cfg)["topology"]["mode"], "same-lan")
        self.assertEqual(visibility.snapshot(dict(FIELD_CFG, topology="routed"))["topology"],
                         {"mode": "routed", "source": "config"})

    def test_local_address_in_sensor_subnet_hint_remove(self):
        addr = json.loads(json.dumps(FIELD_ADDR))
        addr[1]["addr_info"].append({"family": "inet", "local": "192.0.2.177", "prefixlen": 24})
        self.host.addr = addr
        # with that address present the kernel uses the connected /24: no gateway any more
        self.host.route_get = [{"dst": "192.0.2.81", "dev": "eth0", "prefsrc": "192.0.2.177"}]
        s = visibility.snapshot(dict(FIELD_CFG, topology="routed"))
        text = " ".join(s["hints"])
        self.assertIn("This node holds 192.0.2.177/24 in the sensor's subnet", text)
        self.assertIn("scapegoat net addr_del --iface eth0 --cidr 192.0.2.177/24 --confirm", text)
        self.assertNotIn("addr_add", text)

    def test_never_suggest_removing_the_only_address(self):
        addr = json.loads(json.dumps(FIELD_ADDR))
        addr[1]["addr_info"][0].update(local="192.0.2.227", prefixlen=16)
        self.host.addr = addr
        self.host.route_get = [{"dst": "192.0.2.81", "dev": "eth0", "prefsrc": "192.0.2.227"}]
        text = " ".join(visibility.snapshot(dict(FIELD_CFG, topology="routed"))["hints"])
        self.assertNotIn("addr_del", text)
        self.assertIn("own network 192.0.2.227/16 on eth0 includes the sensor address", text)

    def test_route_out_wifi_or_mesh(self):
        for dev, word in (("wlan0", "Wi-Fi"), ("wt0", "NetBird mesh")):
            self.host.route_get = [dict(FIELD_ROUTE_GET[0], dev=dev)]
            text = " ".join(visibility.snapshot(dict(FIELD_CFG, topology="routed"))["hints"])
            self.assertIn(f"would leave on {dev} ({word})", text)


class TestIcmpUnreachable(unittest.TestCase):
    SAMPLE = ("12:00:01.000000 eth0  Out IP 198.51.100.212.47000 > 192.0.2.81.47000: UDP, length 16\n"
              "12:00:01.002000 eth0  In  IP 198.51.100.1 > 198.51.100.212: ICMP host 192.0.2.81 "
              "unreachable, length 52\n"
              "12:00:02.002000 eth0  In  IP 198.51.100.1 > 198.51.100.212: ICMP host 192.0.2.81 "
              "unreachable, length 52\n")

    def test_parse_and_hint(self):
        u = probe.icmp_unreachable(self.SAMPLE)
        self.assertEqual([(x["router"], x["target"]) for x in u], [("198.51.100.1", "192.0.2.81")])
        self.assertEqual(probe.unreachable_hints(u), [
            "The router 198.51.100.1 cannot find the sensor at 192.0.2.81: the sensor link not enabled, "
            "wrong address, or the sensor not on that segment."])
        self.assertEqual(probe.icmp_unreachable("IP 203.0.113.4.5 > 6.7.8.9.10: UDP, length 3"), [])
        pk = probe.parse_tcpdump(self.SAMPLE)
        self.assertEqual((pk[1]["src"], pk[1]["dst"], pk[1]["src_port"]),
                         ("198.51.100.1", "198.51.100.212", None))
        self.assertIn("unreachable", pk[1]["icmp"])


# node-a in the field: eth0 192.0.2.18/16 by DHCP with the default route; the sensor
# 192.0.2.81 reached through a /32 host route via wlan0; the session bound to wlan0's address.
RPI02_ADDR = json.loads(json.dumps(IP_ADDR))
RPI02_ADDR[1]["addr_info"][0].update(local="192.0.2.18", prefixlen=16, dynamic=True)
RPI02_ADDR[2]["flags"] = ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"]
RPI02_ADDR[2]["operstate"] = "UP"
RPI02_ADDR[2]["addr_info"] = [{"family": "inet", "local": "198.51.100.105", "prefixlen": 16}]
RPI02_ROUTE_GET = [{"dst": "192.0.2.81", "gateway": "198.51.100.1", "dev": "wlan0",
                    "prefsrc": "198.51.100.105", "flags": [], "uid": 0, "cache": []}]


class TestRoutedFalseAlarms(Base):
    def make_host(self):
        h = FakeHost(addr=RPI02_ADDR, route_get=RPI02_ROUTE_GET, ss=SS_SCAPEGOAT)
        h.carriers["wlan0"] = "1"
        return h

    def cfg(self, local="198.51.100.105:47000"):
        return {"topology": "routed", "sessions": {"sensor": {
            "protocol": "toy", "local": local, "peer_candidates": ["192.0.2.81:47000"]}}}

    def test_overlap_with_gateway_route_is_only_a_note(self):
        s = visibility.snapshot(self.cfg())
        text = " ".join(s["hints"])
        self.assertNotIn("addr_del", text)
        self.assertNotIn("192.0.2.18/16", text)
        notes = " ".join(s["sessions"][0]["notes"])
        self.assertIn("192.0.2.18/16 on eth0 overlaps the sensor's subnet", notes)
        self.assertIn("no change needed", notes)

    def test_local_bound_to_route_iface_no_wifi_hint(self):
        text = " ".join(visibility.snapshot(self.cfg())["hints"])
        self.assertNotIn("would leave on wlan0", text)
        text = " ".join(visibility.snapshot(self.cfg("0.0.0.0:47000"))["hints"])
        self.assertIn("would leave on wlan0 (Wi-Fi)", text)

    def test_never_delete_dhcp_or_default_source_even_on_direct_route(self):
        addr = json.loads(json.dumps(RPI02_ADDR))
        addr[1]["addr_info"].append({"family": "inet", "local": "10.9.9.9", "prefixlen": 24})
        self.host.addr = addr
        self.host.route_get = [{"dst": "192.0.2.81", "dev": "eth0", "prefsrc": "192.0.2.18"}]
        text = " ".join(visibility.snapshot(self.cfg("0.0.0.0:47000"))["hints"])
        self.assertNotIn("addr_del", text, "DHCP address must never get a removal command")
        addr[1]["addr_info"][0]["dynamic"] = False   # static, but the default route's source
        self.host.routes = [{"dst": "default", "gateway": "192.168.1.1", "dev": "eth0",
                             "prefsrc": "192.0.2.18", "metric": 100}]
        text = " ".join(visibility.snapshot(self.cfg("0.0.0.0:47000"))["hints"])
        self.assertNotIn("addr_del", text, "default route source must never get a removal command")
