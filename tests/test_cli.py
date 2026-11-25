import contextlib
import io
import unittest

from scapegoat import cli

SNAP = {
    "host": {"hostname": "node-b"},
    "interfaces": [
        {"name": "lo", "admin_up": True, "carrier": True,
         "addresses": [{"cidr": "127.0.0.1/8"}, {"cidr": "::1/128"}]},
        {"name": "eth0", "admin_up": True, "carrier": True,
         "addresses": [{"cidr": "192.0.2.177/24"}, {"cidr": "fe80::1/64"}]},
        {"name": "wlan0", "admin_up": False, "carrier": False, "addresses": []},
    ],
    "firewall": {"tool": "ufw", "active": True, "default_incoming": "deny",
                 "port_rules": ["47000/udp ALLOW IN 192.0.2.0/24"]},
    "sessions": [{"id": "sensor", "local_port": 47000, "hints": [],
                  "listeners": [{"local": "0.0.0.0", "port": 47000, "process": "python3"}],
                  "peers": [
                      {"ip": "192.0.2.81", "port": 47000,
                       "same_subnet": [{"iface": "eth0", "cidr": "192.0.2.177/24"}],
                       "route": {"iface": "eth0", "gateway": None},
                       "neighbor": {"state": ["REACHABLE"], "mac": "aa:bb:cc:dd:ee:ff"}},
                      {"ip": "192.0.2.74", "port": 47000, "same_subnet": [],
                       "route": {"iface": "wlan0", "gateway": "10.0.0.1"},
                       "neighbor": {"state": ["NONE"], "mac": None}}]}],
    "expected_local": {"cidr": "192.0.2.177/24", "present": True, "on": ["eth0"]},
    "hints": ["Open the port: scapegoat net fw_allow --iface eth0 --from_cidr 192.0.2.0/24 "
              "--port 47000 --confirm"],
}


class TestNetHuman(unittest.TestCase):
    def render(self, snap):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli._print_net(snap)
        return out.getvalue()

    def test_layout(self):
        out = self.render(SNAP)
        self.assertTrue(out.startswith("FIX THESE FIRST\n  1. Open the port"), out)
        self.assertIn("       scapegoat net fw_allow --iface eth0 --from_cidr 192.0.2.0/24 "
                      "--port 47000 --confirm", out)
        self.assertIn("Node address: [OK] 192.0.2.177/24 present on eth0", out)
        self.assertIn("eth0", out)
        self.assertNotIn("fe80", out)
        self.assertIn("(1 more without addresses", out)
        self.assertIn("192.0.2.81:47000  yes, eth0 192.0.2.177/24", out)
        self.assertIn("REACHABLE aa:bb:cc:dd:ee:ff", out)
        self.assertIn("NO", out)
        self.assertIn("via wlan0 gw 10.0.0.1", out)
        self.assertIn("listeners: 0.0.0.0:47000 (python3)", out)
        self.assertIn("FIREWALL  ufw: active, default incoming deny; rules for the port: "
                      "47000/udp ALLOW IN", out)
        self.assertNotIn("{", out)

    def test_sections_degrade(self):
        out = self.render({"interfaces": {"error": "ip not found"}, "sessions": {"error": "x"},
                           "firewall": {"tool": None, "note": "no ufw or nft found"},
                           "hints": [], "expected_local": None})
        self.assertIn("No problems found", out)
        self.assertIn("not available: ip not found", out)
        self.assertIn("FIREWALL  none: no ufw or nft found", out)


class TestFlagSpellings(unittest.TestCase):
    def test_both_spellings(self):
        p = cli.build_parser()
        for flag in ("--from_cidr", "--from-cidr"):
            a = p.parse_args(["net", "fw_allow", "--iface", "eth0", flag, "192.0.2.0/24",
                              "--port", "47000", "--confirm"])
            self.assertEqual(a.from_cidr, "192.0.2.0/24")
        for flag in ("--profiles-dir", "--profiles_dir"):
            self.assertEqual(p.parse_args(["profiles", flag, "/x"]).profiles_dir, "/x")

    def test_api_json_before_and_after(self):
        p = cli.build_parser()
        a = p.parse_args(["--api", "http://h:1", "--json", "status"])
        self.assertEqual((a.api, a.json), ("http://h:1", True))
        a = p.parse_args(["status", "--api", "http://h:2", "--json"])
        self.assertEqual((a.api, a.json), ("http://h:2", True))
        a = p.parse_args(["net", "show", "--api", "http://h:3"])
        self.assertEqual((a.api, a.json), ("http://h:3", False))
        a = p.parse_args(["--json", "net", "ping", "203.0.113.4"])
        self.assertTrue(a.json)


if __name__ == "__main__":
    unittest.main()


class TestNetResults(unittest.TestCase):
    def render(self, r):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli._print_net_result(r)
        return out.getvalue()

    def test_shapes(self):
        self.assertIn("REACHABLE (3/3 replies, average 0.4 ms)",
                      self.render({"ip": "192.0.2.81", "reachable": True, "sent": 3,
                                   "received": 3, "rtt_avg_ms": 0.4}))
        out = self.render({"ok": True, "action": "addr_add", "message": "added",
                           "command": ["ip", "addr", "add", "192.0.2.177/24", "dev", "eth0"],
                           "stdout": "", "stderr": ""})
        self.assertIn("Done: added", out)
        self.assertIn("ran: ip addr add 192.0.2.177/24 dev eth0", out)
        self.assertIn("FAILED: refused: x", self.render({"ok": False, "message": "refused: x"}))
        self.assertIn("1 packets in 10 s", self.render(
            {"packets": [{"time": "t", "src": "a", "dst": "b", "length": 16}], "count": 1,
             "seconds": 10}))


class TestTopologyLines(unittest.TestCase):
    def test_status_and_net(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.print_status([], {"topology": "routed"})
            cli._print_net({"topology": {"mode": "routed",
                                         "source": "inferred from the route to 192.0.2.81 "
                                                   "(via gateway 198.51.100.1)"},
                            "hints": []})
        text = out.getvalue()
        self.assertIn("Topology: routed (sensor reached through a router", text)
        self.assertIn("from inferred from the route to 192.0.2.81 (via gateway 198.51.100.1)",
                      text)


class TestIdentity(unittest.TestCase):
    def test_lines(self):
        ident = {"hostname": "node-a", "node_role": "C2 node", "role_note": "",
                 "title": "node-a · C2 node", "billie_node": "node-a-edge",
                 "mesh_address": "100.127.12.7", "slot_short": "slot/demo",
                 "sensor_sees": [{"session": "sensor", "address": "198.51.100.105:47000"}]}
        lines = cli.identity_lines(ident)
        self.assertEqual(lines[0], "node-a · C2 node")
        self.assertEqual(lines[1], "  Billie node node-a-edge  ·  sensor sees us at "
                                   "198.51.100.105:47000  ·  mesh 100.127.12.7  ·  slot slot/demo")
        unset = dict(ident, node_role=None, role_note="role not set (node_role in scapegoat.toml)",
                     title="node-a · node-a-edge")
        self.assertEqual(cli.identity_lines(unset)[0],
                         "node-a · node-a-edge   (role not set (node_role in scapegoat.toml))")
        bare = dict(unset, billie_node=None, title="node-a · role not set")
        self.assertEqual(cli.identity_lines(bare)[0],
                         "node-a · role not set (node_role in scapegoat.toml)")

    def test_net_notes_printed(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli._print_net({"hints": [], "sessions": [{"id": "sensor", "peers": [], "notes": [
                "192.0.2.18/16 on eth0 overlaps the sensor's subnet, but traffic to "
                "192.0.2.81 still goes via gateway 198.51.100.1 on wlan0; no change needed."]}]})
        self.assertIn("note (sensor): 192.0.2.18/16 on eth0 overlaps", out.getvalue())
