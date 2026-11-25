import contextlib
import io
import json
import os
import tempfile
import unittest

from scapegoat import cli
from scapegoat.core import node

# Shapes from `ip -j addr` / `ip -j route` on Ubuntu 24.04 arm64 (Raspberry Pi), trimmed.
IP_ADDR = json.dumps([
    {"ifindex": 1, "ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"], "operstate": "UNKNOWN",
     "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8},
                   {"family": "inet6", "local": "::1", "prefixlen": 128}]},
    {"ifindex": 2, "ifname": "eth0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
     "operstate": "UP",
     "addr_info": [{"family": "inet", "local": "192.0.2.177", "prefixlen": 24},
                   {"family": "inet6", "local": "fe80::2ecf:67ff:fe01:203", "prefixlen": 64}]},
    {"ifindex": 3, "ifname": "wlan0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
     "operstate": "UP", "addr_info": [{"family": "inet", "local": "10.20.30.41", "prefixlen": 24}]},
    {"ifindex": 4, "ifname": "wt0", "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"],
     "operstate": "UNKNOWN", "addr_info": [{"family": "inet", "local": "100.127.12.7", "prefixlen": 16}]},
    {"ifindex": 5, "ifname": "podman0", "flags": ["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"],
     "operstate": "DOWN", "addr_info": [{"family": "inet", "local": "10.88.0.1", "prefixlen": 16}]},
    {"ifindex": 6, "ifname": "end1", "flags": ["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"],
     "operstate": "DOWN", "addr_info": [{"family": "inet", "local": "172.16.5.2", "prefixlen": 24}]},
])
IP_ROUTE = json.dumps([
    {"dst": "default", "gateway": "10.20.30.1", "dev": "wlan0", "protocol": "dhcp",
     "prefsrc": "10.20.30.41", "metric": 600},
    {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "protocol": "dhcp",
     "prefsrc": "192.0.2.177", "metric": 100},
    {"dst": "192.0.2.0/24", "dev": "eth0", "protocol": "kernel", "scope": "link"},
])


class TestNode(unittest.TestCase):
    def build(self, **kw):
        rows = node.parse_ip_addr(IP_ADDR)
        return node.build(rows, node.parse_ip_route(IP_ROUTE), ["192.0.2.81", "192.0.2.74"],
                          "192.0.2.177/24", "node-b", kw.get("billie"),
                          kw.get("loopback", False))

    def test_roles_and_order(self):
        n = self.build()
        got = [(a["role"], a["iface"], a["cidr"]) for a in n["addresses"]]
        self.assertEqual(got, [
            ("sensor LAN", "eth0", "192.0.2.177/24"),
            ("NetBird mesh", "wt0", "100.127.12.7/16"),
            ("wired", "end1", "172.16.5.2/24"),
            ("Wi-Fi", "wlan0", "10.20.30.41/24"),
            ("Billie containers", "podman0", "10.88.0.1/16"),
        ])
        self.assertEqual(n["loopback_hidden"], 2)
        self.assertEqual(n["default_route"]["iface"], "eth0", "lowest metric first")
        by = {a["iface"]: a for a in n["addresses"]}
        self.assertEqual((by["eth0"]["default_route"], by["eth0"]["route_note"]),
                         (True, "default route"))
        self.assertEqual((by["wlan0"]["default_route"], by["wlan0"]["route_note"]),
                         (False, "backup default (metric 600)"))
        self.assertEqual(by["wt0"]["route_note"], "")
        self.assertIsNone(by["wlan0"]["cable"], "Wi-Fi shows up/down, not cable")
        self.assertEqual((by["eth0"]["link"], by["eth0"]["cable"]), ("up", True))
        self.assertEqual((by["end1"]["link"], by["end1"]["cable"]), ("no cable", False))

    def test_only_src_address_marked(self):
        two = json.dumps([{"ifname": "eth0", "flags": ["UP", "LOWER_UP"], "operstate": "UP",
                           "addr_info": [{"local": "192.0.2.177", "prefixlen": 24},
                                         {"local": "198.51.100.212", "prefixlen": 24}]}])
        route = json.dumps([{"dst": "default", "dev": "eth0", "prefsrc": "198.51.100.212",
                             "metric": 100}])
        n = node.build(node.parse_ip_addr(two), node.parse_ip_route(route), [], "", "pi", None)
        marks = {a["ip"]: a["route_note"] for a in n["addresses"]}
        self.assertEqual(marks, {"192.0.2.177": "", "198.51.100.212": "default route"})

    def test_loopback_on_request(self):
        self.assertIn("loopback", [a["role"] for a in self.build(loopback=True)["addresses"]])

    def test_billie_files(self):
        with tempfile.TemporaryDirectory() as d:
            idp, fab = os.path.join(d, "node.yml"), os.path.join(d, "fabric.json")
            with open(idp, "w") as f:
                f.write("# billie identity\nnode_handle: node-b-edge\nsite: x\n")
            with open(fab, "w") as f:
                json.dump({"billie_fabric_prefix": "slot/demo", "zenoh": {
                    "billie_fabric_endpoint": "tls/core.example:7447"}}, f)
            b = node.read_billie(idp, fab)
        self.assertEqual(b, {"node_handle": "node-b-edge", "billie_fabric_prefix": "slot/demo",
                             "billie_fabric_endpoint": "tls/core.example:7447"})
        self.assertIsNone(node.read_billie("/nonexistent/a", "/nonexistent/b"))

    def test_cli_block(self):
        n = self.build(billie={"node_handle": "node-b-edge", "billie_fabric_prefix": "slot/demo"})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.print_node(n)
        text = out.getvalue()
        self.assertTrue(text.startswith("This node: node-b   Billie node node-b-edge   slot slot/demo"))
        self.assertIn("sensor LAN", text)
        self.assertIn("192.0.2.177/24", text)
        self.assertIn("no cable, NO CABLE", text)
        self.assertIn("default route", text)
        self.assertIn("backup default (metric 600)", text)
        wifi = next(l for l in text.splitlines() if "wlan0" in l)
        self.assertNotIn("cable", wifi)
        self.assertNotIn("127.0.0.1", text)
