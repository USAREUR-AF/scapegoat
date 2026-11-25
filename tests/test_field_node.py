"""The sensor-neutral field-node installer with the built-in toy pack (stubbed system)."""

import re
import shutil
import subprocess
import unittest

from tests.field_node_harness import DRIVER, FIELD, FieldNodeCase

TOY_SITE = """\
COMPONENTS="network capture kids scapegoat"
FIELD_PACK=toy
FIELD_MODE=lan
NODE_NAME=test-node
NODE_ROLE="C2 test"
SENSOR_IFACE=eth0
LAN_LOCAL_CIDR=192.0.2.10/24
LAN_PEER=192.0.2.81:47000
LAN_PEER_CANDIDATES="192.0.2.81:47000 192.0.2.82:47000"
ALLOW_NET_CONTROL=true
ISLAND_REST=http://127.0.0.1:8000
CAPTURE=off
KIDS=
"""


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class ToyFieldNode(FieldNodeCase):
    SITE = TOY_SITE

    def test_install_check_rerun(self):
        r = self.run_driver()
        self.assertOk(r)
        conf = (self.root / "etc/scapegoat/scapegoat.toml").read_text()
        self.assertIn('profile = "sim-local"', conf)
        self.assertIn('local = "0.0.0.0:47000"', conf)
        self.assertIn('peer = "192.0.2.81:47000"', conf)
        self.assertIn('expected_local_address = "192.0.2.10/24"', conf)
        self.assertIn("[sessions.sensor.protocol_settings]", conf)
        netplan = (self.root / "etc/netplan/55-eth0-sensor.yaml").read_text()
        self.assertIn("addresses: [192.0.2.10/24]", netplan)
        self.assertIn("eth0 192.0.2.10/24", self.addrs())
        self.assertTrue((self.root / "usr/local/bin/field-node-mode").exists())
        self.assertTrue((self.root / "etc/field-node/pack/pack.env").exists())
        self.assertTrue((self.root / "usr/local/lib/field-node/mode.d/scapegoat").exists())
        self.assertTrue(self.active("scapegoat.service"))
        self.assertIn("note: no kids in the site file", r.stdout)

        r = self.run_driver("--check")
        self.assertOk(r)
        self.assertIn("matches the site file", r.stdout)
        n = len(self.calls())
        r = self.run_driver()
        self.assertOk(r)
        self.assertNotIn("doing:", r.stdout)
        self.assertFalse([c for c in self.calls()[n:] if re.match(r"(ip addr|systemctl (restart|enable)|scapegoat-install)", c)])
        r = self.run_driver(site=False)
        self.assertOk(r)
        self.assertNotIn("doing:", r.stdout)

    def test_site_change_is_drift_then_converges(self):
        self.assertOk(self.run_driver())
        self.site.write_text(self.site.read_text().replace("LAN_PEER=192.0.2.81:47000", "LAN_PEER=192.0.2.82:47000"))
        self.assertEqual(self.run_driver("--check").returncode, 3)
        n = len(self.calls())
        self.assertOk(self.run_driver())
        self.assertIn('peer = "192.0.2.82:47000"', (self.root / "etc/scapegoat/scapegoat.toml").read_text())
        self.assertIn("systemctl restart scapegoat", self.calls()[n:])

    def test_bad_site_stops_before_any_change(self):
        good = self.site.read_text()
        self.site.write_text(good.replace("LAN_PEER=192.0.2.81:47000", "LAN_PEER=198.51.100.9:47000"))
        r = self.run_driver()
        self.assertEqual(r.returncode, 1)
        self.assertIn("not in 192.0.2.0/24", r.stdout)
        self.site.write_text(good + "# cable " + ":".join(["0a"] * 6) + "\n")   # no MAC literal in the repo
        r = self.run_driver()
        self.assertEqual(r.returncode, 1)
        self.assertIn("MAC address", r.stdout)
        self.assertFalse((self.root / "etc").exists())

    def test_unknown_mode_and_old_interface_name_refused(self):
        r = self.run_driver("--mode", "nope")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not one of the pack's modes", r.stderr)
        self.site.write_text(self.site.read_text().replace("SENSOR_IFACE=eth0", "RADAR_IFACE=eth0"))
        r = self.run_driver()
        self.assertEqual(r.returncode, 1)
        self.assertIn("rename it to SENSOR_IFACE", r.stderr)

    def test_unknown_pack_refused(self):
        self.site.write_text(self.site.read_text().replace("FIELD_PACK=toy", "FIELD_PACK=nope"))
        r = self.run_driver()
        self.assertEqual(r.returncode, 1)
        self.assertIn("names no field-node pack", r.stderr)

    def test_uninstall(self):
        self.assertOk(self.run_driver())
        self.assertEqual(self.run_driver("--uninstall").returncode, 2)
        r = self.run_driver("--uninstall", "--yes")
        self.assertOk(r)
        self.assertFalse((self.root / "usr/local/bin/field-node-mode").exists())
        self.assertFalse((self.root / "etc/netplan/55-eth0-sensor.yaml").exists())
        self.assertFalse((self.root / "etc/field-node/pack").exists())
        self.assertFalse((self.root / "opt/scapegoat").exists())
        self.assertEqual(self.addrs(), [])
        self.assertTrue((self.root / "etc/field-node/site.env").exists())


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class CaptureHook(FieldNodeCase):
    """A pack with capture units and a tap instance: units first, then first-bite."""
    SITE = TOY_SITE.replace("FIELD_PACK=toy", "FIELD_PACK={tmp}/pack").replace(
        "CAPTURE=off", "CAPTURE=units\nCAPTURE_RING_FILES=2\nCAPTURE_RING_MB=1\nPCAP_KEEP=5\n"
        "FIRST_BITE_TAP_INSTALL={tmp}/stubs/fb-tap-install\nFIRST_BITE_TAP_ENV_DIR={tmp}/taps")

    def setUp(self):
        super().setUp()
        pack = self.tmp / "pack"
        shutil.copytree(FIELD / "packs" / "toy", pack)
        env = (pack / "pack.env").read_text()
        env = env.replace('CAPTURE_UNITS=""', 'CAPTURE_UNITS="toy-ring.service"')
        env = env.replace('TAP_ENVS=""', 'TAP_ENVS="ring=ring.env"')
        (pack / "pack.env").write_text(env)
        (pack / "units").mkdir()
        (pack / "units" / "toy-ring.service").write_text(
            "[Service]\nEnvironmentFile=/etc/field-node/site.env\n"
            "ExecStart=/usr/bin/tcpdump -i ${SENSOR_IFACE} -w /var/tmp/ring.pcap\n")
        (self.tmp / "taps").mkdir()
        (self.tmp / "taps" / "ring.env").write_text(
            "TAP_INTERFACE=eth9\nTAP_ARGS=--pcap-key toy/pcap/{host}\n")

    def test_units_then_first_bite(self):
        self.assertOk(self.run_driver())
        self.assertTrue((self.root / "etc/systemd/system/toy-ring.service").exists())
        self.assertTrue(self.active("toy-ring.service"))
        self.site.write_text(self.site.read_text().replace("CAPTURE=units", "CAPTURE=first-bite"))
        self.assertEqual(self.run_driver("--check").returncode, 3)
        r = self.run_driver()
        self.assertOk(r)
        tap = (self.root / "etc/first-bite/tap-ring.env").read_text()
        self.assertIn("TAP_INTERFACE=eth0", tap)
        self.assertIn("toy/pcap/test-node", tap)
        self.assertTrue(self.active("first-bite-tap@ring.service"))
        self.assertFalse((self.root / "etc/systemd/system/toy-ring.service").exists())
        self.assertIn("fb-tap-install ring --env", " ".join(self.calls()))
        r = self.run_driver()
        self.assertOk(r)
        self.assertNotIn("doing:", r.stdout)
        # a changed settings file restarts the running tap
        (self.tmp / "taps" / "ring.env").write_text("TAP_INTERFACE=eth9\nTAP_ARGS=--pcap-key toy/pcap2/{host}\n")
        n = len(self.calls())
        self.assertOk(self.run_driver())
        later = self.calls()[n:]
        self.assertIn("systemctl restart first-bite-tap@ring.service", later)
        self.assertIn("toy/pcap2/test-node", (self.root / "etc/first-bite/tap-ring.env").read_text())
        r = self.run_driver("--uninstall", "--yes")
        self.assertOk(r)
        self.assertIn("fb-tap-install ring --uninstall", self.calls())

    def test_first_bite_is_the_default_and_needs_mind(self):
        self.site.write_text(self.site.read_text().replace("CAPTURE=units\n", ""))
        (self.root / "usr/local/bin/mind").unlink()
        r = self.run_driver()
        self.assertEqual(r.returncode, 1)
        self.assertIn("mind is not installed", r.stderr)


STANDARD_SITE = """\
COMPONENTS="network capture kids"
FIELD_PACK=plain
NODE_NAME=radar-node
SENSOR_IFACE=eth0
SENSOR_CIDRS="192.0.2.10/24"
CAPTURE=first-bite
FIRST_BITE_TAP_INSTALL={tmp}/stubs/fb-tap-install
CAPTURE_TAPS="radar={tmp}/radar-tap.env"
KIDS="xf-ingest"
KID_XF_INGEST_VERSION=0.2.0
KID_XF_INGEST_BUNDLE={bundle}
KID_XF_INGEST_SHA256={sha}
KID_XF_INGEST_TRANSPORT=udp
KID_XF_INGEST_BIND=192.0.2.10
KID_XF_INGEST_PORT=4000
KID_XF_INGEST_SOURCE_CIDR=192.0.2.0/24
KID_XF_INGEST_CAT062="xf-track:0:160 xf-plot:0:161"
"""


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class StandardFormatRadarNode(FieldNodeCase):
    """No surrogate C2: plain pack, first-bite tap from the site file, one kid."""
    SITE = STANDARD_SITE
    KID = ("xf-ingest", "0.2.0")

    def setUp(self):
        super().setUp()
        (self.tmp / "radar-tap.env").write_text("TAP_INTERFACE=eth0\nTAP_ARGS=--pcap-key radar/pcap/{host}\n")

    def test_no_scapegoat_one_kid(self):
        r = self.run_driver()
        self.assertOk(r)
        self.assertFalse((self.root / "opt/scapegoat").exists())
        self.assertFalse((self.root / "etc/scapegoat").exists())
        self.assertFalse([c for c in self.calls() if c.startswith("scapegoat-install")])
        self.assertIn("eth0 192.0.2.10/24", self.addrs())
        self.assertIn("radar/pcap/radar-node", (self.root / "etc/first-bite/tap-radar.env").read_text())
        billie = [c for c in self.calls() if c.startswith("billie ")]
        self.assertIn("--bind-address 192.0.2.10 --port 4000 --source-cidr 192.0.2.0/24", " ".join(billie))
        self.assertEqual(sum("cat062 source set xf-ingest" in c for c in billie), 2)
        self.assertTrue(self.active("billie-kid-xf-ingest.service"))
        r = self.run_driver()
        self.assertOk(r)
        self.assertNotIn("doing:", r.stdout)

    def test_scapegoat_needs_network(self):
        self.site.write_text(self.site.read_text().replace('COMPONENTS="network capture kids"', 'COMPONENTS="capture kids scapegoat"'))
        r = self.run_driver()
        self.assertEqual(r.returncode, 1)
        self.assertIn("needs the network component", r.stderr)

    def test_billie_owned_interface_refused(self):
        (self.root / "etc/netplan").mkdir(parents=True)
        (self.root / "etc/netplan/99-billie-sensor-eth0.yaml").write_text("network: {}\n")
        r = self.run_driver()
        self.assertEqual(r.returncode, 1)
        self.assertIn("One owner per interface", r.stderr)


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class DhcpInterface(FieldNodeCase):
    """plain pack, mode dhcp: the address is checked, never set, and no netplan file is written."""
    SITE = STANDARD_SITE.replace("FIELD_PACK=plain", "FIELD_PACK=plain\nFIELD_MODE=dhcp")
    KID = ("xf-ingest", "0.2.0")

    def setUp(self):
        super().setUp()
        (self.tmp / "radar-tap.env").write_text("TAP_INTERFACE=eth0\n")

    def test_dhcp_address_present(self):
        (self.state / "addrs").write_text("eth0 192.0.2.10/24\n")
        r = self.run_driver()
        self.assertOk(r)
        self.assertFalse((self.root / "etc/netplan/55-eth0-sensor.yaml").exists())
        self.assertFalse([c for c in self.calls() if c.startswith("ip addr ")])
        self.assertIn("192.0.2.10/24 on eth0 (from DHCP)", r.stdout)
        self.assertOk(self.run_driver("--uninstall", "--yes"))
        self.assertIn("eth0 192.0.2.10/24", self.addrs(), "uninstall never removes a DHCP address")

    def test_dhcp_address_missing_fails_verify(self):
        r = self.run_driver()
        self.assertEqual(r.returncode, 1)
        self.assertIn("MISSING: 192.0.2.10/24 on eth0 (from DHCP)", r.stderr)


XTAR_LIKE_SITE = """\
COMPONENTS="network capture passthrough"
FIELD_PACK=plain
FIELD_MODE=static-hosts
NODE_NAME=radar-node
SENSOR_IFACE=enx*
SENSOR_CIDRS="192.0.2.212/24"
SENSOR_HOST_ROUTES="192.0.2.10"
CAPTURE=first-bite
FIRST_BITE_TAP_INSTALL={tmp}/stubs/fb-tap-install
CAPTURE_TAPS="radar={tmp}/radar-tap.env"
PASSTHROUGH="radar"
PASSTHROUGH_RADAR_BIND=192.0.2.212
PASSTHROUGH_RADAR_PORT=6219
PASSTHROUGH_RADAR_SOURCE_CIDR=192.0.2.10/32
PASSTHROUGH_RADAR_KEY=radar/asterix/{{host}}
"""
DONGLE = "enx" + "0" * 11 + "1"   # a USB Ethernet name (its real form carries a MAC address)


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class StaticHostsNode(FieldNodeCase):
    """USB Ethernet by glob, a /32 address with no subnet route, a host route, a pass-through."""
    SITE = XTAR_LIKE_SITE

    def setUp(self):
        super().setUp()
        (self.state / "links").write_text(DONGLE + "\n")
        (self.tmp / "radar-tap.env").write_text("TAP_INTERFACE=eth0\nTAP_ARGS=--filter 'udp port 6219'\n")

    def test_install_rerun_uninstall(self):
        r = self.run_driver()
        self.assertOk(r)
        self.assertEqual(self.addrs(), [f"{DONGLE} 192.0.2.212/32"])
        self.assertEqual(self.routes(), [f"{DONGLE} 192.0.2.10/32"])
        netplan = (self.root / f"etc/netplan/55-{DONGLE}-sensor.yaml").read_text()
        self.assertIn("addresses: [192.0.2.212/32]", netplan)
        self.assertIn("- to: 192.0.2.10/32", netplan)
        self.assertIn("from: 192.0.2.212", netplan)
        self.assertIn(f"TAP_INTERFACE={DONGLE}", (self.root / "etc/first-bite/tap-radar.env").read_text())
        pt = (self.root / "etc/field-node/passthrough-radar.env").read_text()
        self.assertIn("PT_PORT=6219", pt)
        self.assertIn("PT_KEY=radar/asterix/radar-node", pt)
        self.assertTrue(self.active("field-node-passthrough@radar.service"))
        self.assertIn("enx*", (self.root / "etc/field-node/site.env").read_text())
        r = self.run_driver()
        self.assertOk(r)
        self.assertNotIn("doing:", r.stdout)
        self.assertOk(self.run_driver("--uninstall", "--yes"))
        self.assertEqual((self.addrs(), self.routes()), ([], []))
        self.assertFalse(self.active("field-node-passthrough@radar.service"))

    def test_host_route_off_subnet_refused(self):
        self.site.write_text(self.site.read_text().replace('SENSOR_HOST_ROUTES="192.0.2.10"', 'SENSOR_HOST_ROUTES="198.51.100.7"'))
        r = self.run_driver()
        self.assertEqual(r.returncode, 1)
        self.assertIn("is not on 192.0.2.0/24", r.stdout)

    def test_glob_must_match_one(self):
        (self.state / "links").write_text(DONGLE + "\n" + DONGLE[:-1] + "2\n")
        r = self.run_driver()
        self.assertEqual(r.returncode, 1)
        self.assertIn("matches 2 interfaces", r.stderr)


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class NoComponents(FieldNodeCase):
    """COMPONENTS="none": the site file is recorded and checked; nothing is managed."""
    SITE = 'COMPONENTS="none"\nNODE_NAME=tap-node\n'

    def test_manages_nothing(self):
        r = self.run_driver()
        self.assertOk(r)
        self.assertIn("components none", r.stdout)
        self.assertFalse([c for c in self.calls() if not c.startswith("systemctl is-")])
        self.assertTrue((self.root / "etc/field-node/site.env").exists())
        self.assertOk(self.run_driver("--uninstall", "--yes"))


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class UsbEthernet(FieldNodeCase):
    """USB_ETH=on: one netplan file for a hot-plug enx* adapter, even with COMPONENTS="none"."""
    SITE = 'COMPONENTS="none"\nNODE_NAME=tap-node\nUSB_ETH=on\nUSB_ETH_ROUTE_METRIC=700\n'

    def netplan(self):
        return self.root / "etc/netplan/56-usb-ethernet.yaml"

    def test_writes_replaces_checks_and_uninstalls(self):
        hand = self.root / "etc/netplan/55-usb-ethernet.yaml"   # a hand-made file under another name
        hand.parent.mkdir(parents=True, exist_ok=True)
        hand.write_text("network: {version: 2}\n")
        r = self.run_driver("--check")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertFalse(self.netplan().exists())
        self.assertTrue(hand.exists())
        self.assertOk(self.run_driver())
        text = self.netplan().read_text()
        for line in ('name: "enx*"', "optional: true", "dhcp4: true", "route-metric: 700",
                     "dhcp6: false", "link-local: [ipv4]"):
            self.assertIn(line, text)
        self.assertFalse(hand.exists(), "the hand-made file is replaced")
        self.assertEqual(oct(self.netplan().stat().st_mode & 0o777), "0o600")
        self.assertFalse([c for c in self.calls() if c.startswith("ip ")], "nothing is applied to a link")
        self.assertOk(self.run_driver("--check"))
        self.assertOk(self.run_driver("--uninstall", "--yes"))
        self.assertFalse(self.netplan().exists())

    def test_metric_changes_rewrite(self):
        self.assertOk(self.run_driver())
        self.site.write_text(self.SITE.replace("700", "300"))
        self.assertEqual(self.run_driver("--check").returncode, 3)
        self.assertOk(self.run_driver())
        self.assertIn("route-metric: 300", self.netplan().read_text())

    def test_bad_metric_refused(self):
        self.site.write_text(self.SITE.replace("700", "fast"))
        r = self.run_driver()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("USB_ETH_ROUTE_METRIC", r.stdout + r.stderr)

    def test_off_by_default(self):
        self.site.write_text('COMPONENTS="none"\nNODE_NAME=tap-node\n')
        self.assertOk(self.run_driver())
        self.assertFalse(self.netplan().exists())


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class OneKidSiteFile(FieldNodeCase):
    """The older one-kid variables (KID_NAME, KID_BUNDLE, CAT062_SOURCE, ...) still work."""
    SITE = STANDARD_SITE.split("KIDS=")[0] + """\
KID_NAME=xf-ingest
KID_VERSION=0.2.0
KID_BUNDLE={bundle}
KID_BUNDLE_SHA256={sha}
KID_BIND=192.0.2.10
KID_PORT=4000
CAT062_SOURCE=xf-track
CAT062_SAC=0
CAT062_SIC=160
"""
    KID = ("xf-ingest", "0.2.0")

    def setUp(self):
        super().setUp()
        (self.tmp / "radar-tap.env").write_text("TAP_INTERFACE=eth0\n")

    def test_legacy_kid(self):
        self.assertOk(self.run_driver())
        billie = " ".join(c for c in self.calls() if c.startswith("billie "))
        self.assertIn("kid configure xf-ingest --transport udp --bind-address 192.0.2.10 --port 4000 --source-cidr 192.0.2.10/32", billie)
        self.assertIn("cat062 source set xf-ingest xf-track --sac 0 --sic 160", billie)


@unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
class FieldNodeShellcheck(unittest.TestCase):
    def test_shellcheck_clean(self):
        files = [DRIVER, FIELD / "bin" / "field-node-mode", FIELD / "lib" / "common.sh",
                 FIELD / "components" / "scapegoat-field-config", *sorted((FIELD / "components").glob("*.sh"))]
        r = subprocess.run(["shellcheck", "-x", *map(str, files)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)


if __name__ == "__main__":
    unittest.main()
