"""The field-node site file's C2 output settings render into scapegoat.toml [outputs.*]."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from scapegoat.core import config as cfgmod

REPO = Path(__file__).resolve().parent.parent
FIELD = REPO / "deploy" / "field-node"

SITE = """NODE_NAME=c2-node
NODE_ROLE="C2 node"
SENSOR_IFACE=eth0
LAN_LOCAL_CIDR=192.0.2.10/24
LAN_PEER=192.0.2.81:47000
LAN_PEER_CANDIDATES="192.0.2.81:47000"
ISLAND_REST=http://127.0.0.1:8000
GOAT_TRANSFORMERS_PATH=/opt/goat-transformers
SCAPEGOAT_OUTPUTS="cat062 cot"
OUTPUT_CAT062_FORMAT=asterix-cat062
OUTPUT_CAT062_TO="udp://239.255.62.1:8600 zenoh:site/sensor/cat062"
OUTPUT_CAT062_SAC=38
OUTPUT_CAT062_SIC=202
OUTPUT_COT_FORMAT=cot-xml
OUTPUT_COT_ENABLED=false
OUTPUT_COT_TO="udp://239.2.3.1:6969"
OUTPUT_COT_HOW=m-r
OUTPUT_COT_STALE_S=20
"""


class TestFieldNodeOutputs(unittest.TestCase):
    def test_site_outputs_render_and_load(self):
        with tempfile.TemporaryDirectory() as d:
            site = Path(d) / "site.env"
            site.write_text(SITE)
            env = dict(os.environ, FIELD_ROOT=d, FIELD_ENV=str(site),
                       FIELD_PACK_DIR=str(FIELD / "packs" / "toy"), FIELD_PROGRAM=str(REPO))
            p = subprocess.run([str(FIELD / "components" / "scapegoat-field-config"), "lan",
                                "--no-restart"], env=env, capture_output=True, text=True,
                               timeout=60)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            conf = Path(d) / "etc" / "scapegoat" / "scapegoat.toml"
            text = conf.read_text()
            self.assertIn("[outputs.cat062]", text)
            cfg = cfgmod.load(str(conf))
        o = cfg.outputs
        self.assertEqual(o["cat062"]["to"], ["udp://239.255.62.1:8600", "zenoh:site/sensor/cat062"])
        self.assertEqual(o["cat062"]["context"], {"cat062.sac": 38, "cat062.sic": 202})
        self.assertFalse(o["cot"]["enabled"])
        self.assertEqual((o["cot"]["context"], o["cot"]["stale_s"]), ({"how": "m-r"}, 20.0))
        self.assertEqual(cfg.transformers_path, "/opt/goat-transformers")

    def test_no_outputs_renders_none(self):
        with tempfile.TemporaryDirectory() as d:
            site = Path(d) / "site.env"
            site.write_text(SITE.split("GOAT_TRANSFORMERS_PATH")[0])
            env = dict(os.environ, FIELD_ROOT=d, FIELD_ENV=str(site),
                       FIELD_PACK_DIR=str(FIELD / "packs" / "toy"), FIELD_PROGRAM=str(REPO))
            p = subprocess.run([str(FIELD / "components" / "scapegoat-field-config"), "lan",
                                "--no-restart"], env=env, capture_output=True, text=True,
                               timeout=60)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            cfg = cfgmod.load(str(Path(d) / "etc" / "scapegoat" / "scapegoat.toml"))
        self.assertEqual(cfg.outputs, {})
