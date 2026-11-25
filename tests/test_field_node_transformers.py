"""Field-node component "transformers": goat-transformers at a pinned ref (stubbed system,
a synthetic goat-transformers tree; no network)."""

import hashlib
import shutil
import subprocess
import tarfile
import unittest

from tests.field_node_harness import FieldNodeCase
from tests.test_field_node import TOY_SITE

SITE = TOY_SITE.replace('COMPONENTS="network capture kids scapegoat"',
                        'COMPONENTS="network transformers capture kids scapegoat"') + """\
GOAT_TRANSFORMERS_REF=v0.8.0
SCAPEGOAT_OUTPUTS="cat062"
OUTPUT_CAT062_FORMAT=asterix-cat062
OUTPUT_CAT062_TO="udp://239.255.62.1:8600"
OUTPUT_CAT062_SAC=1
OUTPUT_CAT062_SIC=7
"""


def make_tree(root):
    """A small stand-in for a goat-transformers checkout."""
    (root / "engines/python/src/goat_transformers").mkdir(parents=True)
    (root / "engines/python/src/goat_transformers/__init__.py").write_text("Engine = object\n")
    (root / "engines/go").mkdir(parents=True)
    (root / "engines/go/main.go").write_text("package main\n")
    (root / "model").mkdir()
    (root / "model/core.def").write_text("module core\n")
    for p in ("canonical-track-v2", "asterix-cat062", "cot-xml", "sapient", "adsb"):
        (root / "packs" / p).mkdir(parents=True)
        (root / "packs" / p / "pack.def").write_text(f"format {p}\n")
    (root / "LICENSE").write_text("Apache-2.0\n")


@unittest.skipUnless(shutil.which("bash") and shutil.which("git"), "needs bash and git")
class TransformersFromTarball(FieldNodeCase):
    SITE = SITE

    def setUp(self):
        super().setUp()
        src = self.tmp / "gt-src" / "goat-transformers-0.8.0"
        make_tree(src)
        self.tarball = self.tmp / "gt.tar.gz"
        with tarfile.open(self.tarball, "w:gz") as tf:
            tf.add(src, arcname="goat-transformers-0.8.0")
        self.sha = hashlib.sha256(self.tarball.read_bytes()).hexdigest()
        self.gt = self.root / "opt/goat-transformers"

    def set_pin(self, sha=None, tarball=None):
        self.site.write_text(SITE + f"GOAT_TRANSFORMERS_SHA256={sha or self.sha}\n"
                             f"GOAT_TRANSFORMERS_TARBALL={tarball or self.tarball}\n")

    def test_install_only_what_outputs_need_check_rerun_uninstall(self):
        self.set_pin()
        r = self.run_driver()
        self.assertOk(r)
        self.assertTrue((self.gt / "engines/python/src/goat_transformers/__init__.py").exists())
        self.assertEqual(sorted(p.name for p in (self.gt / "packs").iterdir()),
                         ["asterix-cat062", "canonical-track-v2"])
        self.assertFalse((self.gt / "engines/go").exists())
        self.assertTrue((self.gt / "LICENSE").exists())
        self.assertIn(f"sha256={self.sha}", (self.gt / ".field-node-pin").read_text())
        self.assertIn("goat-transformers importable", r.stdout)
        r = self.run_driver("--check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("installed at the pinned ref", r.stdout)
        r = self.run_driver()
        self.assertOk(r)
        self.assertNotIn("install goat-transformers", r.stdout)
        r = self.run_driver("--uninstall", "--yes")
        self.assertOk(r)
        self.assertFalse(self.gt.exists())

    def test_wrong_sha256_refused_nothing_installed(self):
        self.set_pin(sha="0" * 64)
        r = self.run_driver()
        self.assertEqual(r.returncode, 1)
        self.assertIn("the site file pins " + "0" * 64, r.stderr)
        self.assertFalse(self.gt.exists())

    def test_no_pin_refused(self):
        r = self.run_driver()
        self.assertEqual(r.returncode, 1)
        self.assertIn("pin it", r.stderr)

    def test_pin_change_is_drift(self):
        self.set_pin()
        self.assertOk(self.run_driver())
        self.site.write_text(self.site.read_text() + 'GOAT_TRANSFORMERS_PACKS="cot-xml"\n')
        r = self.run_driver("--check")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("would: install goat-transformers", r.stdout)


@unittest.skipUnless(shutil.which("bash") and shutil.which("git"), "needs bash and git")
class TransformersFromGit(FieldNodeCase):
    SITE = SITE

    def setUp(self):
        super().setUp()
        self.repo = self.tmp / "gt-repo"
        make_tree(self.repo)
        git = ["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=tester",
               "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"]
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-q", "-m", "tree"], check=True)
        subprocess.run(git + ["tag", "v0.8.0"], check=True)
        self.commit = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                                     capture_output=True, text=True, check=True).stdout.strip()

    def test_commit_pin(self):
        self.site.write_text(SITE + f"GOAT_TRANSFORMERS_COMMIT={self.commit}\n"
                             f"GOAT_TRANSFORMERS_GIT={self.repo}\n")
        r = self.run_driver()
        self.assertOk(r)
        self.assertIn(f"commit={self.commit}",
                      (self.root / "opt/goat-transformers/.field-node-pin").read_text())

    def test_wrong_commit_refused(self):
        self.site.write_text(SITE + f"GOAT_TRANSFORMERS_COMMIT={'a' * 40}\n"
                             f"GOAT_TRANSFORMERS_GIT={self.repo}\n")
        r = self.run_driver()
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"is commit {self.commit}, the site file pins {'a' * 40}", r.stderr)
        self.assertFalse((self.root / "opt/goat-transformers").exists())
