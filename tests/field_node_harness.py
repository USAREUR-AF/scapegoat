"""Shared harness for field-node installer tests: a scratch root and stub system commands.

ip, systemctl, tcpdump, curl, billie, first-bite's tap installer and deploy/install.sh are
stubs that record their calls and keep a little state, so the installer's phases,
idempotence, --check, --mode and --uninstall run on any machine without touching its
network or services.
"""

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIELD = REPO / "deploy" / "field-node"
DRIVER = FIELD / "install-field-node.sh"

STUBS = {
    # ip: addresses kept in $STATE/addrs as "<iface> <cidr>" lines; only eth0 exists.
    "ip": r'''
        f="$STATE/addrs"; touch "$f" "$STATE/links" "$STATE/routes"; echo "ip $*" >> "$STATE/calls"
        case "$*" in
          "-o link show") echo "1: lo: <LOOPBACK>"; echo "2: eth0: <UP>"; awk '{print NR+2 ": " $1 ": <UP>"}' "$STATE/links" ;;
          "link show dev eth0") exit 0 ;;
          "link show dev"*) grep -qxF "$4" "$STATE/links" ;;
          "-4 route show "*) awk -v d="$4" -v i="$6" '$1==i && $2==d {print d " dev " i " scope link"}' "$STATE/routes" ;;
          "route replace "*) grep -vxF "$5 $3" "$STATE/routes" > "$STATE/routes.n" || true; echo "$5 $3" >> "$STATE/routes.n"; mv "$STATE/routes.n" "$STATE/routes" ;;
          "route del "*) grep -vxF "$5 $3" "$STATE/routes" > "$STATE/routes.n" || true; mv "$STATE/routes.n" "$STATE/routes" ;;
          "-4 -o addr show dev "*) i=${6}; awk -v i="$i" '$1==i {print "2: " i "    inet " $2 " scope global " i}' "$f" ;;
          "-4 -br addr show dev "*) echo "$6 UP $(awk -v i="$6" '$1==i {printf "%s ", $2}' "$f")" ;;
          "addr add "*) echo "$5 $3" >> "$f" ;;
          "addr del "*) grep -vxF "$5 $3" "$f" > "$f.n" || true; mv "$f.n" "$f" ;;
          *) exit 0 ;;
        esac''',
    # systemctl: $STATE/active/<unit>, $STATE/enabled/<unit>
    "systemctl": r'''
        mkdir -p "$STATE/active" "$STATE/enabled"; echo "systemctl $*" >> "$STATE/calls"
        q=""; [ "$2" = "--quiet" ] && q=1
        case "$1" in
          is-active) u=${3:-$2}; [ -f "$STATE/active/$u" ] ;;
          is-enabled) u=${3:-$2}; [ -f "$STATE/enabled/$u" ] ;;
          enable) shift; [ "$1" = "--now" ] && { shift; touch "$STATE/active/$1"; }; touch "$STATE/enabled/$1" ;;
          restart|start) touch "$STATE/active/$2" ;;
          disable) shift; [ "$1" = "--now" ] && shift; rm -f "$STATE/active/$1" "$STATE/enabled/$1" ;;
          *) exit 0 ;;
        esac''',
    "tcpdump": 'exit 0',
    "curl": 'exit 0',
    "billie": r'''
        echo "billie $*" >> "$STATE/calls"
        case "$1 $2" in
          "kid install") b=$(basename "$3" .tar.gz); mkdir -p "$FIELD_NODE_ROOT/opt/billie/kids/${b%_*}/${b##*_}" ;;
          "kid configure") mkdir -p "$FIELD_NODE_ROOT/etc/billie/kids/$3"
             printf '{"transport":"%s","hostAddress":"%s","hostPort":%s}\n' "$5" "$7" "$9" > "$FIELD_NODE_ROOT/etc/billie/kids/$3/listener.json" ;;
          "kid activate") mkdir -p "$STATE/active"; touch "$STATE/active/billie-kid-$3.service" ;;
          "kid deactivate") rm -f "$STATE/active/billie-kid-$3.service" ;;
          "cat062 source") mkdir -p "$FIELD_NODE_ROOT/etc/billie/translator"
             python3 - "$FIELD_NODE_ROOT/etc/billie/translator/cat062-sources.json" "$4" "$5" "$7" "$9" <<'PY'
import json, sys
f, kid, src, sac, sic = sys.argv[1:]
try:
    d = json.load(open(f))
except (OSError, ValueError):
    d = {"kids": {}}
d["kids"].setdefault(kid, {"sources": {}})["sources"][src] = {"sac": int(sac), "sic": int(sic)}
json.dump(d, open(f, "w"))
PY
             ;;
        esac''',
    # first-bite deployment/tap/install.sh <name> [--env <file>] [--uninstall]
    "fb-tap-install": r'''
        echo "fb-tap-install $*" >> "$STATE/calls"
        mkdir -p "$FIELD_NODE_ROOT/etc/first-bite" "$STATE/active"
        if [ "$2" = "--uninstall" ]; then rm -f "$FIELD_NODE_ROOT/etc/first-bite/tap-$1.env" "$STATE/active/first-bite-tap@$1.service"; exit 0; fi
        cp "$3" "$FIELD_NODE_ROOT/etc/first-bite/tap-$1.env"; touch "$STATE/active/first-bite-tap@$1.service"''',
    # stands in for deploy/install.sh (which needs real root paths)
    "scapegoat-install": r'''
        echo "scapegoat-install $*" >> "$STATE/calls"
        R="$FIELD_NODE_ROOT"
        if [ "$1" = "--uninstall" ]; then rm -rf "$R/opt/scapegoat" "$R/usr/local/bin/scapegoat" "$R/etc/systemd/system/scapegoat.service"; rm -f "$STATE/active/scapegoat.service"; exit 0; fi
        mkdir -p "$R/opt/scapegoat" "$R/usr/local/bin" "$R/etc/systemd/system" "$STATE/active"
        rm -rf "$R/opt/scapegoat/scapegoat"; cp -R "$REPO/scapegoat" "$R/opt/scapegoat/scapegoat"
        find "$R/opt/scapegoat/scapegoat" -name __pycache__ -type d -prune -exec rm -rf {} +
        if [ -d "$REPO/plugins" ]; then rm -rf "$R/opt/scapegoat/plugins"; cp -R "$REPO/plugins" "$R/opt/scapegoat/plugins"; fi
        cp "$REPO/deploy/scapegoat.service" "$R/etc/systemd/system/scapegoat.service"
        printf '#!/bin/sh\n' > "$R/usr/local/bin/scapegoat"; chmod 755 "$R/usr/local/bin/scapegoat"
        touch "$STATE/active/scapegoat.service"''',
}



class FieldNodeCase(unittest.TestCase):
    """Subclass: set SITE (a format string; {dict}, {bundle}, {sha}, {tmp} are filled in)."""
    SITE = ""
    KID = ("kid", "0.1.0")
    DICT_INTERFACE = "example-interface"   # the dictionary folder a protocol pack expects

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="field-node-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root, self.state, self.stubs = self.tmp / "root", self.tmp / "state", self.tmp / "stubs"
        for d in (self.root, self.state, self.stubs):
            d.mkdir()
        for name, body in STUBS.items():
            p = self.stubs / name
            p.write_text("#!/usr/bin/env bash\n" + textwrap.dedent(body).strip() + "\n")
            p.chmod(p.stat().st_mode | stat.S_IEXEC)
        dict_src = self.tmp / "dict"
        (dict_src / self.DICT_INTERFACE).mkdir(parents=True)
        (dict_src / self.DICT_INTERFACE / "metadata.json").write_text("{}\n")
        bundle = self.tmp / f"{self.KID[0]}_{self.KID[1]}.tar.gz"
        bundle.write_bytes(b"bundle")
        mind = self.root / "usr/local/bin/mind"   # first-bite's tap needs mind installed
        mind.parent.mkdir(parents=True)
        mind.write_text("#!/bin/sh\n")
        mind.chmod(0o755)
        self.site = self.tmp / "site.env"
        self.site.write_text(self.SITE.format(dict=dict_src, bundle=bundle, tmp=self.tmp,
                                              sha=hashlib.sha256(b"bundle").hexdigest()))

    def run_driver(self, *args, site=True):
        env = dict(os.environ, FIELD_NODE_ROOT=str(self.root), STATE=str(self.state),
                   REPO=str(REPO), SCAPEGOAT_INSTALL=str(self.stubs / "scapegoat-install"),
                   PATH=f"{self.stubs}:{os.environ['PATH']}")
        env.pop("SCAPEGOAT_PLUGIN_PATH", None)
        cmd = ["bash", str(DRIVER)] + (["--site", str(self.site)] if site else []) + list(args)
        return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)

    def calls(self):
        p = self.state / "calls"
        return p.read_text().splitlines() if p.exists() else []

    def addrs(self):
        p = self.state / "addrs"
        return sorted(x for x in p.read_text().split("\n") if x) if p.exists() else []

    def routes(self):
        p = self.state / "routes"
        return sorted(x for x in p.read_text().split("\n") if x) if p.exists() else []

    def active(self, unit):
        return (self.state / "active" / unit).exists()

    def assertOk(self, r):
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
