#!/usr/bin/env bash
# Install scapegoat on this node (Ubuntu/Raspberry Pi OS with systemd).
#   sudo ./deploy/install.sh              install or upgrade (safe to re-run)
#   sudo ./deploy/install.sh --uninstall  remove the program and service (keeps /etc/scapegoat)
#
# Site hooks: every deploy/install.d/*.sh is sourced at each phase with HOOK_PHASE set to
# after-uninstall, after-program, before-profiles or before-service (none ship with the core).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT=${SCAPEGOAT_INSTALL_ROOT:-}             # tests only: install under a scratch root
SYSTEMCTL=${SCAPEGOAT_SYSTEMCTL:-systemctl}  # tests only: a stub
PREFIX="$ROOT/opt/scapegoat"
CONF_DIR="$ROOT/etc/scapegoat"
UNIT_DIR="$ROOT/etc/systemd/system"
UNIT="$UNIT_DIR/scapegoat.service"
BIN="$ROOT/usr/local/bin"
WRAPPER="$BIN/scapegoat"
# Protocol plugins carried by this checkout (plugins/<name>/__init__.py), if any.
PLUGINS=()
for d in "$REPO"/plugins/*/; do [[ -f "$d/__init__.py" ]] && PLUGINS+=("$(basename "$d")"); done
# Site file template: a plugin's deploy/scapegoat.toml if one ships, else the core default.
SITE_TEMPLATE="$REPO/deploy/scapegoat.toml"
for n in "${PLUGINS[@]+"${PLUGINS[@]}"}"; do
  [[ -f "$REPO/plugins/$n/deploy/scapegoat.toml" ]] && { SITE_TEMPLATE="$REPO/plugins/$n/deploy/scapegoat.toml"; break; }
done
profile_files() { ls "$REPO"/scapegoat/profiles/*.toml "$REPO"/plugins/*/profiles/*.toml 2>/dev/null || true; }

if [[ -z "$ROOT" && $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0 $*" >&2
  exit 1
fi

sc() { "$SYSTEMCTL" "$@"; }
run_hooks() {
  local h
  for h in "$REPO"/deploy/install.d/*.sh; do
    [[ -f "$h" ]] || continue
    # shellcheck disable=SC1090
    HOOK_PHASE=$1 . "$h"
  done
}

if [[ "${1:-}" == "--uninstall" ]]; then
  sc disable --now scapegoat 2>/dev/null || true
  rm -f "$UNIT" "$WRAPPER"
  for f in $(profile_files); do rm -f "$CONF_DIR/profiles/$(basename "$f")"; done
  rm -rf "$PREFIX"
  sc daemon-reload
  echo "scapegoat removed (and its shipped profiles). Your config is still in $CONF_DIR."
  run_hooks after-uninstall
  exit 0
fi
if [[ -n "${1:-}" ]]; then
  echo "Unknown option: $1  (use --uninstall or nothing)" >&2
  exit 2
fi

command -v python3 >/dev/null || { echo "python3 is missing. Install it: apt install python3" >&2; exit 1; }
python3 - <<'PY' || { echo "scapegoat needs Python 3.10 or newer." >&2; exit 1; }
import sys
sys.exit(0 if sys.version_info >= (3, 10) else 1)
PY

echo "Installing the program to $PREFIX"
mkdir -p "$PREFIX"
rm -rf "$PREFIX/scapegoat.new"
cp -R "$REPO/scapegoat" "$PREFIX/scapegoat.new"
find "$PREFIX/scapegoat.new" -name __pycache__ -type d -prune -exec rm -rf {} +
rm -rf "$PREFIX/scapegoat"
mv "$PREFIX/scapegoat.new" "$PREFIX/scapegoat"

# Protocol plugins go to $PREFIX/plugins/<name> (the core looks there).
rm -rf "$PREFIX/plugins"
for n in "${PLUGINS[@]+"${PLUGINS[@]}"}"; do
  mkdir -p "$PREFIX/plugins"
  cp -R "$REPO/plugins/$n" "$PREFIX/plugins/$n"
  rm -rf "$PREFIX/plugins/$n/tests"
  find "$PREFIX/plugins/$n" -name __pycache__ -type d -prune -exec rm -rf {} +
  echo "Installed protocol plugin $n"
done

echo "Writing $WRAPPER"
mkdir -p "$BIN"
cat > "$WRAPPER" <<'SH'
#!/bin/sh
PYTHONPATH=/opt/scapegoat exec /usr/bin/python3 -m scapegoat "$@"
SH
chmod 755 "$WRAPPER"
run_hooks after-program

run_hooks before-profiles

# Shipped profiles (scapegoat/profiles and each plugin's profiles/) are also
# installed in /etc. Shipped names are overwritten; other profiles there are left alone.
mkdir -p "$CONF_DIR/profiles"
for f in $(profile_files); do
  install -m 644 "$f" "$CONF_DIR/profiles/"
  echo "Installed profile $(basename "$f" .toml)"
done

if [[ -f "$CONF_DIR/scapegoat.toml" ]]; then
  echo "Keeping your config $CONF_DIR/scapegoat.toml"
else
  install -m 644 "$SITE_TEMPLATE" "$CONF_DIR/scapegoat.toml"
  echo "Wrote $CONF_DIR/scapegoat.toml from $SITE_TEMPLATE. Edit it for this site."
fi

run_hooks before-service
mkdir -p "$UNIT_DIR"
install -m 644 "$REPO/deploy/scapegoat.service" "$UNIT"
sc daemon-reload
sc enable scapegoat >/dev/null
sc restart scapegoat
sleep 1
if sc is-active --quiet scapegoat; then
  echo "scapegoat is running. Check it:  scapegoat status"
else
  echo "scapegoat did not start. See:  journalctl -u scapegoat -n 50" >&2
  exit 1
fi
