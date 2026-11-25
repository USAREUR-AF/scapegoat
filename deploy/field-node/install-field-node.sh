#!/usr/bin/env bash
# shellcheck disable=SC2034  # globals below are used by the sourced components
# shellcheck source-path=SCRIPTDIR
# install-field-node.sh: build (or re-build) a field node from one site file.
#
#   sudo ./install-field-node.sh --site my-site.env      install, or converge to the site file
#   sudo ./install-field-node.sh                         re-run with /etc/field-node/site.env
#   ./install-field-node.sh --check [--site f]           print state, change nothing (exit 3 = drift)
#   sudo ./install-field-node.sh --mode <mode>           also switch the sensor mode
#   sudo ./install-field-node.sh --uninstall --yes       undo everything this script installed
#
# The site file chooses the components (COMPONENTS, default "network capture kids"):
#   network    static addresses and modes on the sensor interface (components/network.sh)
#   capture    first-bite's tap, or a pack's capture units (components/capture.sh)
#   kids       any Billie kids (components/kids.sh)
#   passthrough  publish a sensor's datagrams unchanged, for a format no kid takes yet
#   none       COMPONENTS="none": record and check the site file, manage nothing
#   scapegoat  a surrogate C2, only for sensors that wait to be spoken to (components/scapegoat.sh)
#   transformers  goat-transformers at a pinned ref, for scapegoat's C2 outputs (components/transformers.sh)
#   usb_eth    a hot-plug USB Ethernet adapter as an optional DHCP uplink; also switched on by
#              USB_ETH=on, which works with COMPONENTS="none" (components/usb_eth.sh)
# Sensor-specific facts (modes, profiles, capture lists) come from the pack named by
# FIELD_PACK (default: the built-in "plain" pack). Every phase checks first and changes only
# what differs; a failed check stops the run before later phases.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ROOT=${FIELD_NODE_ROOT:-}                    # tests only: install under a scratch root

ETC="$ROOT/etc/field-node"
SITE_DST="$ETC/site.env"
PACK_DST="$ETC/pack"
MODE_FILE="$ETC/mode"
UNIT_DIR="$ROOT/etc/systemd/system"
BIN_DIR="$ROOT/usr/local/bin"
LIBEXEC_DIR="$ROOT/usr/local/libexec"
HOOK_DIR="$ROOT/usr/local/lib/field-node/mode.d"
TAP_ETC="$ROOT/etc/first-bite"
ORDER="usb_eth network transformers scapegoat capture kids passthrough"   # apply order; scapegoat needs the network modes
FIELD_HOOKS=()

# shellcheck source=lib/common.sh
. "$HERE/lib/common.sh"

SITE=""
CHECK=0
UNINSTALL=0
YES=0
MODE_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --site) SITE=${2:?--site needs a file}; shift 2 ;;
    --check) CHECK=1; shift ;;
    --mode) MODE_ARG=${2:?--mode needs a mode name}; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --yes) YES=1; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done
DRIFT=0
N=0
PHASES=0
FAILED=0

if [[ -z "$ROOT" && $CHECK -eq 0 && $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0 $*" >&2
  exit 1
fi

# ------------------------------------------------------------------ site file and pack
if [[ -z "$SITE" ]]; then
  SITE=$SITE_DST
  [[ -f "$SITE" ]] || { echo "No site file. First run: $0 --site <file> (start from $HERE/examples/)" >&2; exit 1; }
fi
[[ -f "$SITE" ]] || { echo "Site file not found: $SITE" >&2; exit 1; }
set -a
# shellcheck disable=SC1090
. "$SITE"
set +a
if [[ -z "${SENSOR_IFACE:-}" && -n "${RADAR_IFACE:-}" ]]; then
  echo "The site file sets RADAR_IFACE; rename it to SENSOR_IFACE." >&2
  exit 1
fi
SENSOR_IFACE_GLOB=""
if [[ ${SENSOR_IFACE:-} == *[\*\?]* ]]; then   # enx*: resolve to the one matching interface
  SENSOR_IFACE_GLOB=$SENSOR_IFACE
  SENSOR_IFACE=$(resolve_iface "$SENSOR_IFACE") || exit 1
  export SENSOR_IFACE
fi
COMPONENTS=${COMPONENTS:-network capture kids}
# COMPONENTS="none": the node's site file is recorded and checked, and the installer manages
# nothing on it (for a node whose links are owned by another tool).
[[ $COMPONENTS == none ]] && COMPONENTS=""
for c in $COMPONENTS; do
  # shellcheck disable=SC2086
  in_list "$c" $ORDER || { echo "Unknown component '$c' in COMPONENTS (known: $ORDER)" >&2; exit 1; }
done

find_pack() {  # a directory, or a name: plugins/<name>/field-node, packs/<name>, installed copies
  local p=$1 d
  if [[ -d "$p" && -f "$p/pack.env" ]]; then (cd "$p" && pwd); return 0; fi
  for d in "$REPO/plugins/$p/field-node" "$HERE/packs/$p" "$ROOT/opt/scapegoat/plugins/$p/field-node"; do
    if [[ -f "$d/pack.env" ]]; then (cd "$d" && pwd); return 0; fi
  done
  return 1
}
PACK=$(find_pack "${FIELD_PACK:-plain}") || { echo "FIELD_PACK=${FIELD_PACK:-} names no field-node pack (plugins/<name>/field-node or deploy/field-node/packs/<name>)" >&2; exit 1; }
set -a
# shellcheck disable=SC1091
. "$PACK/pack.env"
set +a
MODES=${MODES:?the field-node pack defines no MODES}

ACTIVE=()
for c in $ORDER; do
  # shellcheck disable=SC2086
  in_list "$c" $COMPONENTS || { [[ "$c" == usb_eth && "${USB_ETH:-off}" == on ]]; } || continue
  # shellcheck disable=SC1090
  . "$HERE/components/$c.sh"
  ACTIVE+=("$c")
done
has() { in_list "$1" "${ACTIVE[@]+"${ACTIVE[@]}"}"; }
call() { if declare -F "$1" >/dev/null; then "$1"; fi; }
expect_active() { if systemctl is-active --quiet "$1"; then ok "$1 active"; else echo "    NOT ACTIVE: $1 (journalctl -u $1 -n 50)" >&2; FAILED=1; fi; }

# ================================================================== uninstall
if [[ $UNINSTALL -eq 1 ]]; then
  if [[ $YES -ne 1 && $CHECK -eq 0 ]]; then
    cat >&2 <<EOF
--uninstall undoes the components ${ACTIVE[*]:-none} on this node: capture units or first-bite tap
instances, the managed addresses on ${SENSOR_IFACE:-} and their netplan file, the mode
command and hooks, the scapegoat program and service (if the component is used), the installed
pack. Billie kids are stopped; their packages are kept. Kept: /etc/field-node/site.env and
every capture file. Re-run with --uninstall --yes to proceed.
EOF
    exit 2
  fi
  PHASES=$(( ${#ACTIVE[@]} + 1 ))
  for ((i=${#ACTIVE[@]}-1; i>=0; i--)); do call "${ACTIVE[$i]}_uninstall"; done
  phase "Installed pack"
  if [[ -d "$PACK_DST" ]]; then act "remove $PACK_DST" rm -rf "$PACK_DST"; fi
  echo
  if [[ $CHECK -eq 1 && $DRIFT -eq 1 ]]; then exit 3; fi
  echo "Uninstalled. Re-install any time with: sudo $0 --site $SITE_DST"
  exit 0
fi

# ================================================================== install / converge
PHASES=3
for c in "${ACTIVE[@]+"${ACTIVE[@]}"}"; do v="${c}_phases"; PHASES=$((PHASES + ${!v:-1})); done

phase "Preflight: site file, pack ${PACK_NAME}, components ${ACTIVE[*]:-none}"
NEED_IFACE=0
for c in network capture passthrough; do has "$c" && NEED_IFACE=1; done
export NEED_IFACE
python3 - "$SITE" <<'PY' || die "fix the site file values above"
import os, re, sys
e, bad = os.environ, []
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", e.get("NODE_NAME", "")): bad.append("NODE_NAME: letters, digits, . _ -")
if (e.get("NEED_IFACE") == "1" or e.get("SENSOR_IFACE")) and not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", e.get("SENSOR_IFACE", "")):
    bad.append("SENSOR_IFACE is not an interface name")
if e.get("ALLOW_NET_CONTROL", "false") not in ("true", "false"): bad.append("ALLOW_NET_CONTROL must be true or false")
if e.get("ISLAND_REST") and not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d+)?/?", e["ISLAND_REST"]):
    bad.append("ISLAND_REST must be like http://127.0.0.1:8000")
if re.search(r"(?i)\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b", open(sys.argv[1]).read()):
    bad.append("the site file contains a MAC address; remove it")
for b in bad: print("    -", b)
sys.exit(1 if bad else 0)
PY
for t in python3 ip systemctl install cmp; do command -v "$t" >/dev/null || die "$t is not installed"; done
for c in "${ACTIVE[@]+"${ACTIVE[@]}"}"; do call "${c}_preflight"; done
MODE=$MODE_ARG
for pair in ${MODE_ALIASES:-}; do [[ "${pair%%=*}" == "$MODE" ]] && MODE=${pair#*=}; done
if [[ -z "$MODE" && -f "$MODE_FILE" ]]; then MODE=$(tr -d '[:space:]' < "$MODE_FILE"); fi
MODE=${MODE:-${FIELD_MODE:-${MODES%% *}}}
# shellcheck disable=SC2086
in_list "$MODE" $MODES || die "mode '$MODE' is not one of the pack's modes: $MODES"
ok "site file $SITE; node $NODE_NAME; pack $PACK_NAME; interface ${SENSOR_IFACE:-none}; mode $MODE; components ${ACTIVE[*]:-none}"

phase "Site file and pack on the node ($SITE_DST, $PACK_DST)"
SITE_CHANGED=0
if [[ "$(cd "$(dirname "$SITE")" && pwd)/$(basename "$SITE")" == "$SITE_DST" ]] || same_file "$SITE" "$SITE_DST"; then
  ok "site file in place"
else
  act "copy $SITE to $SITE_DST" put_file "$SITE" "$SITE_DST" 644
  SITE_CHANGED=1
fi
if diff -rq "$PACK" "$PACK_DST" >/dev/null 2>&1; then
  ok "pack in place"
else
  act "copy the $PACK_NAME pack to $PACK_DST" bash -c "rm -rf '$PACK_DST' && mkdir -p '$ETC' && cp -R '$PACK' '$PACK_DST'"
  SITE_CHANGED=1
fi

for c in "${ACTIVE[@]+"${ACTIVE[@]}"}"; do call "${c}_pre"; done
for c in "${ACTIVE[@]+"${ACTIVE[@]}"}"; do call "${c}_apply"; done

phase "Verify"
if [[ $CHECK -eq 1 ]]; then
  echo
  if [[ $DRIFT -eq 1 ]]; then echo "Check: this node differs from the site file (see 'would' lines). Run without --check to converge."; exit 3; fi
  echo "Check: this node matches the site file."
  exit 0
fi
for c in "${ACTIVE[@]+"${ACTIVE[@]}"}"; do call "${c}_verify"; done
[[ $FAILED -eq 0 ]] || die "verification failed (above)"
echo
echo "Field node $NODE_NAME is in place (components ${ACTIVE[*]:-none}, pack $PACK_NAME, mode $MODE)."
