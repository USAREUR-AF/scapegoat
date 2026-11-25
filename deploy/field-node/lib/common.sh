# shellcheck shell=bash disable=SC2034,SC2154  # globals come from install-field-node.sh
# Shared helpers for install-field-node.sh and its components. Sourced, never run.
# Globals used: ROOT CHECK DRIFT N PHASES.

phase() { N=$((N + 1)); echo; echo "[$N/$PHASES] $*"; }
ok() { echo "    ok: $*"; }
note() { echo "    note: $*"; }
die() { echo "    FAILED: $*" >&2; echo "Stopped at phase $N. Nothing after it was run." >&2; exit 1; }
act() {  # act "<what>" cmd... : run cmd, or in --check mode only report it
  local what=$1; shift
  DRIFT=1
  if [[ $CHECK -eq 1 ]]; then echo "    would: $what"; return 0; fi
  echo "    doing: $what"
  "$@"
}
same_file() { [[ -f "$2" ]] && cmp -s "$1" "$2"; }
put_file() { mkdir -p "$(dirname "$2")" && install -m "$3" "$1" "$2"; }   # BSD install has no -D
install_file() {  # returns 0 if it changed something
  if same_file "$1" "$2"; then return 1; fi
  act "install $2" put_file "$1" "$2" "$3"
  return 0
}
sha256_of() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
in_list() { local x=$1 y; shift; for y in "$@"; do [[ $x == "$y" ]] && return 0; done; return 1; }
remove_unit() { systemctl disable --now "$1" >/dev/null 2>&1 || true; rm -f "$UNIT_DIR/$1"; }
var_key() { echo "$1" | tr '[:lower:]-' '[:upper:]_'; }   # xf-ingest -> XF_INGEST
# resolve_iface <name-or-glob>: an interface name passes through; a glob such as enx* (a USB
# Ethernet adapter, whose name carries its MAC address and so never goes in a site file)
# resolves to the one matching interface. Fails if none or several match.
resolve_iface() {
  local want=$1 n found=()
  if [[ $want != *[\*\?]* ]]; then echo "$want"; return 0; fi
  while read -r n; do
    # shellcheck disable=SC2053
    [[ $n == $want ]] && found+=("$n")
  done < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1)
  if [[ ${#found[@]} -ne 1 ]]; then
    echo "SENSOR_IFACE=$want matches ${#found[@]} interfaces (${found[*]:-none}); it must match exactly one" >&2
    return 1
  fi
  echo "${found[0]}"
}
