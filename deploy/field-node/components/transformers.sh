# shellcheck shell=bash disable=SC2034,SC2154  # globals come from install-field-node.sh
# Component "transformers": goat-transformers on the node at /opt/goat-transformers, for
# scapegoat's C2 outputs (ASTERIX CAT062, CoT, SAPIENT). From a PINNED ref of the public
# USAREUR-AF/goat-transformers; only what the outputs need is kept: the Python engine
# (engines/python/src), model/, LICENSE, NOTICE and the packs canonical-track-v2 plus the
# output formats.
#
# Site file, one of two pins (the run refuses without one, and on any mismatch):
#   GOAT_TRANSFORMERS_REF=<tag or commit>      what to fetch (shown in status)
#   GOAT_TRANSFORMERS_COMMIT=<40 hex>          git: the fetched ref must be this commit
#   GOAT_TRANSFORMERS_SHA256=<64 hex>          tarball: the archive must have this sha256
#   GOAT_TRANSFORMERS_TARBALL=<path>           offline: a local .tar.gz of the tree (needs SHA256)
#   GOAT_TRANSFORMERS_GIT=<url>                default https://github.com/USAREUR-AF/goat-transformers.git
#   GOAT_TRANSFORMERS_PACKS="<format> ..."     default: the formats of SCAPEGOAT_OUTPUTS, else all three
# Sourced by install-field-node.sh.

transformers_phases=1
GT_DIR="$ROOT/opt/goat-transformers"
GT_PIN_FILE="$GT_DIR/.field-node-pin"

gt_packs() {
  local p="" n v
  if [[ -n "${GOAT_TRANSFORMERS_PACKS:-}" ]]; then p=$GOAT_TRANSFORMERS_PACKS
  else
    for n in ${SCAPEGOAT_OUTPUTS:-}; do v="OUTPUT_$(var_key "$n")_FORMAT"; [[ -n "${!v:-}" ]] && p+=" ${!v}"; done
    [[ -n "$p" ]] || p="asterix-cat062 cot-xml sapient"
  fi
  # shellcheck disable=SC2086
  echo "canonical-track-v2 $(printf '%s\n' $p | sort -u | grep -vx canonical-track-v2 | tr '\n' ' ')" | xargs
}

gt_pin() {  # the pin line recorded beside the install; a change means reinstall
  if [[ -n "${GOAT_TRANSFORMERS_SHA256:-}" ]]; then
    echo "ref=${GOAT_TRANSFORMERS_REF:-} sha256=$GOAT_TRANSFORMERS_SHA256 packs=$(gt_packs)"
  else
    echo "ref=${GOAT_TRANSFORMERS_REF:-} commit=${GOAT_TRANSFORMERS_COMMIT:-} packs=$(gt_packs)"
  fi
}

transformers_preflight() {
  local c=${GOAT_TRANSFORMERS_COMMIT:-} s=${GOAT_TRANSFORMERS_SHA256:-}
  [[ -n "$c" || -n "$s" ]] || die "transformers: pin it: set GOAT_TRANSFORMERS_COMMIT (git) or GOAT_TRANSFORMERS_SHA256 (tarball)"
  [[ -z "$c" || $c =~ ^[0-9a-f]{40}$ ]] || die "transformers: GOAT_TRANSFORMERS_COMMIT must be a full 40-character commit id"
  [[ -z "$s" || $s =~ ^[0-9a-f]{64}$ ]] || die "transformers: GOAT_TRANSFORMERS_SHA256 must be 64 hex characters"
  [[ -n "$s" || -n "${GOAT_TRANSFORMERS_REF:-}" ]] || die "transformers: set GOAT_TRANSFORMERS_REF (the tag or commit to fetch)"
  if [[ -n "${GOAT_TRANSFORMERS_TARBALL:-}" ]]; then
    [[ -n "$s" ]] || die "transformers: a local GOAT_TRANSFORMERS_TARBALL needs GOAT_TRANSFORMERS_SHA256"
    [[ -f "$GOAT_TRANSFORMERS_TARBALL" ]] || die "transformers: no tarball at $GOAT_TRANSFORMERS_TARBALL"
  fi
  return 0
}

gt_fetch() {  # $1 = scratch dir; leaves the source tree in $1/tree; refuses on any mismatch
  local work=$1 tb got
  mkdir -p "$work/tree"
  if [[ -n "${GOAT_TRANSFORMERS_SHA256:-}" ]]; then
    tb=${GOAT_TRANSFORMERS_TARBALL:-}
    if [[ -z "$tb" ]]; then
      tb="$work/gt.tar.gz"
      curl -fsSL -o "$tb" "https://codeload.github.com/USAREUR-AF/goat-transformers/tar.gz/${GOAT_TRANSFORMERS_REF}" ||
        die "transformers: download of ${GOAT_TRANSFORMERS_REF} failed (offline? set GOAT_TRANSFORMERS_TARBALL)"
    fi
    got=$(sha256_of "$tb")
    [[ $got == "$GOAT_TRANSFORMERS_SHA256" ]] ||
      die "transformers: $tb has sha256 $got, the site file pins $GOAT_TRANSFORMERS_SHA256; nothing installed"
    tar -xzf "$tb" -C "$work/tree" --strip-components 1 || die "transformers: $tb is not a readable .tar.gz"
  else
    git -c advice.detachedHead=false clone -q --depth 1 --branch "$GOAT_TRANSFORMERS_REF" \
        "${GOAT_TRANSFORMERS_GIT:-https://github.com/USAREUR-AF/goat-transformers.git}" "$work/tree" 2>/dev/null ||
      { rm -rf "$work/tree"; git clone -q "${GOAT_TRANSFORMERS_GIT:-https://github.com/USAREUR-AF/goat-transformers.git}" "$work/tree" &&
        git -C "$work/tree" checkout -q "$GOAT_TRANSFORMERS_REF"; } ||
      die "transformers: could not fetch ${GOAT_TRANSFORMERS_REF} from ${GOAT_TRANSFORMERS_GIT:-github}"
    got=$(git -C "$work/tree" rev-parse HEAD)
    [[ $got == "$GOAT_TRANSFORMERS_COMMIT" ]] ||
      die "transformers: ${GOAT_TRANSFORMERS_REF} is commit $got, the site file pins $GOAT_TRANSFORMERS_COMMIT; nothing installed"
  fi
}

gt_stage() {  # $1 = source tree, $2 = destination: only what the outputs need
  local src=$1 dst=$2 p
  [[ -d "$src/engines/python/src/goat_transformers" ]] || die "transformers: the tree has no engines/python/src/goat_transformers"
  mkdir -p "$dst/engines/python" "$dst/packs"
  cp -R "$src/engines/python/src" "$dst/engines/python/src"
  [[ -d "$src/model" ]] && cp -R "$src/model" "$dst/model"
  for p in LICENSE NOTICE; do [[ -f "$src/$p" ]] && cp "$src/$p" "$dst/$p"; done
  for p in $(gt_packs); do
    [[ -f "$src/packs/$p/pack.def" ]] || die "transformers: the pinned tree has no pack $p"
    cp -R "$src/packs/$p" "$dst/packs/$p"
  done
  find "$dst" -name __pycache__ -type d -prune -exec rm -rf {} +
  gt_pin > "$dst/.field-node-pin"
}

gt_install() {
  local work new
  work=$(mktemp -d)
  new="$GT_DIR.new"
  gt_fetch "$work"
  rm -rf "$new"
  gt_stage "$work/tree" "$new"
  rm -rf "$work"
  rm -rf "$GT_DIR"
  mkdir -p "$(dirname "$GT_DIR")"
  mv "$new" "$GT_DIR"
}

transformers_apply() {
  phase "goat-transformers for the C2 outputs ($GT_DIR, $(gt_pin))"
  if [[ -f "$GT_PIN_FILE" && "$(cat "$GT_PIN_FILE")" == "$(gt_pin)" ]]; then
    ok "installed at the pinned ref"
  else
    act "install goat-transformers $(gt_pin)" gt_install
  fi
}

transformers_verify() {
  if [[ $CHECK -eq 1 && ! -d "$GT_DIR" ]]; then return 0; fi
  if PYTHONPATH="$GT_DIR/engines/python/src" python3 -c 'import goat_transformers' 2>/dev/null &&
     [[ -f "$GT_DIR/packs/canonical-track-v2/pack.def" ]]; then
    ok "goat-transformers importable"
  else
    echo "    NOT USABLE: $GT_DIR (goat_transformers does not import or packs are missing)" >&2
    FAILED=1
  fi
}

transformers_uninstall() {
  phase "goat-transformers"
  if [[ -f "$GT_PIN_FILE" ]]; then act "remove $GT_DIR" rm -rf "$GT_DIR"
  elif [[ -d "$GT_DIR" ]]; then note "$GT_DIR was not installed by this script; left in place"; fi
}
