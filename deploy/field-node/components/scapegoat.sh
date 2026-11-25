# shellcheck shell=bash disable=SC2034,SC2154  # globals come from install-field-node.sh
# Component "scapegoat" (contributed by the scapegoat project): a surrogate C2 for sensors
# that send nothing until a C2 system speaks first. Only for such sensors; a sensor that
# sends a standard format on its own needs a Billie kid and no scapegoat.
#   - protocol data the pack needs (DATA_VAR / DATA_SRC_VAR / DATA_CHECK, e.g. a dictionary)
#   - the mode hook scapegoat-field-config: on every mode switch it renders
#     /etc/scapegoat/scapegoat.toml from the site file and the pack (checked by scapegoat's
#     own loader first) and restarts scapegoat if the file changed
#   - the scapegoat program and service (deploy/install.sh of this checkout)
# Needs the network component (the pack's modes) and a pack with SESSION_ID and SENSOR_PORT.
# Sourced by install-field-node.sh.

scapegoat_phases=2
FIELD_HOOKS+=("$HERE/components/scapegoat-field-config")
SCAPEGOAT_INSTALL=${SCAPEGOAT_INSTALL:-$REPO/deploy/install.sh}

scapegoat_preflight() {
  # shellcheck disable=SC2086
  in_list network $COMPONENTS || die "the scapegoat component needs the network component (its modes)"
  [[ -n "${SESSION_ID:-}" && -n "${SENSOR_PORT:-}" ]] || die "pack $PACK_NAME has no SESSION_ID/SENSOR_PORT: it is not a scapegoat pack"
  local v
  for v in ${REQUIRED_VARS:-}; do [[ -n "${!v:-}" ]] || die "$v is empty (the $PACK_NAME pack needs it)"; done
  [[ -f "$PACK/session.toml.in" ]] || die "pack $PACK_NAME has no session.toml.in"
}

scapegoat_pre() {   # before the network component applies the mode (the hook must be there)
  phase "scapegoat: protocol data and mode hook"
  if [[ -n "${DATA_VAR:-}" ]]; then
    local data="$ROOT${!DATA_VAR}" src=""
    [[ -n "${DATA_SRC_VAR:-}" ]] && src=${!DATA_SRC_VAR:-}
    if [[ -f "$data/$DATA_CHECK" ]]; then
      ok "protocol data present (${!DATA_VAR})"
    elif [[ -n "$src" && -f "$src/$DATA_CHECK" ]]; then
      act "copy protocol data from $src" bash -c "mkdir -p '$data' && cp -R '$src'/. '$data'/"
    elif [[ $CHECK -eq 1 ]]; then
      DRIFT=1; echo "    missing: $data/$DATA_CHECK"
    else
      die "no protocol data at $data (needs $DATA_CHECK). Copy it there or set $DATA_SRC_VAR."
    fi
  fi
  install_file "$HERE/components/scapegoat-field-config" "$HOOK_DIR/scapegoat" 755 || ok "mode hook current"
}

scapegoat_apply() {
  phase "scapegoat program (/opt/scapegoat, service scapegoat)"
  if [[ -d "$ROOT/opt/scapegoat/scapegoat" ]] &&
     diff -rq -x __pycache__ "$REPO/scapegoat" "$ROOT/opt/scapegoat/scapegoat" >/dev/null 2>&1 &&
     same_file "$REPO/deploy/scapegoat.service" "$UNIT_DIR/scapegoat.service" &&
     [[ -x "$BIN_DIR/scapegoat" ]]; then
    ok "installed and current"
  else
    act "run $SCAPEGOAT_INSTALL" "$SCAPEGOAT_INSTALL"
  fi
}

scapegoat_verify() { expect_active scapegoat.service; }

scapegoat_uninstall() {
  phase "scapegoat"
  local m
  if [[ -f "$HOOK_DIR/scapegoat" ]]; then act "remove $HOOK_DIR/scapegoat" rm -f "$HOOK_DIR/scapegoat"; fi
  for m in $MODES; do
    if [[ -f "$ROOT/etc/scapegoat/modes/$m.toml" ]]; then act "remove $ROOT/etc/scapegoat/modes/$m.toml" rm -f "$ROOT/etc/scapegoat/modes/$m.toml"; fi
  done
  if [[ -d "$ROOT/opt/scapegoat" ]]; then act "run $SCAPEGOAT_INSTALL --uninstall" "$SCAPEGOAT_INSTALL" --uninstall; fi
}
