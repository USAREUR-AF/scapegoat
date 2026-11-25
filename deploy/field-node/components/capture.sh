# shellcheck shell=bash disable=SC2034,SC2154  # globals come from install-field-node.sh
# Component "capture": packet capture of the sensor link. Default CAPTURE=first-bite.
#   CAPTURE=first-bite  first-bite's tap (`mind --tap-only`): one instance per entry of
#                       CAPTURE_TAPS ("name=/path/settings.env ...") or, if that is empty, of
#                       the pack's TAP_ENVS ("name=file") read from FIRST_BITE_TAP_ENV_DIR.
#                       TAP_INTERFACE is set from SENSOR_IFACE and {host} becomes NODE_NAME.
#                       The pack's own capture units are removed. A changed settings file
#                       restarts its running tap (install.sh alone does not). Files land in
#                       /var/lib/first-bite-tap/<name>/; uninstall keeps them.
#   CAPTURE=units       the pack's units/ and bin/ files (packs that still carry them)
#   CAPTURE=off         nothing
# Sourced by install-field-node.sh.

capture_phases=1
CAPTURE=${CAPTURE:-first-bite}
FIRST_BITE_MIND=${FIRST_BITE_MIND:-/usr/local/bin/mind}
read -ra CAP_UNITS <<<"${CAPTURE_UNITS:-}"
read -ra CAP_SCRIPTS <<<"${CAPTURE_SCRIPTS:-}"
capture_units_wanted=()

capture_taps() {  # one "name=path" per line
  local t
  if [[ -n "${CAPTURE_TAPS:-}" ]]; then
    for t in $CAPTURE_TAPS; do echo "$t"; done
  else
    for t in ${TAP_ENVS:-}; do echo "${t%%=*}=${FIRST_BITE_TAP_ENV_DIR:-}/${t#*=}"; done
  fi
}

capture_preflight() {
  case "$CAPTURE" in
    units)
      if [[ ${#CAP_UNITS[@]} -gt 0 && -n "${SENSOR_IFACE_GLOB:-}" ]]; then
        die "CAPTURE=units reads SENSOR_IFACE from the site file, so it cannot be a glob ($SENSOR_IFACE_GLOB); use CAPTURE=first-bite"
      fi
      if [[ ${#CAP_UNITS[@]} -gt 0 ]]; then
        local t
        for t in tcpdump curl; do command -v "$t" >/dev/null || die "$t is not installed (CAPTURE=units)"; done
      fi ;;
    first-bite)
      if [[ -n "$(capture_taps)" ]]; then
        [[ -x "${FIRST_BITE_TAP_INSTALL:-}" ]] || die "FIRST_BITE_TAP_INSTALL must be first-bite's deployment/tap/install.sh (CAPTURE=first-bite)"
        [[ -x "$ROOT$FIRST_BITE_MIND" ]] || die "first-bite's mind is not installed at $FIRST_BITE_MIND (install it from a first-bite release, then re-run)"
        local line
        while IFS= read -r line; do
          [[ -f "${line#*=}" ]] || die "first-bite tap settings not found: ${line#*=}"
        done < <(capture_taps)
      fi ;;
    off) ;;
    *) die "CAPTURE must be first-bite, units or off" ;;
  esac
}

capture_tap_render() {
  sed -e "s|^TAP_INTERFACE=.*|TAP_INTERFACE=${SENSOR_IFACE}|" -e "s|{host}|${NODE_NAME}|g" "$1"
}
capture_tap_install() { "$FIRST_BITE_TAP_INSTALL" "$1" --env "$2"; }
capture_tap_uninstall() { "$FIRST_BITE_TAP_INSTALL" "$1" --uninstall; }

capture_remove_pack_units() {
  local u f
  for u in "${CAP_UNITS[@]+"${CAP_UNITS[@]}"}"; do
    if [[ -f "$UNIT_DIR/$u" ]]; then act "stop and remove $u${1:+ ($1)}" remove_unit "$u"; fi
  done
  for f in "${CAP_SCRIPTS[@]+"${CAP_SCRIPTS[@]}"}"; do
    if [[ -f "$LIBEXEC_DIR/$f" ]]; then act "remove $LIBEXEC_DIR/$f" rm -f "$LIBEXEC_DIR/$f"; fi
  done
}

capture_apply() {
  phase "Capture ($CAPTURE)"
  local before=$DRIFT u f changed=0 line name src tmp
  DRIFT=0
  case "$CAPTURE" in
    units)
      for u in "${CAP_UNITS[@]+"${CAP_UNITS[@]}"}"; do
        capture_units_wanted+=("$u")
        install_file "$PACK/units/$u" "$UNIT_DIR/$u" 644 && changed=1
      done
      for f in "${CAP_SCRIPTS[@]+"${CAP_SCRIPTS[@]}"}"; do
        install_file "$PACK/bin/$f" "$LIBEXEC_DIR/$f" 755 && changed=1
      done
      if [[ $changed -eq 1 ]]; then act "systemctl daemon-reload" systemctl daemon-reload; fi
      for u in "${capture_units_wanted[@]+"${capture_units_wanted[@]}"}"; do
        # shellcheck disable=SC2086
        in_list "$u" ${CAPTURE_TIMER_STARTED:-} && continue
        if ! systemctl is-enabled --quiet "$u" 2>/dev/null || ! systemctl is-active --quiet "$u" 2>/dev/null; then
          act "enable and start $u" systemctl enable --now "$u"
        elif [[ $changed -eq 1 || $SITE_CHANGED -eq 1 ]]; then
          act "restart $u (unit or site file changed)" systemctl restart "$u"
        fi
      done ;;
    first-bite)
      while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        name=${line%%=*}; src=${line#*=}
        tmp=$(mktemp); capture_tap_render "$src" > "$tmp"
        local was_active=0 unchanged=0
        systemctl is-active --quiet "first-bite-tap@$name.service" && was_active=1
        same_file "$tmp" "$TAP_ETC/tap-$name.env" && unchanged=1
        if [[ $unchanged -eq 1 && $was_active -eq 1 ]]; then
          ok "first-bite tap $name current and running"
        else
          act "write $ETC/tap-$name.env" put_file "$tmp" "$ETC/tap-$name.env" 644
          act "first-bite tap install $name --env $ETC/tap-$name.env" capture_tap_install "$name" "$ETC/tap-$name.env"
          if [[ $was_active -eq 1 && $unchanged -eq 0 ]]; then
            # install.sh runs `enable --now`, which does not restart a running unit
            act "restart first-bite-tap@$name (settings changed)" systemctl restart "first-bite-tap@$name.service"
          fi
        fi
        rm -f "$tmp"
      done < <(capture_taps)
      capture_remove_pack_units "replaced by the first-bite tap" ;;
    off) note "capture is off in the site file" ;;
  esac
  [[ $DRIFT -eq 1 ]] || ok "capture current"
  [[ $before -eq 0 ]] || DRIFT=1
}

capture_verify() {
  local u line
  for u in "${capture_units_wanted[@]+"${capture_units_wanted[@]}"}"; do
    # shellcheck disable=SC2086
    in_list "$u" ${CAPTURE_TIMER_STARTED:-} || expect_active "$u"
  done
  if [[ $CAPTURE == first-bite ]]; then
    while IFS= read -r line; do [[ -n "$line" ]] && expect_active "first-bite-tap@${line%%=*}.service"; done < <(capture_taps)
  fi
}

capture_uninstall() {
  phase "Capture"
  local line name
  capture_remove_pack_units
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    name=${line%%=*}
    if [[ -f "$TAP_ETC/tap-$name.env" && -x "${FIRST_BITE_TAP_INSTALL:-}" ]]; then
      act "first-bite tap $name --uninstall" capture_tap_uninstall "$name"
    fi
  done < <(capture_taps)
  if [[ $CHECK -eq 0 ]]; then systemctl daemon-reload; fi
  ok "capture removed (capture files are kept)"
}
