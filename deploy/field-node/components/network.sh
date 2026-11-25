# shellcheck shell=bash disable=SC2034,SC2154  # globals come from install-field-node.sh
# Component "network": the sensor interface's static addresses, per mode, kept by a netplan
# file. Modes come from the pack (FIELD_PACK; the built-in "plain" pack has one mode,
# "static", holding SENSOR_CIDRS). The mode tool field-node-mode applies a mode and runs the
# mode hooks other components install (scapegoat renders its config there).
# Sourced by install-field-node.sh.

network_phases=2
NETPLAN="$ROOT/etc/netplan/55-${SENSOR_IFACE}-${NETPLAN_SUFFIX:-sensor}.yaml"

network_mode_cidrs() {
  local v out=""
  LOCAL_CIDRS_VARS=""
  # shellcheck disable=SC1090
  . "$PACK/modes/$1.mode"
  for v in $LOCAL_CIDRS_VARS; do out+="${out:+ }${!v}"; done
  echo "$out"
}
# shellcheck disable=SC1090
network_managed() { MANAGED=true; . "$PACK/modes/$1.mode"; [[ $MANAGED != false ]]; }   # MANAGED=false: addresses come from DHCP
# shellcheck disable=SC1090
network_applied() {   # addresses as they sit on the interface (PREFIX_ROUTE=false -> /32)
  local c
  PREFIX_ROUTE=true; . "$PACK/modes/$1.mode"
  local pr=$PREFIX_ROUTE
  for c in $(network_mode_cidrs "$1"); do
    if [[ $pr == false ]]; then echo "${c%/*}/32"; else echo "$c"; fi
  done
}
# shellcheck disable=SC1090
network_host_routes() { HOST_ROUTES_VAR=""; . "$PACK/modes/$1.mode"; [[ -n "$HOST_ROUTES_VAR" ]] && echo "${!HOST_ROUTES_VAR:-}"; true; }
network_all_cidrs() {   # addresses the installer manages (never those of a DHCP mode)
  local m
  for m in $MODES; do network_managed "$m" && network_applied "$m"; done | sed '/^$/d' | sort -u
}
network_tools() { echo "field-node-mode${MODE_TOOL_ALIAS:+ $MODE_TOOL_ALIAS}"; }

network_preflight() {
  python3 - "$PACK" <<'PY' || die "fix the network values above"
import ipaddress, os, sys
e, bad, pack = os.environ, [], sys.argv[1]
def mode_file(m):
    out = {}
    for line in open(os.path.join(pack, "modes", m + ".mode")):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            out[k] = v.strip().strip('"')
    return out
def cidrs(var):
    out = []
    for v in e.get(var, "").split():
        try:
            if "/" not in v: raise ValueError
            out.append(ipaddress.ip_interface(v))
        except ValueError:
            bad.append(f"{var}: {v!r} must be address/prefix, e.g. 192.0.2.10/24")
    if not e.get(var, "").strip(): bad.append(f"{var} is empty")
    return out
def peer(k, nets, v):
    host, _, port = v.rpartition(":")
    try:
        ip = ipaddress.ip_address(host)
        if not 1 <= int(port) <= 65535: raise ValueError
    except ValueError:
        bad.append(f"{k}={v!r} must be ip:port, e.g. 192.0.2.81:47000"); return
    if nets and not any(ip in n.network for n in nets):
        bad.append(f"{k}={v} is not in {' or '.join(str(n.network) for n in nets)}; "
                   "the sensor must be on one of this node's subnets for the mode")
modes = e.get("MODES", "").split()
if e.get("FIELD_MODE") and e["FIELD_MODE"] not in modes:
    bad.append(f"FIELD_MODE must be one of the pack's modes: {' '.join(modes)}")
for m in modes:
    try:
        mf = mode_file(m)
    except OSError:
        bad.append(f"the pack has no modes/{m}.mode"); continue
    nets = [n for v in mf.get("LOCAL_CIDRS_VARS", "").split() for n in cidrs(v)]
    if mf.get("PEER_VAR"):
        if not e.get(mf["PEER_VAR"], "").strip(): bad.append(f"{mf['PEER_VAR']} is empty")
        else: peer(mf["PEER_VAR"], nets, e[mf["PEER_VAR"]])
    for c in e.get(mf.get("CANDIDATES_VAR", ""), "").split():
        peer(f"{mf.get('CANDIDATES_VAR')} entry", nets, c)
    hv = mf.get("HOST_ROUTES_VAR", "")
    if mf.get("PREFIX_ROUTE") == "false" and hv and m == (e.get("FIELD_MODE") or modes[0]):
        hosts = e.get(hv, "").split()
        if not hosts: bad.append(f"{hv} is empty: mode {m} has no subnet route, so it needs host routes")
        own = {str(n.ip) for n in nets}
        for h in hosts:
            try:
                ip = ipaddress.ip_address(h)
            except ValueError:
                bad.append(f"{hv}: {h!r} is not an IPv4 address"); continue
            if nets and not any(ip in n.network for n in nets):
                bad.append(f"{hv}: {h} is not on {' or '.join(str(n.network) for n in nets)}")
            if h in own: bad.append(f"{hv}: {h} is this node's own address")
for b in bad: print("    -", b)
sys.exit(1 if bad else 0)
PY
  ip link show dev "$SENSOR_IFACE" >/dev/null 2>&1 || die "no interface $SENSOR_IFACE on this node"
  if [[ -f "$ROOT/etc/netplan/99-billie-sensor-${SENSOR_IFACE}.yaml" ]]; then
    network_managed "${FIELD_MODE:-${MODES%% *}}" || return 0   # a DHCP mode writes nothing
    die "Billie already manages ${SENSOR_IFACE} (99-billie-sensor-${SENSOR_IFACE}.yaml). One owner per interface: clear it with: sudo billie network clear --interface ${SENSOR_IFACE}"
  fi
}

network_apply() {
  phase "Mode commands ($(network_tools))"
  local t changed=0
  for t in $(network_tools); do install_file "$HERE/bin/field-node-mode" "$BIN_DIR/$t" 755 && changed=1; done
  [[ $changed -eq 1 ]] || ok "current"

  phase "Sensor mode $MODE (netplan, addresses on $SENSOR_IFACE, mode hooks)"
  local modecmd=(env FIELD_ROOT="$ROOT" FIELD_PROGRAM="$REPO" FIELD_HOOK_DIR="$HOOK_DIR" "$HERE/bin/field-node-mode")
  if [[ $CHECK -eq 1 ]]; then
    # the hooks the components would install, so --check sees their drift too
    local hooks h
    hooks=$(mktemp -d)
    for h in "${FIELD_HOOKS[@]+"${FIELD_HOOKS[@]}"}"; do cp "$h" "$hooks/"; done
    modecmd=(env FIELD_ROOT="$ROOT" FIELD_PROGRAM="$REPO" FIELD_HOOK_DIR="$hooks" "$HERE/bin/field-node-mode")
    FIELD_ENV="$SITE" FIELD_PACK_DIR="$PACK" "${modecmd[@]}" "$MODE" --check | sed 's/^/    /' || {
      local rc=$?
      rm -rf "$hooks"
      if [[ $rc -eq 3 ]]; then DRIFT=1; else die "field-node-mode --check failed"; fi
    }
    rm -rf "$hooks"
  else
    FIELD_ENV="$SITE_DST" FIELD_PACK_DIR="$PACK_DST" "${modecmd[@]}" "$MODE" | sed 's/^/    /' || die "field-node-mode $MODE failed"
  fi
}

network_verify() {
  local have c how="static"
  network_managed "$MODE" || how="from DHCP"
  have=$(ip -4 -o addr show dev "$SENSOR_IFACE" 2>/dev/null | awk '{print $4}' || true)
  for c in $(network_applied "$MODE"); do
    if grep -qxF "$c" <<<"$have"; then ok "$c on $SENSOR_IFACE ($how)"; else echo "    MISSING: $c on $SENSOR_IFACE ($how)" >&2; FAILED=1; fi
  done
  local h
  for h in $(network_host_routes "$MODE"); do
    if ip -4 route show "$h/32" dev "$SENSOR_IFACE" 2>/dev/null | grep -q .; then ok "route $h/32 on $SENSOR_IFACE"
    else echo "    MISSING: route $h/32 on $SENSOR_IFACE" >&2; FAILED=1; fi
  done
}

network_uninstall() {
  phase "Addresses on ${SENSOR_IFACE}"
  local have c t m
  if [[ -f "$NETPLAN" ]]; then act "remove $NETPLAN" rm -f "$NETPLAN"; fi
  local cur
  cur=$( [[ -f "$MODE_FILE" ]] && tr -d '[:space:]' < "$MODE_FILE" || true)
  cur=${cur:-${FIELD_MODE:-${MODES%% *}}}
  local m h
  for m in $MODES; do
    for h in $(network_host_routes "$m"); do
      if ip -4 route show "$h/32" dev "$SENSOR_IFACE" 2>/dev/null | grep -q .; then
        act "remove route $h/32 from $SENSOR_IFACE" ip route del "$h/32" dev "$SENSOR_IFACE"
      fi
    done
  done
  if network_managed "$cur"; then
    have=$(ip -4 -o addr show dev "$SENSOR_IFACE" 2>/dev/null | awk '{print $4}' || true)
    for c in $(network_all_cidrs); do
      if grep -qxF "$c" <<<"$have"; then act "remove $c from $SENSOR_IFACE" ip addr del "$c" dev "$SENSOR_IFACE"; fi
    done
  else
    note "mode $cur takes its address from DHCP: addresses left as they are"
  fi
  for t in $(network_tools); do
    if [[ -f "$BIN_DIR/$t" ]]; then act "remove $BIN_DIR/$t" rm -f "$BIN_DIR/$t"; fi
  done
  if [[ -f "$MODE_FILE" ]]; then act "remove $MODE_FILE" rm -f "$MODE_FILE"; fi
}
