# shellcheck shell=bash disable=SC2034,SC2154  # globals come from install-field-node.sh
# Component "kids": Billie kids on this node, any number (for example xf-ingest).
#   KIDS="<name> ..."   and per kid, with KEY = the name in capitals, "-" as "_":
#   KID_<KEY>_VERSION, KID_<KEY>_BUNDLE, KID_<KEY>_SHA256   the bundle (sha256 checked first)
#   KID_<KEY>_TRANSPORT (udp|tcp, default udp), KID_<KEY>_BIND, KID_<KEY>_PORT
#   KID_<KEY>_SOURCE_CIDR (default <BIND>/32)    who may send to the listener
#   KID_<KEY>_CAT062="<source>:<sac>:<sic> ..."  CAT062 identities (optional)
# Older site files with one kid (KID_NAME, KID_BUNDLE, ..., CAT062_SOURCE/SAC/SIC) still work.
# Each step (install, configure, cat062 source set, activate) runs only when needed.
# Sourced by install-field-node.sh.

kids_phases=1
if [[ -z "${KIDS:-}" && -n "${KID_BUNDLE:-}" && -n "${KID_NAME:-}" ]]; then   # one-kid site file
  KIDS=$KID_NAME
  _k=$(var_key "$KID_NAME")
  for _f in VERSION BUNDLE BIND PORT; do _v="KID_$_f"; printf -v "KID_${_k}_$_f" '%s' "${!_v:-}"; done
  printf -v "KID_${_k}_SHA256" '%s' "${KID_BUNDLE_SHA256:-}"
  [[ -n "${CAT062_SOURCE:-}" ]] && printf -v "KID_${_k}_CAT062" '%s' "$CAT062_SOURCE:${CAT062_SAC:-}:${CAT062_SIC:-}"
  export "KID_${_k}_VERSION" "KID_${_k}_BUNDLE" "KID_${_k}_BIND" "KID_${_k}_PORT" "KID_${_k}_SHA256" "KID_${_k}_CAT062" KIDS
  unset _k _f _v
fi
kid_var() { local v; v="KID_$(var_key "$1")_$2"; echo "${!v:-$3}"; }

kids_preflight() {
  [[ -n "${KIDS:-}" ]] || return 0
  command -v billie >/dev/null || die "billie is not installed (KIDS is set)"
  python3 - <<'PY' || die "fix the kid values above"
import ipaddress, os, re, sys
e, bad = os.environ, []
for name in e.get("KIDS", "").split():
    key = "KID_" + name.upper().replace("-", "_") + "_"
    g = lambda f, d="": e.get(key + f, d).strip()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name): bad.append(f"kid name {name!r}: lowercase letters, digits, -")
    if not re.fullmatch(r"[A-Za-z0-9.+_-]+", g("VERSION")): bad.append(f"{key}VERSION is not a version")
    if not g("BUNDLE"): bad.append(f"{key}BUNDLE is empty")
    if not re.fullmatch(r"[0-9a-f]{64}", g("SHA256")): bad.append(f"{key}SHA256 must be the 64-hex sha256 of the bundle")
    if g("TRANSPORT", "udp") not in ("udp", "tcp"): bad.append(f"{key}TRANSPORT must be udp or tcp")
    try: ipaddress.IPv4Address(g("BIND"))
    except ValueError: bad.append(f"{key}BIND must be an IPv4 address of this node")
    if not (g("PORT").isdigit() and 1 <= int(g("PORT")) <= 65535): bad.append(f"{key}PORT must be 1-65535")
    try:
        if g("SOURCE_CIDR"): ipaddress.ip_network(g("SOURCE_CIDR"), strict=False)
    except ValueError: bad.append(f"{key}SOURCE_CIDR is not a network")
    for item in g("CAT062").split():
        p = item.split(":")
        if len(p) != 3 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", p[0]) or not all(
                x.isdigit() and 0 <= int(x) <= 255 for x in p[1:]):
            bad.append(f"{key}CAT062 entry {item!r} must be <source>:<sac 0-255>:<sic 0-255>")
for b in bad: print("    -", b)
sys.exit(1 if bad else 0)
PY
}

kids_listener_ok() {  # <name> <transport> <bind> <port>
  python3 - "$ROOT/etc/billie/kids/$1/listener.json" "$2" "$3" "$4" <<'PY'
import json, sys
try:
    c = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    sys.exit(1)
sys.exit(0 if (c.get("transport"), c.get("hostAddress"), str(c.get("hostPort"))) == tuple(sys.argv[2:5]) else 1)
PY
}
kids_cat062_ok() {  # <kid> <source> <sac> <sic>
  python3 - "$ROOT/etc/billie/translator/cat062-sources.json" "$@" <<'PY'
import json, sys
f, kid, src, sac, sic = sys.argv[1:]
try:
    s = json.load(open(f))["kids"][kid]["sources"][src]
except (OSError, ValueError, KeyError, TypeError):
    sys.exit(1)
sys.exit(0 if (str(s.get("sac")), str(s.get("sic"))) == (sac, sic) else 1)
PY
}

kids_apply() {
  phase "Billie kids (${KIDS:-none})"
  [[ -n "${KIDS:-}" ]] || { note "no kids in the site file"; return 0; }
  local k ver bundle sha tr bind port src unit need item s sac sic
  for k in $KIDS; do
    ver=$(kid_var "$k" VERSION); bundle=$(kid_var "$k" BUNDLE); sha=$(kid_var "$k" SHA256)
    tr=$(kid_var "$k" TRANSPORT udp); bind=$(kid_var "$k" BIND); port=$(kid_var "$k" PORT)
    src=$(kid_var "$k" SOURCE_CIDR "$bind/32"); unit="billie-kid-$k.service"
    if [[ -d "$ROOT/opt/billie/kids/$k/$ver" ]]; then
      ok "$k@$ver installed"
    else
      [[ -f "$bundle" ]] || die "kid bundle not found: $bundle"
      [[ "$(sha256_of "$bundle")" == "$sha" ]] || die "sha256 of $bundle does not match KID_$(var_key "$k")_SHA256"
      act "billie kid install $bundle" billie kid install "$bundle"
    fi
    need=0
    if kids_listener_ok "$k" "$tr" "$bind" "$port"; then
      ok "$k listener $tr $bind:$port"
    else
      if systemctl is-active --quiet "$unit"; then
        act "billie kid deactivate $k (to change its listener)" billie kid deactivate "$k"
      fi
      act "billie kid configure $k --transport $tr --bind-address $bind --port $port --source-cidr $src" \
        billie kid configure "$k" --transport "$tr" --bind-address "$bind" --port "$port" --source-cidr "$src"
      need=1
    fi
    for item in $(kid_var "$k" CAT062); do
      IFS=: read -r s sac sic <<<"$item"
      if kids_cat062_ok "$k" "$s" "$sac" "$sic"; then
        ok "CAT062 source $k/$s SAC $sac SIC $sic"
      else
        act "billie cat062 source set $k $s --sac $sac --sic $sic" billie cat062 source set "$k" "$s" --sac "$sac" --sic "$sic"
      fi
    done
    if [[ $need -eq 0 ]] && systemctl is-active --quiet "$unit"; then
      ok "$unit active"
    else
      act "billie kid activate $k" billie kid activate "$k"
    fi
  done
}

kids_verify() { local k; for k in ${KIDS:-}; do expect_active "billie-kid-$k.service"; done; }

kids_uninstall() {
  phase "Billie kids"
  local k
  for k in ${KIDS:-}; do
    if command -v billie >/dev/null && systemctl is-active --quiet "billie-kid-$k.service"; then
      act "billie kid deactivate $k" billie kid deactivate "$k"
    fi
    note "package $k kept; remove it with: sudo billie kid remove $k"
  done
}
