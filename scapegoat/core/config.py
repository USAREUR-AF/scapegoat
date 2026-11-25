"""Load the scapegoat config file.

TOML is read with tomllib (Python 3.11+). On Python 3.10 a JSON file with the
same structure is accepted instead.

The Config object works both ways: as attributes (config.sessions["sensor"].peer)
and as a mapping over the parsed file with defaults filled in
(config["sessions"]["sensor"]["peer"]), so other modules can treat it as a dict.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import ext, plugins

try:
    import tomllib  # type: ignore[import-not-found]
except ImportError:  # Python 3.10
    tomllib = None


DEFAULT_PROFILES_DIR = "/etc/scapegoat/profiles"
# Profiles shipped inside the package (scapegoat/profiles/), so they install with it.
SHIPPED_PROFILES_DIR = str(Path(__file__).resolve().parent.parent / "profiles")
PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class ConfigError(Exception):
    """The config file is missing or wrong. The message says what to fix."""


def parse_addr(text: str, what: str) -> tuple[str, int]:
    """'192.168.1.5:47000' -> ('192.168.1.5', 47000)."""
    if not isinstance(text, str) or ":" not in text:
        raise ConfigError(f"{what}: expected 'IP:PORT', got {text!r}")
    host, _, port = text.rpartition(":")
    host = host.strip("[]")
    try:
        p = int(port)
    except ValueError:
        raise ConfigError(f"{what}: port must be a number, got {port!r}") from None
    if not 0 <= p <= 65535:
        raise ConfigError(f"{what}: port {p} out of range")
    return host, p


@dataclass
class SessionConfig:
    id: str
    protocol: str
    enabled: bool = True
    local: str = ""   # "" = 0.0.0.0 on the protocol's default port
    peer: str = ""
    peer_candidates: list = field(default_factory=list)
    forward: list = field(default_factory=list)
    allow_radiate_control: bool = False
    protocol_settings: dict = field(default_factory=dict)
    # Copied from [features] radiate_control. False hides radiate on/off everywhere.
    radiate_feature: bool = False
    # A plugin's address check may honour this (a peer on a private internal network).
    direct_internal_network: bool = False
    # "message": forward each message separately (a datagram may carry several);
    # "datagram": forward each datagram unchanged.
    forward_mode: str = "message"

    @property
    def local_addr(self) -> tuple[str, int]:
        if not self.local:
            return ("0.0.0.0", 0)
        return parse_addr(self.local, f"sessions.{self.id}.local")

    @property
    def candidate_addrs(self) -> list:
        """`peer` first (if set), then `peer_candidates`, duplicates dropped."""
        out = []
        for text in ([self.peer] if self.peer else []) + list(self.peer_candidates):
            a = parse_addr(text, f"sessions.{self.id}.peer")
            if a not in out:
                out.append(a)
        return out

    @property
    def peer_addr(self) -> tuple[str, int]:
        return self.candidate_addrs[0]

    @property
    def forward_addrs(self) -> list:
        return [parse_addr(f, f"sessions.{self.id}.forward") for f in self.forward]


@dataclass
class Config:
    bind: str = "127.0.0.1:8730"
    allow_net_control: bool = False
    node_name: str = "scapegoat"
    island_rest: str = ""
    expected_local_address: str = ""
    topology: str = ""   # "routed" | "same-lan" | "" (inferred by scapegoat net)
    node_role: str = ""  # free text shown first on every page, e.g. "C2 node · Pi A"
    features: dict = field(default_factory=dict)
    # C2 outputs: name -> {format, enabled, to, sessions, multicast_ttl, context, uid_prefix,
    # stale_s}; see scapegoat/core/outputs.py. transformers_path: goat-transformers tree.
    outputs: dict = field(default_factory=dict)
    transformers_path: str = ""
    profile: str = ""
    sessions: dict = field(default_factory=dict)
    path: str = ""
    raw: dict = field(default_factory=dict)

    @property
    def bind_addr(self) -> tuple[str, int]:
        return parse_addr(self.bind, "bind")

    # Mapping access over the parsed file (with defaults), for modules that
    # prefer a plain dict.
    def __getitem__(self, key):
        return self.raw[key]

    def get(self, key, default=None):
        return self.raw.get(key, default)

    def __contains__(self, key):
        return key in self.raw

    def keys(self):
        return self.raw.keys()


def _bool(value, what):
    if isinstance(value, bool):
        return value
    raise ConfigError(f"{what}: expected true or false, got {value!r}")


OUTPUT_FORMATS = ("asterix-cat062", "cot-xml", "sapient")


def _outputs(raw: dict, island_rest: str) -> dict:
    """[outputs.<name>] tables -> checked output specs."""
    from .outputs import parse_destination
    if not isinstance(raw, dict):
        raise ConfigError("[outputs] must be tables, e.g. [outputs.cat062]")
    out = {}
    for name, o in raw.items():
        where = f"outputs.{name}"
        if not isinstance(o, dict):
            raise ConfigError(f"[{where}] must be a table")
        fmt = str(o.get("format", ""))
        if fmt not in OUTPUT_FORMATS:
            raise ConfigError(f"{where}.format must be one of {', '.join(OUTPUT_FORMATS)}")
        to = o.get("to", [])
        if not isinstance(to, list) or not to:
            raise ConfigError(f"{where}.to: list the destinations, e.g. "
                              '["udp://239.255.62.1:8600", "zenoh:site/sensor/cat062"]')
        try:
            dests = [parse_destination(d) for d in to]
        except ValueError as exc:
            raise ConfigError(f"{where}: {exc}") from None
        enabled = _bool(o.get("enabled", True), f"{where}.enabled")
        if enabled and any(d["kind"] == "zenoh" for d in dests) and not island_rest:
            raise ConfigError(f"{where}: a zenoh: destination needs island_rest (the Zenoh REST "
                              "address, e.g. http://127.0.0.1:8000)")
        sessions = o.get("sessions", [])
        if not isinstance(sessions, list):
            raise ConfigError(f"{where}.sessions must be a list of session names")
        context = {}
        if fmt == "asterix-cat062":
            for k in ("sac", "sic"):
                v = o.get(k)
                if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= 255:
                    raise ConfigError(f"{where}.{k} is required for CAT062: 0-255 (System Area "
                                      "Code / System Identification Code of this source)")
                context[f"cat062.{k}"] = v
        elif fmt == "cot-xml":
            context["how"] = str(o.get("how", "m-g"))
        elif fmt == "sapient":
            if not o.get("node_id"):
                raise ConfigError(f"{where}.node_id is required for SAPIENT (a UUID)")
            context["sapient.node_id"] = str(o["node_id"])
        stale = o.get("stale_s", 30)
        if not isinstance(stale, (int, float)) or stale <= 0:
            raise ConfigError(f"{where}.stale_s must be a positive number of seconds")
        out[str(name)] = {"format": fmt, "enabled": enabled, "to": [d["text"] for d in dests],
                          "sessions": [str(s) for s in sessions],
                          "multicast_ttl": int(o.get("multicast_ttl", 1)), "context": context,
                          "uid_prefix": o.get("uid_prefix"), "stale_s": float(stale)}
    return out


def from_dict(data: dict, path: str = "") -> Config:
    if not isinstance(data, dict):
        raise ConfigError("config must be a table of settings")
    cfg = Config(
        bind=str(data.get("bind", "127.0.0.1:8730")),
        allow_net_control=_bool(data.get("allow_net_control", False), "allow_net_control"),
        node_name=str(data.get("node_name", "scapegoat")),
        island_rest=str(data.get("island_rest", "") or ""),
        expected_local_address=str(data.get("expected_local_address", "") or ""),
        profile=str(data.get("profile", "") or ""),
        path=path,
    )
    cfg.bind_addr  # validate
    topo = str(data.get("topology", "") or "")
    if topo not in ("", "routed", "same-lan"):
        raise ConfigError(f'topology must be "routed" or "same-lan" (or left out), got {topo!r}')
    cfg.topology = topo
    cfg.node_role = str(data.get("node_role", "") or "").strip()
    cfg.transformers_path = str((data.get("transformers") or {}).get("path", "") or "")
    cfg.outputs = _outputs(data.get("outputs") or {}, cfg.island_rest)
    feats = data.get("features", {}) or {}
    if not isinstance(feats, dict):
        raise ConfigError("[features] must be a table, e.g. [features] radiate_control = false")
    cfg.features = {"radiate_control": _bool(feats.get("radiate_control", False),
                                             "features.radiate_control")}
    ppath = data.get("plugin_path", []) or []
    if isinstance(ppath, str):
        ppath = [ppath]
    if not isinstance(ppath, list):
        raise ConfigError('plugin_path must be a list of directories, e.g. ["/opt/scapegoat/plugins"]')
    plugins.set_extra_dirs(ppath)
    sessions = data.get("sessions", {}) or {}
    if not isinstance(sessions, dict):
        raise ConfigError("[sessions] must be a table, e.g. [sessions.sensor]")
    raw_sessions = {}
    for sid, s in sessions.items():
        if not isinstance(s, dict):
            raise ConfigError(f"[sessions.{sid}] must be a table")
        if not s.get("protocol"):
            raise ConfigError(f"sessions.{sid}.protocol is required (for example \"toy\")")
        cands = s.get("peer_candidates", []) or []
        if not isinstance(cands, list):
            raise ConfigError(f"sessions.{sid}.peer_candidates must be a list like "
                              "[\"192.0.2.81:47000\", \"192.0.2.74:47000\"]")
        if not s.get("peer") and not cands:
            raise ConfigError(f"sessions.{sid}.peer is required: the sensor's IP:PORT "
                              "(or give peer_candidates)")
        fwd = s.get("forward", []) or []
        if not isinstance(fwd, list):
            raise ConfigError(f"sessions.{sid}.forward must be a list like [\"127.0.0.1:40531\"]")
        ps = s.get("protocol_settings", {}) or {}
        if not isinstance(ps, dict):
            raise ConfigError(f"[sessions.{sid}.protocol_settings] must be a table")
        sc = SessionConfig(
            id=str(sid),
            protocol=str(s["protocol"]),
            enabled=_bool(s.get("enabled", True), f"sessions.{sid}.enabled"),
            local=str(s.get("local", "") or ""),
            peer=str(s.get("peer") or ""),
            peer_candidates=[str(c) for c in cands],
            forward=[str(f) for f in fwd],
            allow_radiate_control=_bool(s.get("allow_radiate_control", False),
                                        f"sessions.{sid}.allow_radiate_control"),
            protocol_settings=dict(ps),
            radiate_feature=cfg.features["radiate_control"],
            direct_internal_network=_bool(s.get("direct_internal_network", False),
                                          f"sessions.{sid}.direct_internal_network"),
            forward_mode=str(s.get("forward_mode", "message")),
        )
        if sc.forward_mode not in ("message", "datagram"):
            raise ConfigError(f'sessions.{sid}.forward_mode must be "message" or "datagram"')
        sc.local_addr, sc.candidate_addrs, sc.forward_addrs  # validate
        try:
            plugins.validate_session(sc.protocol, sc)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        cfg.sessions[sc.id] = sc
        raw_sessions[sc.id] = {
            "id": sc.id, "protocol": sc.protocol, "enabled": sc.enabled,
            "local": sc.local, "peer": sc.peer,
            "peer_candidates": list(sc.peer_candidates), "forward": list(sc.forward),
            "allow_radiate_control": sc.allow_radiate_control,
            "protocol_settings": dict(sc.protocol_settings),
        }
    cfg.raw = dict(data)
    cfg.raw.update({
        "bind": cfg.bind, "allow_net_control": cfg.allow_net_control,
        "node_name": cfg.node_name, "island_rest": cfg.island_rest,
        "expected_local_address": cfg.expected_local_address, "profile": cfg.profile,
        "features": dict(cfg.features), "topology": cfg.topology, "node_role": cfg.node_role,
        "outputs": dict(cfg.outputs),
        "sessions": raw_sessions,
    })
    return cfg


def _read(path: str) -> dict:
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {path}")
    text = p.read_bytes()
    if text.lstrip().startswith(b"{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{path}: bad JSON: {exc}") from None
    elif tomllib is not None:
        try:
            data = tomllib.loads(text.decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"{path}: bad TOML: {exc}") from None
    else:
        raise ConfigError(
            f"{path}: this Python ({__import__('sys').version.split()[0]}) cannot read TOML. "
            "Use Python 3.11 or newer, or write the same settings as a JSON file.")
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: must be a table of settings")
    return data


def deep_merge(base: dict, over: dict) -> dict:
    """Tables merge key by key; any other value in `over` (lists too) replaces `base`."""
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out




def profile_dirs(profiles_dir: str | None = None) -> list:
    """Site profiles dir, legacy dir, the profiles shipped with the core, then the
    profiles shipped by installed protocol plugins."""
    dirs = [profiles_dir or DEFAULT_PROFILES_DIR] + ext.profile_dirs() + [SHIPPED_PROFILES_DIR]
    dirs += plugins.profile_dirs()
    return list(dict.fromkeys(dirs))


def _description(path: Path) -> str:
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("#"):
                return s.lstrip("#").strip()
            if s:
                break
    except OSError:
        pass
    return ""


def list_profiles(profiles_dir: str | None = None) -> list:
    """Profiles found, first directory wins on a name clash."""
    seen = {}
    for d in profile_dirs(profiles_dir):
        dp = Path(d)
        if not dp.is_dir():
            continue
        for f in sorted(dp.iterdir()):
            if f.suffix in (".toml", ".json") and f.stem not in seen:
                seen[f.stem] = {"name": f.stem, "description": _description(f), "path": str(f)}
    return sorted(seen.values(), key=lambda x: x["name"])


def find_profile(name: str, profiles_dir: str | None = None) -> Path:
    if not PROFILE_NAME_RE.match(name or ""):
        raise ConfigError(f"bad profile name {name!r}: use letters, digits, - _ .")
    for d in profile_dirs(profiles_dir):
        for ext in (".toml", ".json"):
            f = Path(d) / f"{name}{ext}"
            if f.is_file():
                return f
    have = ", ".join(p["name"] for p in list_profiles(profiles_dir)) or "none"
    raise ConfigError(f"profile {name!r} not found in {', '.join(profile_dirs(profiles_dir))}. "
                      f"Available: {have}. List them with: scapegoat profiles")


def load(path: str, profile: str | None = None) -> Config:
    """Load the site config. If it names a profile (or `profile` is given), the profile
    file supplies defaults and the site file overrides them."""
    site = _read(path)
    name = profile or site.get("profile") or ""
    if name:
        pfile = find_profile(str(name), site.get("profiles_dir"))
        data = deep_merge(_read(str(pfile)), site)
        data["profile"] = str(name)
        data["profile_path"] = str(pfile)
    else:
        data = site
    return from_dict(data, str(Path(path)))
