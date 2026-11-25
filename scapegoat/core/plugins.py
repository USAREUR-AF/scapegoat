"""Protocol plugins: packages that live outside the scapegoat core.

The open core ships only generic protocols (scapegoat.packages.*, e.g. `toy`). Every
other protocol package is a plugin: a directory `<plugin dir>/<name>/` holding a Python
package (`__init__.py`). It is imported as `scapegoat_plugins.<name>`, so it may use
relative imports among its own modules.

Plugin directories, searched in this order:
  1. SCAPEGOAT_PLUGIN_PATH (os.pathsep-separated), then `plugin_path` from the site config
  2. /etc/scapegoat/plugins, /opt/scapegoat/plugins (deploy/install.sh installs here)
  3. <checkout>/plugins (a source checkout that carries plugins)

What a plugin package may provide (all optional except a way to build its Protocol):
  create(settings) -> Protocol              or a class <Name>Protocol / Protocol
  validate_session(session_config)          raise ValueError to refuse a site config
  PROFILES = "profiles"                     a subdirectory of profile TOML files
  SIMULATORS = {"name": "module:function"}  simulators for `scapegoat sim <name>`
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import re
import sys
import types
from pathlib import Path

NAMESPACE = "scapegoat_plugins"
BUILTIN = "scapegoat.packages"
SYSTEM_DIRS = ("/etc/scapegoat/plugins", "/opt/scapegoat/plugins")
CHECKOUT_DIR = Path(__file__).resolve().parent.parent.parent / "plugins"
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
_extra: list = []


class PluginError(Exception):
    """A plugin could not be found or loaded."""


def set_extra_dirs(dirs) -> None:
    """Directories from the site config's `plugin_path`."""
    _extra[:] = [str(d) for d in (dirs or [])]


def plugin_dirs() -> list:
    env = [d for d in os.environ.get("SCAPEGOAT_PLUGIN_PATH", "").split(os.pathsep) if d]
    dirs = env + list(_extra) + list(SYSTEM_DIRS) + [str(CHECKOUT_DIR)]
    return list(dict.fromkeys(dirs))


def _check_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise PluginError(f"bad protocol name: {name!r}")
    return name


def find(name: str):
    """Directory of plugin `name`, or None."""
    _check_name(name)
    for d in plugin_dirs():
        p = Path(d) / name
        if (p / "__init__.py").is_file():
            return p
    return None


def _namespace():
    ns = sys.modules.get(NAMESPACE)
    if ns is None:
        ns = types.ModuleType(NAMESPACE)
        ns.__path__ = []
        sys.modules[NAMESPACE] = ns
    return ns


def load_module(name: str):
    """The module that provides protocol `name`: a built-in package or a plugin."""
    _check_name(name)
    try:
        return importlib.import_module(f"{BUILTIN}.{name}")
    except ModuleNotFoundError as exc:
        if exc.name not in (f"{BUILTIN}.{name}",):
            raise
    full = f"{NAMESPACE}.{name}"
    if full in sys.modules:
        return sys.modules[full]
    where = find(name)
    if where is None:
        raise PluginError(
            f"protocol {name!r} is not installed: not a built-in ({BUILTIN}.{name}) and not "
            f"found in the plugin path ({', '.join(plugin_dirs())}). Install its plugin "
            f"package, or set SCAPEGOAT_PLUGIN_PATH.")
    _namespace()
    spec = importlib.util.spec_from_file_location(
        full, where / "__init__.py", submodule_search_locations=[str(where)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[full] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop(full, None)
        raise
    return mod


def submodule(name: str, sub: str):
    """Import `<plugin>.<sub>` (e.g. a plugin's simulator module)."""
    mod = load_module(name)
    return importlib.import_module(f"{mod.__name__}.{sub}")


def installed() -> list:
    """Names of every plugin found in the plugin path."""
    names = []
    for d in plugin_dirs():
        try:
            for p in sorted(Path(d).iterdir()):
                if (p / "__init__.py").is_file() and _NAME_RE.match(p.name):
                    names.append(p.name)
        except OSError:
            continue
    return list(dict.fromkeys(names))


def validate_session(protocol: str, session_config) -> None:
    """Run the plugin's validate_session hook. A missing plugin is not an error here; the
    session reports it when it starts."""
    try:
        mod = load_module(protocol)
    except (PluginError, ImportError):
        return
    fn = getattr(mod, "validate_session", None)
    if callable(fn):
        fn(session_config)


def config_aliases(section: str, protocol: str | None = None) -> dict:
    """Old config key names a plugin still accepts, as {old: new}. A plugin module sets
    CONFIG_ALIASES = {"session": {...}, "features": {...}}. Session aliases come from the
    session's own protocol; feature aliases from every installed plugin."""
    names = [protocol] if protocol else installed()
    out = {}
    for name in names:
        try:
            table = getattr(load_module(name), "CONFIG_ALIASES", None) or {}
        except Exception:
            continue
        out.update({str(k): str(v) for k, v in (table.get(section) or {}).items()})
    return out


def apply_aliases(table: dict, aliases: dict, where: str) -> dict:
    """A copy of table with each old key renamed to its new name. Both set is an error."""
    out = dict(table)
    for old, new in aliases.items():
        if old in out:
            if new in out:
                raise ValueError(f"{where}: set {new} or its old name {old}, not both")
            out[new] = out.pop(old)
    return out


def profile_dirs() -> list:
    """Profile directories shipped by installed plugins."""
    out = []
    for name in installed():
        p = find(name)
        sub = None
        try:
            sub = getattr(load_module(name), "PROFILES", None)
        except Exception:
            sub = None
        if p is not None and sub and (p / sub).is_dir():
            out.append(str(p / sub))
    return out


def simulators() -> dict:
    """{simulator name: (protocol, "module:function")} over built-ins and plugins."""
    found = {}
    for name in ["toy"] + installed():
        try:
            mod = load_module(name)
        except Exception:
            continue
        for sim, target in (getattr(mod, "SIMULATORS", None) or {}).items():
            found.setdefault(sim, (name, target))
    return found


def simulator_main(sim: str):
    """The main(argv) function of simulator `sim`."""
    table = simulators()
    if sim not in table:
        have = ", ".join(sorted(table)) or "none"
        raise PluginError(f"no simulator {sim!r} installed (have: {have})")
    proto, target = table[sim]
    modname, _, func = target.partition(":")
    if proto == "toy" or load_module(proto).__name__.startswith(BUILTIN):
        mod = importlib.import_module(modname)
    else:
        mod = submodule(proto, modname)
    return getattr(mod, func or "main")
