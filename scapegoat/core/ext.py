"""Optional site extension tables.

A deployment may add a module `scapegoat.compat` (for example to keep an earlier product
name working on its own nodes). The open core ships without it; every lookup here then
falls back to the plain behaviour.
"""

from __future__ import annotations

import os

try:
    from scapegoat import compat as _ext  # type: ignore[attr-defined]
except ImportError:
    _ext = None


def env(name: str, default=None):
    """$name, then any alias the extension declares. -> (value, note)."""
    if os.environ.get(name):
        return os.environ[name], ""
    for alias in (getattr(_ext, "ENV_ALIASES", {}) or {}).get(name, []):
        if os.environ.get(alias):
            return os.environ[alias], (getattr(_ext, "ENV_NOTES", {}) or {}).get(alias, "")
    return default, ""


def config_fallbacks() -> list:
    return list(getattr(_ext, "CONFIG_FALLBACKS", []) or [])


def config_fallback_note(path: str, default: str) -> str:
    tpl = getattr(_ext, "CONFIG_FALLBACK_NOTE", "") or ""
    return tpl.format(path=path, default=default) if tpl else ""


def profile_dirs() -> list:
    return list(getattr(_ext, "PROFILE_DIRS", []) or [])


def header(headers, name: str) -> str:
    v = headers.get(name)
    if v:
        return v
    for alias in (getattr(_ext, "HEADER_ALIASES", {}) or {}).get(name, []):
        if headers.get(alias):
            return headers.get(alias)
    return ""


def extra_island_urls(base: str, config, sid: str) -> list:
    fn = getattr(_ext, "extra_island_urls", None)
    return list(fn(base, config, sid)) if callable(fn) else []
