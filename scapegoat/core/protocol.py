"""Protocol base class, shared data types and the package registry.

A protocol package subclasses Protocol. Generic packages ship in scapegoat.packages
(e.g. `toy`); every other protocol is a plugin found on the plugin path (see plugins.py).
The core owns the socket, timers and state; the package only builds and reads bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Decoded:
    """One received datagram, as the package understood it."""

    name: str = "unknown"
    fields: dict = field(default_factory=dict)
    ok: bool = False
    problems: list = field(default_factory=list)
    is_keepalive: bool = False
    peer_tx_counter: int | None = None


@dataclass
class ActionSpec:
    """A manual trigger offered to the CLI and the web page."""

    name: str
    label: str
    dangerous: bool = False
    description: str = ""
    # Plain words naming what sending it does to the sensor; may use {device_id} and {param}.
    effect: str = ""
    # Arguments the action takes: [(name, help, default or None = required)].
    params: list = field(default_factory=list)


@dataclass
class LinkState:
    """Per-session link facts. Owned by the core, read by the package.

    tx_counter: the transmit counter of the last message we sent (0 = none yet).
    rx_counter: the transmit counter of the last keepalive received from the peer.
    The package calls next_tx() once for every message it builds that carries a
    transmit counter. The core never advances tx_counter itself.
    """

    tx_counter: int = 0
    rx_counter: int = 0
    device_id: int = 0
    settings: dict = field(default_factory=dict)

    def next_tx(self) -> int:
        """Advance the transmit counter (1..65535, then wraps to 1) and return it."""
        self.tx_counter = self.tx_counter + 1 if 0 < self.tx_counter < 65535 else 1
        return self.tx_counter


class Protocol:
    """Base class every protocol package implements."""

    name: str = "base"
    default_port: int = 0
    keepalive_interval_s: float = 30.0

    def __init__(self, settings: dict):
        self.settings = dict(settings or {})

    def keepalive(self, link: LinkState, action: int = 0) -> bytes:
        raise NotImplementedError

    def decode(self, datagram: bytes) -> Decoded:
        raise NotImplementedError

    def on_receive(self, link: LinkState, msg: Decoded) -> list:
        return []

    def actions(self) -> dict:
        return {}

    def build_action(self, link: LinkState, name: str, args: dict | None = None):
        """bytes, or a list of datagrams to send in order."""
        raise NotImplementedError

    # Optional hooks (a package may leave them out):
    #   periodic(link, now) -> list[bytes]   messages due now (e.g. timing every 60 s)
    #   owes(msg) -> str | None               "this received message must be answered"
    #   status() -> dict                       package facts for the session status

    # ---- optional hooks; the defaults mean "nothing protocol-specific" ----
    # split(datagram) -> list of messages: define it when one datagram may carry several.
    # Keepalive field in which the peer asks for something, and code -> the action it asks for.
    peer_request_field: str | None = None
    peer_request_actions: dict = {}
    # Keepalive fields that carry the peer's own status, shown in the session status.
    peer_status_fields: tuple = ()
    # Actions gated by the [features] transmit_control flag (as well as by `dangerous`).
    transmit_actions: frozenset = frozenset()
    # (field, value) a simulator puts in its keepalives, so the page can say SIMULATOR.
    sim_marker: tuple | None = None
    # What the CLI and the web page call the sensor this protocol talks to; the
    # protocol_settings key that holds that sensor's ID (an operator types it to fire a
    # dangerous action); and the field of a decoded peer keepalive that carries the
    # peer's own ID. A protocol whose documents use other words sets its own.
    device_noun: str = "device"
    device_id_setting: str = "device_id"
    peer_id_field: str = "device_id"

    def summarize(self, msg: "Decoded") -> str:
        """One short line of the fields that matter, for `watch` and the traffic page.
        Default: the first six decoded fields."""
        f = getattr(msg, "fields", None) or {}
        return " ".join(f"{k}={str(v)[:24]}" for k, v in list(f.items())[:6])

    def soften_problems(self, part: bytes, msg: "Decoded") -> list:
        """Turn tolerable problems in msg into notes (returns the notes; edits msg)."""
        return []


def split_length_prefixed(data: bytes, length_offset: int = 1, min_len: int = 2):
    """Split a datagram that carries several messages back to back, each starting with
    label (byte 0) and its own total length (byte `length_offset`). Trailing zero bytes are
    padding. -> (parts, padding_bytes, problem or "")."""
    parts, o, n = [], 0, len(data)
    while o < n:
        rest = data[o:]
        if not any(rest):
            return parts, len(rest), ""
        if len(rest) <= length_offset:
            parts.append(rest)
            return parts, 0, f"{len(rest)} trailing bytes too short for a length byte"
        length = rest[length_offset]
        if length < min_len or length > len(rest):
            parts.append(rest)
            return parts, 0, (f"length byte {length} at offset {o} does not fit the "
                              f"{len(rest)} bytes left")
        parts.append(rest[:length])
        o += length
    return parts, 0, ""


class ProtocolError(Exception):
    """The named protocol package could not be loaded."""


def load_protocol(name: str, settings: dict) -> Protocol:
    """Build the Protocol for `name`: a built-in package or a plugin (plugins.py).

    The module may expose create(settings), or a class named
    <Name>Protocol, or a class attribute named Protocol.
    """
    from . import plugins
    try:
        mod = plugins.load_module(name)
    except plugins.PluginError as exc:
        raise ProtocolError(str(exc)) from exc
    except ImportError as exc:
        raise ProtocolError(f"protocol package {name!r} failed to import: {exc}") from exc
    create = getattr(mod, "create", None)
    if callable(create):
        return create(settings)
    for attr in (f"{name.capitalize()}Protocol", f"{name.upper()}Protocol", "Protocol"):
        cls: Any = getattr(mod, attr, None)
        if isinstance(cls, type) and cls is not Protocol:
            return cls(settings)
    raise ProtocolError(
        f"{mod.__name__} has no create(settings) function and no Protocol class")
