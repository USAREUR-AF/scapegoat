"""toy: a small, fully documented demonstration protocol (open, no sensor behind it).

It exercises everything the core does with a real protocol package: a keepalive with
transmit/receive counters, a peer that waits for us to speak first, a peer request,
several messages in one datagram, and a data message that is forwarded.

Wire format, big-endian; every message starts with a 2-byte tag and its total length:
  KA  b"KA" len(1)=10 tx(2) rx(2) action(1) flags(1)  sum(1)    keepalive
      action: 0 none, 2 "answer with a keepalive now"; flags bit 0: sent by the simulator
  DT  b"DT" len(1)=n  payload(n-4)                  sum(1)    data (no reply)
sum = byte sum of everything before it, mod 256.
"""

from __future__ import annotations

import struct

from scapegoat.core.protocol import ActionSpec, Decoded, Protocol

KA_LEN = 10
SIMULATOR_FLAG = 0x01
SIMULATORS = {"toy": "scapegoat.sim.toy:main"}


def _with_sum(body: bytes) -> bytes:
    return body + bytes([sum(body) % 256])


def keepalive_bytes(tx: int, rx: int, action: int = 0, flags: int = 0) -> bytes:
    return _with_sum(b"KA" + bytes([KA_LEN]) + struct.pack(">HHBB", tx, rx, action, flags))


def data_bytes(payload: bytes) -> bytes:
    n = len(payload) + 4
    if n > 255:
        raise ValueError("toy data payload is at most 251 bytes")
    return _with_sum(b"DT" + bytes([n]) + payload)


class ToyProtocol(Protocol):
    name = "toy"
    default_port = 47000
    keepalive_interval_s = 30.0
    peer_request_field = "action"
    peer_request_actions = {}
    sim_marker = ("flags", SIMULATOR_FLAG)

    def __init__(self, settings: dict | None = None):
        super().__init__(settings or {})
        self.keepalive_interval_s = float(self.settings.get("keepalive_interval_s", 30.0))

    def keepalive(self, link, action: int = 0) -> bytes:
        return keepalive_bytes(link.next_tx(), link.rx_counter & 0xFFFF, action)

    def split(self, data: bytes):
        """Messages back to back by their length byte (offset 2); trailing zeros = padding."""
        parts, o = [], 0
        while o < len(data):
            rest = data[o:]
            if not any(rest):
                return parts, len(rest), ""
            if len(rest) < 4 or rest[2] < 4 or rest[2] > len(rest):
                parts.append(rest)
                return parts, 0, f"{len(rest)} bytes at offset {o} do not hold a whole message"
            parts.append(rest[:rest[2]])
            o += rest[2]
        return parts, 0, ""

    def decode(self, d: bytes) -> Decoded:
        try:
            if len(d) < 4:
                return Decoded("unknown", {}, False, [f"short: {len(d)} bytes"], False, None)
            ok = sum(d[:-1]) % 256 == d[-1]
            problems = [] if ok else ["bad checksum"]
            if d[:2] == b"KA" and len(d) == KA_LEN:
                tx, rx, act, flags = struct.unpack(">HHBB", d[3:9])
                return Decoded("KeepAlive", {"transmit_counter": tx, "receive_counter": rx,
                                             "action": act, "flags": flags},
                               ok, problems, True, tx)
            if d[:2] == b"DT":
                return Decoded("Data", {"payload": d[3:-1].hex()}, ok, problems, False, None)
            return Decoded("unknown", {}, False, ["unknown message tag"], False, None)
        except Exception as exc:  # decode never raises
            return Decoded("unknown", {}, False, [f"decode error: {exc}"], False, None)

    def on_receive(self, link, msg: Decoded) -> list:
        if msg.ok and msg.is_keepalive and msg.fields.get("action") == 2:
            return [self.keepalive(link)]
        return []

    def actions(self) -> dict:
        return {
            "keepalive_now": ActionSpec("keepalive_now", "Send keepalive now", False,
                                        "Send a keepalive with no request."),
            "request_keepalive": ActionSpec("request_keepalive", "Request keepalive", False,
                                            "Ask the peer to answer with a keepalive now."),
        }

    def build_action(self, link, name: str) -> bytes:
        codes = {"keepalive_now": 0, "request_keepalive": 2}
        if name not in codes:
            raise KeyError(f"toy: unknown action {name!r}")
        return self.keepalive(link, codes[name])


def create(settings: dict) -> ToyProtocol:
    return ToyProtocol(settings)
