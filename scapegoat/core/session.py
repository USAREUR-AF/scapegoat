"""One sensor session: one UDP socket, the link state machine, counters, events.

The socket is bound to the session's `local` address and used to send AND
receive. The sensor replies to the source address of our keepalives, so the
two directions must share one socket.

States:
  disabled     -> not running (or turned off by an operator)
  handshaking  -> sending keepalives, nothing received yet
  establishing -> peer keepalives arriving, fewer than establish_after so far
  established  -> link up
  degraded     -> one expected peer keepalive missed
  lost         -> two consecutive peer keepalives missed (keeps sending)

Peer candidates: until a sensor answers, every keepalive goes to EVERY candidate
address, each with its own LinkState (its own counters). The first candidate
whose IP sends a valid keepalive becomes the locked peer; the others are
dropped until `reset` (or a forced `lock`).
"""

from __future__ import annotations

import inspect
import ipaddress
import logging
import secrets
import sys
import socket
import threading
import time
from collections import deque
from datetime import datetime, timezone

from .config import SessionConfig, ConfigError, parse_addr
from . import traffic as trafficmod
from .protocol import Decoded, LinkState, Protocol, ProtocolError, load_protocol

log = logging.getLogger("scapegoat.session")

STATES = ("disabled", "handshaking", "establishing", "established", "degraded", "lost")
EVENT_RING = 500
ARM_WINDOW_S = 10.0        # an armed dangerous control stays unlocked this long (one shot)
OWED_REPLY_S = 5.0
FORWARD_REFUSED_PROBLEM_S = 10.0   # a forward target refusing this long is a PROBLEM
FORWARD_ROTATE_S = 60.0            # a fresh forward socket (new source port) at least this often
IP_RECVERR = getattr(socket, "IP_RECVERR", 11 if sys.platform.startswith("linux") else None)         # a message that needs an answer is a PROBLEM if unanswered this long
TRAFFIC_RING = 2000
BIND_RETRY_S = 5.0
FOREIGN_LOG_EVERY_S = 60.0
REPEAT_LOG_EVERY_S = 60.0   # a repeated problem or peer request is logged at most this often
MAX_PROBLEMS = 50           # distinct problem strings kept in status
# Protocol-specific behaviour (peer requests, peer status fields, radiate-gated actions,
# the simulator marker, tolerated decode problems) comes from the Protocol's hooks; see
# core/protocol.py. The core holds no protocol constants.
FEATURE_OFF_MSG = "radiate control is disabled by feature flag (features.radiate_control = false)"
KIND_SIM = "SIMULATOR"     # the other two kinds name the protocol's device: Session.kind_none / kind_real


class ActionRefused(Exception):
    """A dangerous action was asked for without permission (HTTP 403)."""


class ActionUnknown(Exception):
    """No such action for this session's protocol (HTTP 404)."""


class ActionFailed(Exception):
    """The action could not be carried out (HTTP 400)."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Session:
    def __init__(self, cfg: SessionConfig, protocol: Protocol | None = None):
        self.cfg = cfg
        self.id = cfg.id
        self.lock = threading.RLock()
        self.events: deque = deque(maxlen=EVENT_RING)
        self.traffic: deque = deque(maxlen=TRAFFIC_RING)
        self.arms: dict = {}
        self.on_tracks = None          # set by the service: callable(session_id, tracks)
        self.tracks_out = 0
        self.fwd_state: dict = {}      # forward target -> refusal / last-ok facts
        self.fwd_sock_replaced = 0
        self._fwd_replace_logged = 0.0
        self._fwd_rotated = time.monotonic()
        self.owed: list = []           # [{what, name, wall, mono}] waiting for an answer
        self.owed_answered = 0
        self.owed_missed = 0
        self.traffic_seq = 0
        self.error = ""
        self.protocol: Protocol | None = protocol
        if self.protocol is None:
            try:
                self.protocol = load_protocol(cfg.protocol, cfg.protocol_settings)
            except ProtocolError as exc:
                self.error = str(exc)
            except Exception as exc:  # a package that fails to build must not kill the daemon
                self.error = f"protocol {cfg.protocol} failed to start: {exc}"
        ps = cfg.protocol_settings
        default_iv = getattr(self.protocol, "keepalive_interval_s", 30.0) if self.protocol else 30.0
        self.interval = float(ps.get("keepalive_interval_s", default_iv))
        self.establish_after = max(1, int(ps.get("establish_after", 3)))
        self.margin = 0.25 * self.interval
        self.candidates = list(cfg.candidate_addrs)
        self.local = cfg.local_addr
        if not cfg.local:  # not set in the config: the protocol's own port on every address
            self.local = ("0.0.0.0", int(getattr(self.protocol, "default_port", 0) or 0))
        self.forward = cfg.forward_addrs
        noun = getattr(self.protocol, "device_noun", "device") if self.protocol else "device"
        self.noun = noun
        self.kind_none, self.kind_real = f"no {noun} yet", f"REAL {noun.upper()}"
        self.device_id = int(ps.get(getattr(self.protocol, "device_id_setting", "device_id")
                                    if self.protocol else "device_id", 0) or 0)
        self.links: dict = {}
        self.locked = None   # the candidate address we locked onto
        self.forced = False  # locked by an operator, not by a received keepalive
        self.sock: socket.socket | None = None
        self.fwd_sock: socket.socket | None = None
        self.rx_thread: threading.Thread | None = None
        self.stop_flag = threading.Event()
        self.enabled = bool(cfg.enabled) and self.protocol is not None
        self._last_bind_try = 0.0
        self._last_foreign_log = 0.0
        self._reset_counters()
        self.state = "disabled"
        if self.error:
            self.event("error", self.error, level="error")

    # ------------------------------------------------------------------ peers
    def _new_link(self) -> LinkState:
        return LinkState(device_id=self.device_id, settings=dict(self.cfg.protocol_settings))

    @property
    def link(self) -> LinkState:
        """The locked peer's link, or the first candidate's while probing."""
        return self.links[self.locked or self.candidates[0]]

    @property
    def peer(self):
        return self.locked or self.candidates[0]

    def _targets(self) -> list:
        return [self.locked] if self.locked else list(self.candidates)

    def _candidate_for(self, ip: str):
        for c in self._targets():
            if c[0] == ip:
                return c
        return None

    @staticmethod
    def _fmt(a) -> str:
        return f"{a[0]}:{a[1]}" if a else ""

    # ------------------------------------------------------------------ counters
    def _reset_counters(self):
        self.candidates = list(self.cfg.candidate_addrs)
        self.links = {c: self._new_link() for c in self.candidates}
        self.locked = None
        self.forced = False
        self.rx_datagrams = 0
        self.tx_datagrams = 0
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.bad_datagrams = 0
        self.foreign_datagrams = 0
        self.forwarded = 0
        self.forward_errors = 0
        self.send_errors = 0
        self.rx_by_name: dict = {}
        self.rx_messages = 0
        self.multi_message_datagrams = 0
        self.notes: dict = {}          # soft notes: text -> {count, first, last, messages}
        self.datagram_seq = 0
        self.tx_by_name: dict = {}
        self.ka_streak = 0
        self.ka_rx_total = 0
        self.problems: dict = {}       # text -> {count, first, last, logged_count, last_log}
        self.peer_requests: dict = {}  # label -> {code, count, last, last_log}
        self.peer_request = None       # the request in the last peer keepalive, or None
        self.peer_status: dict = {}    # sensor/subsystem labels from the last peer keepalive
        self.peer_status_at = None
        self.peer_urn = None           # the sim_marker field in the last peer keepalive
        self.peer_device_id = None     # the peer's own ID in its last keepalive
        self._kind_logged = None
        self.last_rx = None
        self.last_tx = None
        self.last_ka_rx = None
        self.peer_seen = None
        self.next_ka_due = 0.0
        self.state_since = time.monotonic()

    # ------------------------------------------------------------------ events
    def event(self, kind: str, msg: str, level: str = "info", source: str = "core"):
        ev = {"time": _now_iso(), "ts": time.time(), "kind": kind, "level": level,
              "source": source, "message": msg}
        self.events.append(ev)
        getattr(log, "warning" if level == "warn" else level if level in ("info", "error") else "info")(
            "[%s] %s (%s): %s", self.id, kind, source, msg)

    def _set_state(self, new: str, why: str):
        if new != self.state:
            old, self.state = self.state, new
            self.state_since = time.monotonic()
            self.event("state", f"{old} -> {new}: {why}",
                       level="warn" if new in ("degraded", "lost") else "info")

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        with self.lock:
            if self.enabled:
                self._open()

    def _open(self) -> bool:
        if self.sock is not None:
            return True
        self._last_bind_try = time.monotonic()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(self.local)
            s.settimeout(0.25)
        except OSError as exc:
            msg = f"cannot open UDP {self._fmt(self.local)}: {exc}. Retrying every {BIND_RETRY_S:.0f} s."
            if self.error != msg:
                self.error = msg
                self.event("error", msg, level="error")
            self._set_state("handshaking", "waiting for the local UDP port")
            return False
        self.sock = s
        self.fwd_sock = self._new_fwd_sock() if self.forward else None
        self.error = ""
        self.stop_flag = threading.Event()
        self.rx_thread = threading.Thread(target=self._rx_loop, args=(s, self.stop_flag),
                                          name=f"scapegoat-rx-{self.id}", daemon=True)
        self.rx_thread.start()
        self.event("socket", f"listening on {self._fmt(self.local)}, peer "
                             f"{', '.join(self._fmt(c) for c in self._targets())}")
        self.next_ka_due = 0.0  # send the first keepalive now
        self._set_state("handshaking", "socket open, sending keepalives")
        return True

    def _close(self):
        self.stop_flag.set()
        for s in (self.sock, self.fwd_sock):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        t = self.rx_thread
        self.sock = self.fwd_sock = self.rx_thread = None
        if t is not None and t is not threading.current_thread():
            t.join(timeout=2)

    def stop(self):
        with self.lock:
            self._close()

    def enable(self, source: str = "api"):
        with self.lock:
            if self.protocol is None:
                raise ActionFailed(self.error or "protocol not loaded")
            self.event("action", "enable", source=source)
            self.enabled = True
            self._open()

    def disable(self, source: str = "api"):
        with self.lock:
            self.event("action", "disable", source=source)
            self.enabled = False
            self._close()
            self._set_state("disabled", f"disabled by {source}")

    def reset(self, source: str = "api"):
        with self.lock:
            self.event("action", "reset (counters to 0, unlock peer, state handshaking)",
                       source=source)
            self._reset_counters()
            if self.enabled and self.sock is not None:
                self._set_state("handshaking", f"reset by {source}")
            elif not self.enabled:
                self._set_state("disabled", "reset while disabled")

    def force_lock(self, addr_text: str, source: str = "api"):
        """Lock onto one address now (it is added if it is not a candidate)."""
        with self.lock:
            try:
                addr = parse_addr(addr_text, "peer")
            except ConfigError as exc:
                raise ActionFailed(str(exc)) from None
            if addr not in self.candidates:
                self.candidates.append(addr)
            self.links.setdefault(addr, self._new_link())
            self.locked, self.forced = addr, True
            self.last_ka_rx = None
            self.ka_streak = 0
            self.next_ka_due = 0.0
            self.event("lock", f"locked onto {self._fmt(addr)} (forced by {source}); "
                               "not sending to other candidates", source=source)
            if self.enabled and self.sock is not None:
                self._set_state("handshaking", f"forced lock by {source}")

    def _auto_lock(self, cand, addr):
        self.locked, self.forced = cand, False
        others = [self._fmt(c) for c in self.candidates if c != cand]
        self.event("lock", f"locked onto {self._fmt(addr)}"
                   + (f"; stopped sending to {', '.join(others)}" if others else ""))

    # ------------------------------------------------------------------ sending
    def _decode(self, data: bytes):
        try:
            return self.protocol.decode(data)
        except Exception as exc:
            return Decoded(problems=[f"decoder error: {exc}"])

    def _record(self, direction: str, addr, data: bytes, msg, extra_problem: str = "",
                extra: dict | None = None):
        e = trafficmod.make_entry(direction, self._fmt(addr), data, msg)
        if extra_problem:
            e["problems"].append(extra_problem)
        if msg is not None and getattr(msg, "_notes", None):
            e["notes"] = list(msg._notes)
        if msg is not None and self.protocol is not None:
            try:
                e["summary"] = str(self.protocol.summarize(msg))
            except Exception:
                pass
        if extra:
            e.update(extra)
        self.traffic_seq += 1
        e["seq"] = self.traffic_seq
        self.traffic.append(e)

    def get_traffic(self, since: int | None = None, limit: int = 200) -> dict:
        limit = max(1, min(int(limit), 2000))
        with self.lock:
            items = list(self.traffic)
            last = self.traffic_seq
        if since is None:
            items = items[-limit:]
        else:
            items = [e for e in items if e["seq"] > since][:limit]
        return {"session": self.id, "last_seq": last, "entries": items}

    def wire(self, seconds: float = 10, iface: str = "any") -> dict:
        """Capture the session's UDP port from the wire and decode every payload."""
        packets, error = trafficmod.wire_capture(self.local[1], seconds, iface)
        entries, unreachable = [], []
        for p in [p for p in packets if "icmp_unreachable" in p]:
            u = p["icmp_unreachable"]
            unreachable.append(u)
            self._note_problem(u["hint"], time.monotonic(), "ICMP")
        packets = [p for p in packets if "icmp_unreachable" not in p]
        for i, p in enumerate(packets, 1):
            msg = self._decode(p["payload"]) if self.protocol else None
            e = trafficmod.make_entry("wire", p["src"], p["payload"], msg)
            e.update(seq=i, src=p["src"], dst=p["dst"], capture_time=p["time"])
            entries.append(e)
        return {"session": self.id, "port": self.local[1], "seconds": seconds,
                "entries": entries, "error": error, "icmp_unreachable": unreachable,
                "hints": [u["hint"] for u in unreachable]}

    def _send(self, data: bytes, addr, why: str) -> bool:
        if self.sock is None:
            return False
        try:
            self.sock.sendto(data, addr)
        except OSError as exc:
            self.send_errors += 1
            self.event("error", f"send to {addr[0]}:{addr[1]} failed ({why}): {exc}", level="error")
            return False
        self.tx_datagrams += 1
        self.tx_bytes += len(data)
        self.last_tx = time.monotonic()
        # Same rule as received copies: a message we built that is self-consistent by its own
        # length byte shows dictionary drift as a note, not a failure.
        msg = self._decode_part(data)
        name = msg.name or "unknown"
        self.tx_by_name[name] = self.tx_by_name.get(name, 0) + 1
        self._record("tx", addr, data, msg)
        return True

    def tick(self, now: float | None = None):
        """Called often by the scheduler: send due keepalives, check for misses."""
        now = time.monotonic() if now is None else now
        with self.lock:
            if not self.enabled:
                return
            if self.sock is None:
                if now - self._last_bind_try >= BIND_RETRY_S:
                    self._open()
                if self.sock is None:
                    return
            if now >= self.next_ka_due:
                for c in self._targets():
                    try:
                        data = self.protocol.keepalive(self.links[c], 0)
                    except Exception as exc:
                        self.event("error", f"building keepalive failed: {exc}", level="error")
                        data = None
                    if data:
                        self._send(data, c, "keepalive")
                self.next_ka_due = now + self.interval
            self._expire_arms(now)
            self._periodic(now)
            self._check_owed(now)
            self._check_forwards(now)
            self._check_missed(now)

    def _periodic(self, now: float):
        """Package messages that are due (e.g. a timing message every 60 s) once a peer is locked."""
        fn = getattr(self.protocol, "periodic", None)
        if callable(fn) and self.locked is not None:
            try:
                due = fn(self.links[self.locked], now) or []
            except Exception as exc:
                self.event("error", f"protocol periodic failed: {exc}", level="error")
                due = []
            for d in due:
                self._send(d, self.locked, "periodic")
        drain = getattr(self.protocol, "drain_events", None)
        if callable(drain):
            try:
                for text in drain() or []:
                    self.event("protocol", str(text))
            except Exception:
                pass

    def _check_owed(self, now: float):
        keep = []
        for o in self.owed:
            if now - o["mono"] > OWED_REPLY_S:
                self.owed_missed += 1
                hhmmss = datetime.fromtimestamp(o["wall"], timezone.utc).strftime("%H:%M:%S")
                self._note_problem(f"owed: {o['what']} for {o['name']} from the {self.noun} at {hhmmss}Z, "
                                   "unanswered", now, o["name"])
            else:
                keep.append(o)
        self.owed = keep

    def _check_missed(self, now: float):
        if self.state in ("disabled", "handshaking") or self.last_ka_rx is None:
            return
        silent = now - self.last_ka_rx
        if silent > 2 * self.interval + self.margin:
            if self.state != "lost":
                self.ka_streak = 0
                self._set_state("lost", f"no keepalive from peer for {silent:.1f} s "
                                        "(two missed); still sending keepalives")
        elif silent > self.interval + self.margin:
            if self.state not in ("degraded", "lost"):
                self.ka_streak = 0
                self._set_state("degraded", f"one keepalive from peer missed ({silent:.1f} s)")

    # ------------------------------------------------------------------ receiving
    def _rx_loop(self, sock: socket.socket, stop: threading.Event):
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if stop.is_set():
                    return
                time.sleep(0.1)
                continue
            try:
                self._handle(data, addr)
            except Exception as exc:  # never let one bad datagram kill the thread
                self.event("error", f"handling datagram from {addr}: {exc}", level="error")

    def _handle(self, data: bytes, addr):
        now = time.monotonic()
        with self.lock:
            cand = self._candidate_for(addr[0])
            if cand is None:
                self.foreign_datagrams += 1
                self._record("rx", addr, data, self._decode(data),
                             "ignored: not from a peer candidate")
                if now - self._last_foreign_log > FOREIGN_LOG_EVERY_S:
                    self._last_foreign_log = now
                    want = ", ".join(c[0] for c in self._targets())
                    self.event("foreign", f"ignored datagram from {addr[0]}:{addr[1]} "
                                          f"(expected {want})", level="warn")
                return
            link = self.links[cand]
            self.rx_datagrams += 1
            self.rx_bytes += len(data)
            self.last_rx = now
            if self.peer_seen != addr and (self.locked is None or cand == self.locked):
                self.event("peer", f"peer answering from {addr[0]}:{addr[1]}")
                self.peer_seen = addr
            parts, padding, split_problem = self._split(data)
            self.datagram_seq += 1
            dg = self.datagram_seq
            msgs = [self._decode_part(p) for p in parts]
            if len(parts) > 1 or padding or split_problem:
                if len(parts) > 1:
                    self.multi_message_datagrams += 1
                summary = Decoded(name=f"datagram: {len(parts)} message(s)",
                                  fields={"messages": [f"{m.name or 'unknown'} ({len(p)} B)"
                                                       for m, p in zip(msgs, parts)],
                                          "padding_bytes": padding},
                                  ok=not split_problem,
                                  problems=[split_problem] if split_problem else [])
                self._record("dgram", addr, data, summary, extra={"datagram": dg})
                if split_problem:
                    self._note_problem(split_problem, now, "datagram")
            if self.cfg.forward_mode == "datagram":
                self._forward(data, msgs[0] if len(msgs) == 1 else Decoded(
                    name=f"datagram: {len(parts)} message(s)", ok=True))
            for i, (part, msg) in enumerate(zip(parts, msgs), 1):
                self._record("rx", addr, part, msg, extra={
                    "datagram": dg, "part": i, "parts": len(parts), "datagram_length": len(data)})
                if self.cfg.forward_mode == "message":
                    self._forward(part, msg)
                self._handle_message(part, msg, addr, cand, link, now)

    def _split(self, data: bytes):
        """Messages in one datagram. A package may provide split(data), returning a list of
        messages or (messages, padding_bytes, problem)."""
        fn = getattr(self.protocol, "split", None)
        if callable(fn):
            try:
                r = fn(data)
                if isinstance(r, tuple) and len(r) == 3:
                    parts, padding, problem = r
                    return (list(parts) or [data]), padding, problem
                return list(r) or [data], 0, ""
            except Exception as exc:
                return [data], 0, f"split failed: {exc}"
        return [data], 0, ""

    def _decode_part(self, part: bytes):
        msg = self._decode(part)
        notes = []
        soften = getattr(self.protocol, "soften_problems", None)
        if callable(soften):
            try:
                notes = list(soften(part, msg) or [])
            except Exception:
                notes = []
        try:
            msg._notes = notes
        except Exception:
            pass
        return msg

    @staticmethod
    def _new_fwd_sock():
        """A separate, unconnected UDP socket for copies to the forward targets. On Linux it
        asks for ICMP errors (IP_RECVERR), so a refusing target shows up as ECONNREFUSED on the
        next send instead of being silently ignored."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if IP_RECVERR is not None:
            try:
                s.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
            except OSError:
                pass
        return s

    def _replace_fwd_sock(self, why: str, quiet: bool = False):
        """A fresh socket (new source port) after a send error, and periodically. Hygiene: it
        keeps one broken socket from holding the forward path."""
        old, self.fwd_sock = self.fwd_sock, self._new_fwd_sock()
        self._fwd_rotated = time.monotonic()
        if quiet:
            try:
                if old is not None:
                    old.close()
            except OSError:
                pass
            return
        self.fwd_sock_replaced += 1
        try:
            if old is not None:
                old.close()
        except OSError:
            pass
        now = time.monotonic()
        if now - self._fwd_replace_logged > 5:
            self._fwd_replace_logged = now
            self.event("forward", f"forward socket replaced ({why})", level="warn")

    def _forward(self, data: bytes, msg):
        now = time.monotonic()
        for f in self.forward:
            if self.fwd_sock is None:
                self._replace_fwd_sock("no forward socket")
            st = self.fwd_state.setdefault(f, {"refused_since": None, "last_refused": None,
                                               "last_ok": None, "errors": 0, "last_error": ""})
            try:
                self.fwd_sock.sendto(data, f)
            except OSError as exc:
                # count only what was really sent; any error: count, log, new socket, retry once
                self.forward_errors += 1
                st["errors"] += 1
                st["last_error"] = str(exc)
                if isinstance(exc, ConnectionRefusedError):
                    st["last_refused"] = now
                    if st["refused_since"] is None:
                        st["refused_since"] = now
                self._record("fwd", f, data, msg, f"forward failed: {exc}")
                self._replace_fwd_sock(f"send to {f[0]}:{f[1]} failed: {exc}")
                try:
                    self.fwd_sock.sendto(data, f)
                except OSError as exc2:
                    self.forward_errors += 1
                    st["errors"] += 1
                    st["last_error"] = str(exc2)
                    if isinstance(exc2, ConnectionRefusedError):
                        st["last_refused"] = now
                        if st["refused_since"] is None:
                            st["refused_since"] = now
                    continue
            self.forwarded += 1
            st["last_ok"] = now
            self._record("fwd", f, data, msg)

    def _check_forwards(self, now: float):
        """PROBLEM while a forward target keeps refusing sends for more than 10 s. A refused
        send is retried on a new socket, so the kernel may still accept copies in between:
        what counts is that refusals keep arriving. Also replaces the forward socket every
        FORWARD_ROTATE_S."""
        if self.fwd_sock is not None and now - self._fwd_rotated >= FORWARD_ROTATE_S:
            self._fwd_rotated = now
            self._replace_fwd_sock("periodic rotation", quiet=True)
        for f, st in self.fwd_state.items():
            since = st["refused_since"]
            if since is None:
                continue
            if now - st["last_refused"] > FORWARD_REFUSED_PROBLEM_S:
                st["refused_since"] = None      # no refusal for 10 s: the target is back
                continue
            if now - since > FORWARD_REFUSED_PROBLEM_S:
                self._note_problem(f"forward target {f[0]}:{f[1]}: receiver not receiving for "
                                   f"more than {FORWARD_REFUSED_PROBLEM_S:g} s (check the kid's "
                                   "port forwarding: billie kid activate)", now, "forward")

    def _note_soft(self, text: str, now: float, where: str):
        n = self.notes.get(text)
        if n is None:
            if len(self.notes) >= MAX_PROBLEMS:
                del self.notes[min(self.notes, key=lambda k: self.notes[k]["last"])]
            n = self.notes[text] = {"count": 0, "first": now, "last": now, "messages": []}
            self.event("note", f"{text} [in {where}]")
        if where and where not in n["messages"]:
            n["messages"].append(where)
        n["count"] += 1
        n["last"] = now

    def _handle_message(self, data: bytes, msg, addr, cand, link, now: float):
        """One message (a datagram may hold several): count, surface, receipt, keepalive."""
        with self.lock:
            self.rx_messages += 1
            name = msg.name or "unknown"
            for note in getattr(msg, "_notes", None) or []:
                self._note_soft(note, now, name)
            self.rx_by_name[name] = self.rx_by_name.get(name, 0) + 1
            if not msg.ok:
                self.bad_datagrams += 1
            probs = [str(p) for p in (msg.problems or [])]
            if not msg.ok and not probs:
                probs = ["failed checks"]
            for p in probs:
                self._note_problem(p, now, name)
            if msg.is_keepalive and msg.ok:
                if self.locked is None:
                    self._auto_lock(cand, addr)
                    self.peer_seen = addr
                self._on_keepalive(link, msg, now)
            owes = None
            fn = getattr(self.protocol, "owes", None)
            if callable(fn):
                try:
                    owes = fn(msg)
                except Exception:
                    owes = None
            try:
                # pass decode()'s own object: packages may carry extras (e.g. raw bytes)
                replies = self.protocol.on_receive(link, msg) or []
            except Exception as exc:
                self.event("error", f"protocol on_receive failed for {name}: {exc}", level="error")
                replies = []
            answered = False
            for r in replies:
                answered = self._send(r, addr, f"reply to {name}") or answered
            if owes:
                if answered:
                    self.owed_answered += 1
                else:
                    self.owed.append({"what": owes, "name": name, "wall": time.time(),
                                      "mono": now})
            self._emit_tracks(msg, name)

    def _emit_tracks(self, msg, name: str):
        """Normalized tracks from the plugin's tracks(msg) hook, to the C2 outputs."""
        fn = getattr(self.protocol, "tracks", None)
        if not callable(fn) or self.on_tracks is None or not getattr(msg, "ok", False):
            return
        try:
            tracks = fn(msg) or []
        except Exception as exc:
            self.event("error", f"protocol tracks() failed for {name}: {exc}", level="error")
            return
        if tracks:
            self.tracks_out += len(tracks)
            try:
                self.on_tracks(self.id, tracks)
            except Exception as exc:
                self.event("error", f"C2 outputs failed: {exc}", level="error")

    # ------------------------------------------------------------------ surfacing
    def _note_problem(self, text: str, now: float, where: str = ""):
        """Event the first time a problem appears, then at most once a minute with a count.
        Keyed by the problem text; `where` (the message names it appeared in) is recorded."""
        p = self.problems.get(text)
        if p is None:
            if len(self.problems) >= MAX_PROBLEMS:
                oldest = min(self.problems, key=lambda k: self.problems[k]["last"])
                del self.problems[oldest]
            p = self.problems[text] = {"count": 0, "first": now, "last": now,
                                       "last_log": None, "logged_count": 0, "messages": []}
        if where and where not in p["messages"]:
            p["messages"].append(where)
        p["count"] += 1
        p["last"] = now
        if p["last_log"] is None or now - p["last_log"] >= REPEAT_LOG_EVERY_S:
            extra = "" if p["count"] == 1 else f" (seen {p['count']} times)"
            inn = f" [in {', '.join(p['messages'])}]" if p["messages"] else ""
            self.event("problem", text + inn + extra, level="warn")
            p["last_log"] = now
            p["logged_count"] = p["count"]

    @staticmethod
    def _field(msg, key):
        """(raw number or None, label) of a decoded field. Packages may keep raw numbers in
        msg.values and labels in msg.fields."""
        fields = getattr(msg, "fields", None) or {}
        values = getattr(msg, "values", None) or {}
        label = fields.get(key)
        raw = values.get(key, label if isinstance(label, int) and not isinstance(label, bool) else None)
        return raw, ("" if label is None else str(label))

    def _suggested_action(self, code):
        mapping = getattr(self.protocol, "peer_request_actions", None) or {}
        name = mapping.get(code)
        return name if name in self.actions() else None

    def _on_peer_keepalive_fields(self, msg, now: float):
        for key in getattr(self.protocol, "peer_status_fields", None) or ():
            raw, label = self._field(msg, key)
            if label or raw is not None:
                self.peer_status[key] = label or str(raw)
        if self.peer_status:
            self.peer_status_at = now
        marker = getattr(self.protocol, "sim_marker", None)
        if marker:
            urn, _ = self._field(msg, marker[0])
            if urn is not None:
                self.peer_urn = urn
        rid, rlabel = self._field(msg, getattr(self.protocol, "peer_id_field", "device_id"))
        self.peer_device_id = rid if rid is not None else (rlabel or None)
        req_field = getattr(self.protocol, "peer_request_field", None)
        if not req_field:
            return
        raw, label = self._field(msg, req_field)
        if raw is None and not label:
            return
        if raw == 0 or (raw is None and label.lower() in ("0", "no statement")):
            self.peer_request = None
            return
        label = label or f"request {raw}"
        r = self.peer_requests.setdefault(label, {"code": raw, "count": 0, "last": now,
                                                  "last_log": None})
        r["count"] += 1
        r["last"] = now
        self.peer_request = label
        if r["last_log"] is None or now - r["last_log"] >= REPEAT_LOG_EVERY_S:
            act = self._suggested_action(raw)
            extra = "" if r["count"] == 1 else f" (seen {r['count']} times)"
            self.event("peer", f"peer requests: {label}{extra}"
                       + (f"; matching action: {act}" if act else ""), level="warn")
            r["last_log"] = now

    def peer_kind(self) -> str:
        """SIMULATOR if the answering peer is on loopback or marks its keepalives with the
        protocol's simulator marker (Protocol.sim_marker); REAL <device> once any other peer has answered."""
        addr = self.peer_seen or (self.locked if self.ka_rx_total else None)
        if addr is None:
            return self.kind_none
        try:
            loop = ipaddress.ip_address(addr[0]).is_loopback
        except ValueError:
            loop = False
        marker = getattr(self.protocol, "sim_marker", None)
        is_sim = bool(marker) and self.peer_urn is not None and self.peer_urn == marker[1]
        return KIND_SIM if loop or is_sim else self.kind_real

    def _log_kind(self):
        k = self.peer_kind()
        if k != self._kind_logged:
            self._kind_logged = k
            where = self._fmt(self.peer_seen) if self.peer_seen else ""
            self.event("kind", f"peer is {k}" + (f" at {where}" if where else ""),
                       level="warn" if k == self.kind_real else "info")

    def _on_keepalive(self, link: LinkState, msg: Decoded, now: float):
        self._on_peer_keepalive_fields(msg, now)
        if msg.peer_tx_counter is not None:
            link.rx_counter = int(msg.peer_tx_counter)
        self.last_ka_rx = now
        self.ka_rx_total += 1
        self.ka_streak += 1
        st = self.state
        if st == "handshaking":
            self._set_state("establishing", "first keepalive from peer")
        elif st == "degraded":
            self._set_state("established", "peer keepalive back")
        elif st == "lost":
            self._set_state("establishing", "peer keepalive after link lost")
        if self.state == "establishing" and self.ka_streak >= self.establish_after:
            self._set_state("established", f"{self.ka_streak} keepalives received")
        self._log_kind()

    # ------------------------------------------------------------------ actions
    def _all_actions(self) -> dict:
        if self.protocol is None:
            return {}
        try:
            return dict(self.protocol.actions() or {})
        except Exception:
            return {}

    def _is_radiate(self, name, spec) -> bool:
        gated = getattr(self.protocol, "radiate_actions", None) or ()
        return name in gated or bool(getattr(spec, "dangerous", False))

    def actions(self) -> dict:
        """The actions offered. Radiate actions vanish unless features.radiate_control."""
        acts = self._all_actions()
        if not self.cfg.radiate_feature:
            acts = {n: s for n, s in acts.items() if not self._is_radiate(n, s)}
        return acts

    # ------------------------------------------------------------------ safety latch
    def _effect(self, spec, args=None) -> str:
        text = getattr(spec, "effect", "") or f"{spec.label} will be sent to the {self.noun}"
        vals = {"device_id": self.device_id}
        for p in getattr(spec, "params", []) or []:
            vals.setdefault(p[0], (args or {}).get(p[0], p[2] if p[2] is not None else "?"))
        vals.update(args or {})
        try:
            return text.format(**vals)
        except (KeyError, IndexError, ValueError):
            return text

    def _ctl(self, what: str, name: str, source: str, who: str, extra: str = ""):
        """Every arm / fire / cancel / timeout: an event and a traffic-log entry."""
        msg = f"{what} {name} by {source}" + (f" ({who})" if who else "") + (f": {extra}" if extra else "")
        self.event(what, msg, level="warn", source=source)
        self.traffic_seq += 1
        self.traffic.append({"seq": self.traffic_seq, "time": _now_iso(), "ts": time.time(),
                             "direction": "ctl", "peer": who or source, "length": 0,
                             "name": f"{what} {name}", "ok": True, "problems": [],
                             "fields": {"action": name, "what": what, "source": source,
                                        "who": who, "detail": extra}, "hex": ""})

    def _dangerous_spec(self, name: str, source: str):
        if not self.cfg.radiate_feature and (
                self._is_radiate(name, self._all_actions().get(name))):
            self.event("refused", f"{name} refused: {FEATURE_OFF_MSG}", level="warn", source=source)
            raise ActionRefused(FEATURE_OFF_MSG)
        acts = self.actions()
        spec = acts.get(name)
        if spec is None:
            raise ActionUnknown(f"no action named {name!r}. Known: {', '.join(acts) or 'none'}")
        if spec.dangerous and not self.cfg.allow_radiate_control:
            self.event("refused", f"{name} refused: allow_radiate_control is false "
                                  "in this session's config", level="warn", source=source)
            raise ActionRefused(
                f"{name} commands the {self.noun} and this session does not allow it. "
                f"Set allow_radiate_control = true under [sessions.{self.id}] and restart.")
        return spec

    def arm(self, name: str, source: str = "api", who: str = "", args: dict | None = None) -> dict:
        """Unlock one dangerous action for ARM_WINDOW_S seconds (one shot)."""
        with self.lock:
            spec = self._dangerous_spec(name, source)
            if not spec.dangerous:
                raise ActionFailed(f"{name} needs no arming")
            token = secrets.token_hex(8)
            self.arms[name] = {"token": token, "until": time.monotonic() + ARM_WINDOW_S,
                               "source": source, "who": who}
            effect = self._effect(spec, args)
            self._ctl("arm", name, source, who, f"{ARM_WINDOW_S:g} s window; would: {effect}")
            return {"ok": True, "action": name, "token": token, "expires_in_s": ARM_WINDOW_S,
                    "effect": effect, "device_id": self.device_id, "device_noun": self.noun}

    def disarm(self, name: str, source: str = "api", who: str = "") -> dict:
        with self.lock:
            if self.arms.pop(name, None):
                self._ctl("cancel", name, source, who)
            return {"ok": True, "action": name, "armed": False}

    def _expire_arms(self, now: float):
        for name in [n for n, a in self.arms.items() if now >= a["until"]]:
            a = self.arms.pop(name)
            self._ctl("timeout", name, a["source"], a["who"], "re-locked")

    def run_action(self, name: str, confirm=False, source: str = "api",
                   args: dict | None = None, token: str | None = None, who: str = "") -> dict:
        with self.lock:
            spec = self._dangerous_spec(name, source)
            args = dict(args or {})
            if spec.dangerous:
                arm = self.arms.pop(name, None)   # one shot: any attempt re-locks
                if arm is None or time.monotonic() >= arm["until"]:
                    self.event("refused", f"{name} refused: not armed", level="warn", source=source)
                    raise ActionRefused(f"{name} is locked. Arm it first (CLI: --arm; web page: "
                                        f"Arm), then confirm with the {self.noun} ID within "
                                        f"{ARM_WINDOW_S:g} s. Would: {self._effect(spec, args)}")
                if token is None or token != arm["token"]:
                    self._ctl("cancel", name, source, who, "arm token does not match")
                    raise ActionRefused(f"{name}: this arm belongs to another request; arm again")
                if str(confirm).strip() != str(self.device_id):
                    self._ctl("cancel", name, source, who,
                              f"{self.noun} ID typed {str(confirm)!r}, expected {self.device_id}")
                    raise ActionRefused(f"{name} refused: the {self.noun} ID typed does not match "
                                        f"({self.device_id}). Re-locked; arm again.")
            if not self.enabled or self.sock is None:
                raise ActionFailed(f"session {self.id} is not running; enable it first")
            sent, size = [], 0
            for c in self._targets():
                try:
                    data = self._build(name, c, args)
                except Exception as exc:
                    raise ActionFailed(f"{name}: {exc}") from exc
                for d in data:
                    if self._send(d, c, f"action {name}"):
                        size += len(d)
                        if self._fmt(c) not in sent:
                            sent.append(self._fmt(c))
            effect = self._effect(spec, args) if spec.dangerous else ""
            if spec.dangerous:
                self._ctl("fire", name, source, who, f"{effect}; sent to {', '.join(sent) or 'nobody'}")
            self.event("action", f"{name} sent to {', '.join(sent)} ({size} bytes)"
                       if sent else f"{name} could not be sent", source=source,
                       level="warn" if spec.dangerous else "info")
            if not sent:
                raise ActionFailed(f"sending {name} failed; see events")
            return {"ok": True, "session": self.id, "action": name, "bytes": size,
                    "sent_to": sent, "tx_counter": self.link.tx_counter, "effect": effect}

    def _build(self, name: str, c, args: dict) -> list:
        fn = self.protocol.build_action
        try:
            takes_args = len(inspect.signature(fn).parameters) >= 3
        except (TypeError, ValueError):
            takes_args = False
        data = fn(self.links[c], name, args) if takes_args else fn(self.links[c], name)
        return list(data) if isinstance(data, (list, tuple)) else [data]

    # ------------------------------------------------------------------ status
    def status(self, events: int = 0) -> dict:
        now = time.monotonic()

        def age(t):
            return None if t is None else round(now - t, 2)

        with self.lock:
            acts = []
            for n, spec in self.actions().items():
                allowed = (not spec.dangerous) or self.cfg.allow_radiate_control
                arm = self.arms.get(n)
                acts.append({"name": n, "label": spec.label, "dangerous": bool(spec.dangerous),
                             "description": spec.description, "allowed": allowed,
                             "effect": self._effect(spec) if spec.dangerous else "",
                             "params": [{"name": p[0], "help": p[1], "default": p[2]}
                                        for p in (getattr(spec, "params", []) or [])],
                             "armed_s": round(arm["until"] - now, 1) if arm and arm["until"] > now
                             else 0,
                             "why_not": "" if allowed else
                             "allow_radiate_control is false in this session's config"})
            pstat = None
            fn = getattr(self.protocol, "status", None)
            if callable(fn):
                try:
                    pstat = fn()
                except Exception as exc:
                    pstat = {"error": str(exc)}
            out = {
                "id": self.id, "protocol": self.cfg.protocol, "state": self.state,
                "state_age_s": age(self.state_since), "enabled": self.enabled,
                "error": self.error, "local": self._fmt(self.local), "peer": self._fmt(self.peer),
                "locked": self._fmt(self.locked) or None, "lock_forced": self.forced,
                "candidates": [{"address": self._fmt(c), "locked": c == self.locked,
                                "probing": self.locked is None or c == self.locked,
                                "tx_counter": self.links[c].tx_counter,
                                "rx_counter": self.links[c].rx_counter}
                               for c in self.candidates],
                "peer_seen": f"{self.peer_seen[0]}:{self.peer_seen[1]}" if self.peer_seen else None,
                "forward": list(self.cfg.forward),
                "allow_radiate_control": self.cfg.allow_radiate_control,
                "radiate_control_feature": self.cfg.radiate_feature,
                "peer_kind": self.peer_kind(),
                "peer_is_real": self.peer_kind() == self.kind_real,
                "device_noun": self.noun,
                "tracks_out": self.tracks_out,
                "protocol_status": pstat,
                "owed_replies": {"waiting": len(self.owed), "answered": self.owed_answered,
                                 "missed": self.owed_missed},
                "local_seen_as": self.local_seen_as(),
                "peer_device_id": self.peer_device_id,
                "peer_sim_marker": self.peer_urn,
                "keepalive_interval_s": self.interval, "establish_after": self.establish_after,
                "device_id": self.device_id,
                "tx_counter": self.link.tx_counter, "rx_counter": self.link.rx_counter,
                "keepalives_rx": self.ka_rx_total, "keepalive_streak": self.ka_streak,
                "rx_datagrams": self.rx_datagrams, "tx_datagrams": self.tx_datagrams,
                "rx_messages": self.rx_messages,
                "multi_message_datagrams": self.multi_message_datagrams,
                "forward_mode": self.cfg.forward_mode,
                "notes": sorted(({"note": k, "count": v["count"],
                                  "messages": list(v["messages"]),
                                  "last_seen_age_s": age(v["last"])}
                                 for k, v in self.notes.items()),
                                key=lambda x: x["last_seen_age_s"]),
                "rx_bytes": self.rx_bytes, "tx_bytes": self.tx_bytes,
                "bad_datagrams": self.bad_datagrams, "foreign_datagrams": self.foreign_datagrams,
                "forwarded": self.forwarded, "forward_errors": self.forward_errors,
                "forward_socket_replaced": self.fwd_sock_replaced,
                "forward_targets": {f"{f[0]}:{f[1]}": {
                    "errors": st["errors"], "last_error": st["last_error"],
                    "refusing_for_s": round(now - st["refused_since"], 1)
                    if st["refused_since"] is not None else None,
                    "last_ok_age_s": age(st["last_ok"])} for f, st in self.fwd_state.items()},
                "send_errors": self.send_errors,
                "last_rx_age_s": age(self.last_rx), "last_tx_age_s": age(self.last_tx),
                "last_keepalive_rx_age_s": age(self.last_ka_rx),
                "rx_by_name": dict(self.rx_by_name), "tx_by_name": dict(self.tx_by_name),
                "actions": acts,
                "problems": sorted(({"problem": k, "count": v["count"],
                                     "messages": list(v.get("messages", [])),
                                     "last_seen_age_s": age(v["last"]),
                                     "first_seen_age_s": age(v["first"])}
                                    for k, v in self.problems.items()),
                                   key=lambda x: x["last_seen_age_s"]),
                "peer_request": self._peer_request_status(age),
                "peer_status": dict(self.peer_status, age_s=age(self.peer_status_at))
                if self.peer_status else None,
            }
            if events:
                out["events"] = list(self.events)[-events:]
            return out

    def _peer_request_status(self, age):
        if not self.peer_request:
            return None
        r = self.peer_requests[self.peer_request]
        mapping = getattr(self.protocol, "peer_request_actions", None) or {}
        wanted = mapping.get(r["code"])
        disabled = ("radiate control is disabled on this node"
                    if wanted and not self.cfg.radiate_feature
                    and self._is_radiate(wanted, self._all_actions().get(wanted)) else "")
        return {"label": self.peer_request, "code": r["code"], "count": r["count"],
                "last_seen_age_s": age(r["last"]),
                "suggested_action": self._suggested_action(r["code"]),
                "disabled_reason": disabled}

    def local_seen_as(self) -> str:
        """The address the sensor sees for us: the bound address, or (bound to 0.0.0.0) the
        source address the kernel picks toward the peer. A connected UDP socket sends nothing."""
        host, port = self.local
        if host not in ("0.0.0.0", "", "::"):
            return f"{host}:{port}"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(self.peer)
                return f"{s.getsockname()[0]}:{port}"
            finally:
                s.close()
        except OSError:
            return f"{host}:{port}"

    def get_events(self, n: int = 200) -> list:
        with self.lock:
            return list(self.events)[-max(0, n):]
