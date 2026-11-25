"""A tiny fake protocol and fake sensor for core tests (no protocol plugin needed).

Wire format: b"KA" + tx(2) + rx(2) + action(1) + sum(1)  -> keepalive
             b"DT" + payload                              -> data (no reply)
"""

import socket
import struct
import threading
import time

from scapegoat.core.protocol import ActionSpec, Decoded, Protocol


def _ka(tx, rx, action):
    body = b"KA" + struct.pack(">HHB", tx, rx, action)
    return body + bytes([sum(body) % 256])


class FakeProtocol(Protocol):
    name = "fake"
    default_port = 0
    keepalive_interval_s = 0.2
    # Core hooks, exercised by the core tests.
    peer_request_field = "request"
    peer_request_actions = {7: "radiate_on"}
    peer_status_fields = ("sensor_status",)
    radiate_actions = frozenset({"radiate_on", "radiate_off"})
    sim_marker = ("sim_tag", 0xFFFFFF)

    def keepalive(self, link, action=0):
        return _ka(link.next_tx(), link.rx_counter, action)

    def decode(self, d):
        if len(d) == 8 and d[:2] == b"KA":
            tx, rx, act = struct.unpack(">HHB", d[2:7])
            ok = sum(d[:7]) % 256 == d[7]
            return Decoded("KeepAlive", {"tx": tx, "rx": rx, "action": act}, ok,
                           [] if ok else ["bad checksum"], True, tx)
        if d[:2] == b"DT":
            return Decoded("Data", {"payload": d[2:]}, True, [], False, None)
        return Decoded("unknown", {}, False, ["unknown message"], False, None)

    def on_receive(self, link, msg):
        if msg.is_keepalive and msg.fields.get("action") == 2:
            return [self.keepalive(link)]
        return []

    def actions(self):
        return {
            "keepalive_now": ActionSpec("keepalive_now", "Send keepalive now", False, "KA"),
            "request_keepalive": ActionSpec("request_keepalive", "Request KA", False, "KA 2"),
            "radiate_on": ActionSpec("radiate_on", "Radiate ON", True, "KA 8"),
        }

    def build_action(self, link, name):
        return self.keepalive(link, {"keepalive_now": 0, "request_keepalive": 2,
                                     "radiate_on": 8}[name])


class FakeSensor:
    """Waits for a keepalive, then answers the sender's address every interval."""

    def __init__(self, interval=0.2):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.interval = interval
        self.silent = False
        self.peer = None
        self.received = []
        self.tx = 0
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._t.start()
        return self

    def stop(self):
        self._stop.set()
        self._t.join(1)
        self.sock.close()

    def send(self, data):
        if self.peer:
            self.sock.sendto(data, self.peer)

    def _run(self):
        nxt = 0
        while not self._stop.is_set():
            try:
                d, a = self.sock.recvfrom(2048)
                self.received.append(d)
                self.peer = a
            except (socket.timeout, OSError):
                pass
            now = time.monotonic()
            if self.peer and not self.silent and now >= nxt:
                self.tx += 1
                self.sock.sendto(_ka(self.tx, 0, 0), self.peer)
                nxt = now + self.interval
