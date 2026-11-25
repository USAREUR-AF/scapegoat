"""Simulator for the open `toy` protocol: a peer that waits to be spoken to first.

    scapegoat sim toy --bind 127.0.0.1:47001 --interval 3

Like the sensors scapegoat is built for, it sends nothing until a keepalive arrives. Then
it answers the sender's address and port every --interval seconds with a keepalive (flag
"simulator" set), and sends a data message every --data-every seconds. It answers a
keepalive that asks for one (action 2) at once. --silent-after N stops answering after N
seconds, to show a lost link.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time

from scapegoat.packages.toy import ASK_REPLY, SIMULATOR_FLAG, ToyProtocol, data_bytes, keepalive_bytes


class ToySim:
    def __init__(self, bind=("127.0.0.1", 47001), interval=3.0, data_every=5.0,
                 silent_after=None, out=sys.stdout):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(bind)
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.interval, self.data_every, self.silent_after = interval, data_every, silent_after
        self.proto = ToyProtocol({})
        self.peer = None
        self.tx = 0
        self.rx = 0
        self.sent = 0
        self.out = out
        self._stop = False

    def _next_tx(self):
        self.tx = self.tx + 1 if 0 < self.tx < 65535 else 1
        return self.tx

    def _ka(self, action=0):
        return keepalive_bytes(self._next_tx(), self.rx, action, SIMULATOR_FLAG)

    def say(self, text):
        if self.out:
            print(f"toy-sim: {text}", file=self.out, flush=True)

    def stop(self):
        self._stop = True

    def run(self, duration=None):
        start = time.monotonic()
        next_ka = next_data = 0.0
        self.say(f"listening on UDP {self.sock.getsockname()[0]}:{self.port}; silent until spoken to")
        while not self._stop:
            now = time.monotonic()
            if duration is not None and now - start >= duration:
                break
            silent = self.silent_after is not None and now - start >= self.silent_after
            try:
                d, addr = self.sock.recvfrom(2048)
                parts, _, _ = self.proto.split(d)
                for part in parts:
                    m = self.proto.decode(part)
                    if m.is_keepalive and m.ok:
                        if self.peer != addr:
                            self.say(f"first keepalive from {addr[0]}:{addr[1]}; answering there")
                        self.peer, self.rx = addr, m.peer_tx_counter or 0
                        if m.fields.get("ask") == ASK_REPLY and not silent:
                            self.sock.sendto(self._ka(), addr)
                            self.sent += 1
            except (socket.timeout, OSError):
                pass
            if self.peer and not silent:
                if now >= next_ka:
                    self.sock.sendto(self._ka(), self.peer)
                    self.sent += 1
                    next_ka = now + self.interval
                if self.data_every and now >= next_data:
                    self.sock.sendto(data_bytes(f"tick {self.sent}".encode()), self.peer)
                    next_data = now + self.data_every
        self.sock.close()


def _hostport(text):
    host, _, port = text.rpartition(":")
    return host or "127.0.0.1", int(port)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="scapegoat sim toy", description=__doc__.split("\n\n")[1])
    ap.add_argument("--bind", default="127.0.0.1:47001", help="address:port to listen on")
    ap.add_argument("--interval", type=float, default=3.0, help="seconds between keepalives")
    ap.add_argument("--data-every", type=float, default=5.0, help="seconds between data messages (0 = none)")
    ap.add_argument("--silent-after", type=float, default=None, help="stop answering after N seconds")
    ap.add_argument("--duration", type=float, default=None, help="exit after N seconds")
    a = ap.parse_args(argv)
    sim = ToySim(_hostport(a.bind), a.interval, a.data_every, a.silent_after)
    try:
        sim.run(a.duration)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
