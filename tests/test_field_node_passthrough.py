"""field-node-passthrough: each datagram from the allowed sender is PUT unchanged; others dropped."""

import http.server
import os
import socket
import subprocess
import sys
import threading
import time
import unittest

from tests.field_node_harness import FIELD
from tests.helpers import free_udp_port, wait_for


class Sink(http.server.BaseHTTPRequestHandler):
    got = []

    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0))
        Sink.got.append((self.path, self.headers.get("Content-Type"), self.rfile.read(n)))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):
        pass


class TestPassthrough(unittest.TestCase):
    def run_relay(self, source_cidr):
        Sink.got = []
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sink)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        port = free_udp_port()
        env = dict(os.environ, PT_BIND="127.0.0.1", PT_PORT=str(port), PT_SOURCE_CIDR=source_cidr,
                   PT_KEY="radar/asterix/node-a", PT_CONTENT_TYPE="application/octet-stream",
                   PT_ISLAND_REST=f"http://127.0.0.1:{srv.server_address[1]}")
        p = subprocess.Popen([sys.executable, str(FIELD / "bin" / "field-node-passthrough")], env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(p.kill)
        time.sleep(0.5)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(s.close)
        blocks = [bytes([0x3E, 0x00, 0x05, 0x01, 0x02]), bytes([0x30, 0x00, 0x04, 0xFF])]
        for b in blocks:
            s.sendto(b, ("127.0.0.1", port))
        return blocks

    def test_publish_unchanged(self):
        blocks = self.run_relay("127.0.0.1/32")
        self.assertTrue(wait_for(lambda: len(Sink.got) == 2, 5))
        self.assertEqual([g[2] for g in Sink.got], blocks)
        self.assertEqual({g[0] for g in Sink.got}, {"/radar/asterix/node-a"})
        self.assertEqual({g[1] for g in Sink.got}, {"application/octet-stream"})

    def test_other_senders_dropped(self):
        self.run_relay("203.0.113.9/32")
        time.sleep(1.0)
        self.assertEqual(Sink.got, [])


if __name__ == "__main__":
    unittest.main()
