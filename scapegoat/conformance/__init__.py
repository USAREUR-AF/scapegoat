"""Protocol plugin conformance kit.

Checks any scapegoat Protocol (built-in or plugin) against the contract the core relies
on, without knowing anything about the protocol's message layouts:

    from scapegoat.conformance import ProtocolConformance

    class TestMine(ProtocolConformance, unittest.TestCase):
        def make_protocol(self):
            return load_protocol("mine", {...settings...})

Checks: decode never raises (seeded fuzz), a keepalive decodes as a keepalive carrying our
transmit counter, the transmit counter wraps 65535 -> 1, every action has a name and label
and every non-dangerous action builds bytes, on_receive returns a list of bytes, split()
(when defined) returns two concatenated keepalives as two messages, summarize() returns a
string, and every optional hook has the type the core expects.
"""

from .kit import ProtocolConformance  # noqa: F401
