"""The conformance kit against the open toy protocol (the kit's own self-test)."""

import unittest

from scapegoat.conformance import ProtocolConformance
from scapegoat.core.protocol import load_protocol


class TestToyConformance(ProtocolConformance, unittest.TestCase):
    def make_protocol(self):
        return load_protocol("toy", {})


if __name__ == "__main__":
    unittest.main()
