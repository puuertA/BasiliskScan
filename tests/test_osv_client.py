"""Testes focados para o cliente OSV."""

import unittest

from basiliskscan.ingest.osv import OSVClient


class TestOSVClient(unittest.TestCase):
    """Valida comportamento de normalização do OSV."""

    def test_unknown_ecosystem_falls_back(self):
        client = OSVClient()

        self.assertIsNone(client._normalize_ecosystem("ant"))
        self.assertEqual(client._normalize_ecosystem("maven"), "Maven")


if __name__ == "__main__":
    unittest.main()