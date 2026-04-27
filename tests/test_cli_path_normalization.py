"""Testes para normalização de caminhos informados na CLI."""

import unittest
from pathlib import Path

from basiliskscan.ui import normalize_cli_directory_input


class TestCliPathNormalization(unittest.TestCase):
    def test_removes_unmatched_trailing_quote(self):
        raw_path = r'E:\Users\lucas\Downloads\project-main"'
        normalized = normalize_cli_directory_input(raw_path)

        expected = Path(r"E:\Users\lucas\Downloads\project-main").resolve()
        self.assertEqual(normalized, expected)

    def test_removes_wrapping_quotes(self):
        normalized = normalize_cli_directory_input('"./tests"')

        expected = Path("./tests").resolve()
        self.assertEqual(normalized, expected)


if __name__ == "__main__":
    unittest.main()
