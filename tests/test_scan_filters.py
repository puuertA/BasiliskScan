"""Testes para filtros de dependências usados no comando scan."""

import unittest

from basiliskscan.commands.scan import _filter_scan_dependencies, _is_transitive_dependency


class TestScanFilters(unittest.TestCase):
    """Valida a exclusão de dependências transitivas por padrão."""

    def test_is_transitive_dependency_by_flag(self):
        self.assertTrue(_is_transitive_dependency({"is_transitive": True}))
        self.assertFalse(_is_transitive_dependency({"is_transitive": False}))

    def test_is_transitive_dependency_by_type(self):
        self.assertTrue(_is_transitive_dependency({"dependency_type": "transitive"}))
        self.assertTrue(_is_transitive_dependency({"dependency_type": " Transitive "}))
        self.assertFalse(_is_transitive_dependency({"dependency_type": "direct"}))

    def test_filter_excludes_transitive_when_disabled(self):
        dependencies = [
            {"name": "express", "dependency_type": "direct", "is_transitive": False},
            {"name": "body-parser", "dependency_type": "transitive", "is_transitive": True},
            {"name": "lodash", "dependency_type": "direct"},
        ]

        filtered = _filter_scan_dependencies(dependencies, include_transitive=False)

        self.assertEqual([dep["name"] for dep in filtered], ["express", "lodash"])

    def test_filter_keeps_all_when_enabled(self):
        dependencies = [
            {"name": "express", "dependency_type": "direct"},
            {"name": "body-parser", "dependency_type": "transitive"},
        ]

        filtered = _filter_scan_dependencies(dependencies, include_transitive=True)

        self.assertEqual(len(filtered), 2)


if __name__ == "__main__":
    unittest.main()
