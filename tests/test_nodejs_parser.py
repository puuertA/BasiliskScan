"""Testes para o parser de dependências Node.js."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from basiliskscan.parsers.nodejs import NodeJSParser


class TestNodeJSParser(unittest.TestCase):
    """Valida extração de dependências diretas e transitivas em projetos Node."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.parser = NodeJSParser()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_parse_package_json_generates_direct_dependencies_with_purl(self):
        package_file = self.temp_dir / "package.json"
        package_file.write_text(
            json.dumps(
                {
                    "dependencies": {
                        "express": "^4.19.2",
                        "@types/node": "20.11.0",
                    },
                    "devDependencies": {
                        "vitest": "1.6.0",
                    },
                }
            ),
            encoding="utf-8",
        )

        dependencies = self.parser.parse(package_file)

        self.assertEqual(len(dependencies), 3)
        express = next(dep for dep in dependencies if dep["name"] == "express")
        scoped = next(dep for dep in dependencies if dep["name"] == "@types/node")

        self.assertEqual(express["dependency_type"], "direct")
        self.assertFalse(express["is_transitive"])
        self.assertEqual(express["purl"], "pkg:npm/express@4.19.2")
        self.assertEqual(scoped["purl"], "pkg:npm/%40types/node@20.11.0")

    def test_parse_package_lock_marks_direct_and_transitive_dependencies(self):
        lock_file = self.temp_dir / "package-lock.json"
        lock_file.write_text(
            json.dumps(
                {
                    "name": "demo",
                    "lockfileVersion": 2,
                    "packages": {
                        "": {
                            "dependencies": {
                                "express": "^4.19.2",
                            }
                        },
                        "node_modules/express": {
                            "version": "4.19.2",
                        },
                        "node_modules/body-parser": {
                            "version": "1.20.2",
                        },
                    },
                }
            ),
            encoding="utf-8",
        )

        dependencies = self.parser.parse(lock_file)

        self.assertEqual(len(dependencies), 2)
        express = next(dep for dep in dependencies if dep["name"] == "express")
        body_parser = next(dep for dep in dependencies if dep["name"] == "body-parser")

        self.assertEqual(express["dependency_type"], "direct")
        self.assertFalse(express["is_transitive"])
        self.assertEqual(express["purl"], "pkg:npm/express@4.19.2")

        self.assertEqual(body_parser["dependency_type"], "transitive")
        self.assertTrue(body_parser["is_transitive"])
        self.assertEqual(body_parser["purl"], "pkg:npm/body-parser@1.20.2")


if __name__ == "__main__":
    unittest.main()
