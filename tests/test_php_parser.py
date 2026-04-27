"""Testes para o parser PHP (Composer)."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from basiliskscan.parsers.php import PHPParser


class TestPHPParser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.parser = PHPParser()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_parse_composer_json(self):
        composer_file = self.temp_dir / "composer.json"
        composer_file.write_text(
            json.dumps(
                {
                    "require": {
                        "php": ">=7.4",
                        "monolog/monolog": "^2.0",
                        "guzzlehttp/guzzle": "7.0.*",
                    },
                    "require-dev": {
                        "phpunit/phpunit": "^9.0"
                    },
                }
            ),
            encoding="utf-8",
        )

        dependencies = self.parser.parse(composer_file)

        self.assertEqual(len(dependencies), 3)
        names = {dep["name"] for dep in dependencies}
        self.assertIn("monolog/monolog", names)
        self.assertIn("guzzlehttp/guzzle", names)
        self.assertIn("phpunit/phpunit", names)
        self.assertTrue(all(dep["ecosystem"] == "composer" for dep in dependencies))

    def test_parse_composer_lock_marks_transitive(self):
        (self.temp_dir / "composer.json").write_text(
            json.dumps(
                {
                    "require": {
                        "monolog/monolog": "^2.0"
                    }
                }
            ),
            encoding="utf-8",
        )

        lock_file = self.temp_dir / "composer.lock"
        lock_file.write_text(
            json.dumps(
                {
                    "packages": [
                        {"name": "monolog/monolog", "version": "2.9.1"},
                        {"name": "psr/log", "version": "1.1.4"},
                    ],
                    "packages-dev": [
                        {"name": "phpunit/phpunit", "version": "9.6.0"}
                    ],
                }
            ),
            encoding="utf-8",
        )

        dependencies = self.parser.parse(lock_file)
        direct = next(dep for dep in dependencies if dep["name"] == "monolog/monolog")
        transitive = next(dep for dep in dependencies if dep["name"] == "psr/log")

        self.assertEqual(direct["dependency_type"], "direct")
        self.assertFalse(direct["is_transitive"])
        self.assertEqual(transitive["dependency_type"], "transitive")
        self.assertTrue(transitive["is_transitive"])


if __name__ == "__main__":
    unittest.main()
