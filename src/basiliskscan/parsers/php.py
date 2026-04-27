"""Parser para dependências PHP via Composer."""

import json
import pathlib
from typing import Dict, List, Set

from .base import BaseParser
from .purl import build_purl


COMPOSER_SECTIONS = ["require", "require-dev"]


class PHPParser(BaseParser):
    """Parser para arquivos composer.json e composer.lock."""

    def get_supported_files(self) -> List[str]:
        return ["composer.json", "composer.lock"]

    def parse(self, path: pathlib.Path) -> List[Dict]:
        data = self._load_json(path)

        if path.name == "composer.json":
            return self._parse_composer_json(path, data)

        if path.name == "composer.lock":
            return self._parse_composer_lock(path, data)

        raise ValueError(f"Arquivo não suportado: {path.name}")

    def _load_json(self, path: pathlib.Path) -> Dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(
                f"Erro ao fazer parse do JSON em {path}: {e}",
                e.doc,
                e.pos,
            )
        except FileNotFoundError:
            raise FileNotFoundError(f"Arquivo não encontrado: {path}")

    def _parse_composer_json(self, path: pathlib.Path, data: Dict) -> List[Dict]:
        deps: List[Dict] = []

        for section in COMPOSER_SECTIONS:
            section_data = data.get(section) or {}
            if not isinstance(section_data, dict):
                continue

            for name, version_spec in section_data.items():
                if not name or name == "php":
                    continue
                deps.append({
                    "ecosystem": "composer",
                    "name": name,
                    "version_spec": str(version_spec) if version_spec is not None else None,
                    "declared_in": str(path),
                    "section": section,
                    "dependency_type": "direct",
                    "is_transitive": False,
                    "purl": build_purl("composer", name, version_spec),
                })

        return deps

    def _parse_composer_lock(self, path: pathlib.Path, data: Dict) -> List[Dict]:
        deps: List[Dict] = []
        root_names = self._collect_root_dependency_names(path.parent)

        for section_key in ("packages", "packages-dev"):
            packages = data.get(section_key) or []
            if not isinstance(packages, list):
                continue

            for package in packages:
                if not isinstance(package, dict):
                    continue

                name = str(package.get("name", "") or "").strip()
                if not name:
                    continue

                version_spec = str(package.get("version", "") or "").strip()
                dependency_type = "direct" if name in root_names else "transitive"

                deps.append({
                    "ecosystem": "composer",
                    "name": name,
                    "version_spec": version_spec or None,
                    "declared_in": str(path),
                    "section": "lockfile",
                    "dependency_type": dependency_type,
                    "is_transitive": dependency_type == "transitive",
                    "purl": build_purl("composer", name, version_spec),
                })

        return deps

    def _collect_root_dependency_names(self, project_root: pathlib.Path) -> Set[str]:
        composer_json = project_root / "composer.json"
        if not composer_json.exists():
            return set()

        try:
            data = json.loads(composer_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return set()

        root_names: Set[str] = set()
        for section in COMPOSER_SECTIONS:
            section_data = data.get(section) or {}
            if not isinstance(section_data, dict):
                continue
            root_names.update(
                name for name in section_data.keys() if name and name != "php"
            )

        return root_names