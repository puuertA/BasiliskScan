"""Parser para dependências Node.js (npm/yarn) - inclui Ionic."""

import json
import pathlib
from typing import Dict, List, Set, Tuple

from .base import BaseParser
from .purl import build_purl


# Seções de dependências do package.json
NPM_DEPENDENCY_SECTIONS = [
    "dependencies",
    "devDependencies", 
    "peerDependencies",
    "optionalDependencies"
]


class NodeJSParser(BaseParser):
    """Parser para arquivos package.json (Node.js, Ionic, React, etc.)."""
    
    def get_supported_files(self) -> List[str]:
        """Retorna lista de arquivos suportados."""
        return ["package.json", "package-lock.json", "npm-shrinkwrap.json"]
    
    def parse(self, path: pathlib.Path) -> List[Dict]:
        """
        Extrai dependências de um arquivo package.json.
        
        Args:
            path: Caminho para o arquivo package.json
            
        Returns:
            Lista de dicionários com informações das dependências
            
        Raises:
            json.JSONDecodeError: Se o arquivo não for um JSON válido
            FileNotFoundError: Se o arquivo não existir
        """
        data = self._load_json(path)

        if path.name == "package.json":
            return self._parse_package_json(path, data)

        if path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
            return self._parse_npm_lockfile(path, data)

        raise ValueError(f"Arquivo não suportado: {path.name}")

    def _load_json(self, path: pathlib.Path) -> Dict:
        """Carrega um arquivo JSON com tratamento de erro padronizado."""
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

    def _parse_package_json(self, path: pathlib.Path, data: Dict) -> List[Dict]:
        """Extrai dependências diretas de um package.json."""
        deps = []
        is_ionic = self._is_ionic_project(data)
        ecosystem = "ionic" if is_ionic else "npm"

        for section in NPM_DEPENDENCY_SECTIONS:
            items = data.get(section, {}) or {}
            for name, version_spec in items.items():
                deps.append({
                    "ecosystem": ecosystem,
                    "name": name,
                    "version_spec": version_spec,
                    "declared_in": str(path),
                    "section": section,
                    "dependency_type": "direct",
                    "is_transitive": False,
                    "purl": build_purl(ecosystem, name, version_spec),
                })

        return deps

    def _parse_npm_lockfile(self, path: pathlib.Path, data: Dict) -> List[Dict]:
        """Extrai dependências resolvidas (diretas e transitivas) de lockfiles npm."""
        root_dependency_names = self._collect_root_dependency_names(data)
        root_package = data.get("packages", {}).get("", {}) if isinstance(data.get("packages"), dict) else {}
        ecosystem = "ionic" if self._is_ionic_project(root_package) else "npm"

        package_entries = data.get("packages")
        if isinstance(package_entries, dict) and package_entries:
            return self._parse_lockfile_packages(path, package_entries, root_dependency_names, ecosystem)

        legacy_dependencies = data.get("dependencies")
        if isinstance(legacy_dependencies, dict):
            return self._parse_legacy_lock_dependencies(path, legacy_dependencies, root_dependency_names, ecosystem)

        return []

    def _collect_root_dependency_names(self, lock_data: Dict) -> Set[str]:
        """Coleta nomes de dependências diretas a partir da raiz do lockfile."""
        root_names: Set[str] = set()

        packages = lock_data.get("packages")
        if isinstance(packages, dict):
            root_package = packages.get("", {})
            if isinstance(root_package, dict):
                for section in NPM_DEPENDENCY_SECTIONS:
                    section_data = root_package.get(section, {})
                    if isinstance(section_data, dict):
                        root_names.update(section_data.keys())

        dependencies = lock_data.get("dependencies")
        if isinstance(dependencies, dict):
            root_names.update(dependencies.keys())

        return root_names

    def _parse_lockfile_packages(
        self,
        path: pathlib.Path,
        packages: Dict,
        root_dependency_names: Set[str],
        ecosystem: str,
    ) -> List[Dict]:
        """Processa lockfile npm v2+ (chave `packages`)."""
        deps: List[Dict] = []
        seen: Set[Tuple[str, str, str]] = set()

        for package_path, package_data in packages.items():
            if not package_path:
                continue

            name = self._extract_package_name_from_lock_path(package_path, package_data)
            if not name:
                continue

            version_spec = str(package_data.get("version", "")).strip() if isinstance(package_data, dict) else ""
            dependency_type = "direct" if name in root_dependency_names else "transitive"
            key = (name, version_spec, dependency_type)

            if key in seen:
                continue
            seen.add(key)

            deps.append({
                "ecosystem": ecosystem,
                "name": name,
                "version_spec": version_spec,
                "declared_in": str(path),
                "section": "lockfile",
                "dependency_type": dependency_type,
                "is_transitive": dependency_type == "transitive",
                "purl": build_purl(ecosystem, name, version_spec),
            })

        return deps

    def _extract_package_name_from_lock_path(self, package_path: str, package_data: Dict) -> str:
        """Extrai o nome do pacote a partir do caminho em `packages`."""
        if isinstance(package_data, dict):
            explicit_name = package_data.get("name")
            if isinstance(explicit_name, str) and explicit_name.strip():
                return explicit_name.strip()

        normalized_path = str(package_path).replace("\\", "/")
        marker = "node_modules/"
        if marker in normalized_path:
            return normalized_path.rsplit(marker, 1)[-1]

        return ""

    def _parse_legacy_lock_dependencies(
        self,
        path: pathlib.Path,
        dependencies: Dict,
        root_dependency_names: Set[str],
        ecosystem: str,
    ) -> List[Dict]:
        """Processa lockfile npm v1 (chave `dependencies`)."""
        deps: List[Dict] = []
        seen: Set[Tuple[str, str, str]] = set()

        def walk(items: Dict, depth: int) -> None:
            for name, metadata in items.items():
                if not isinstance(metadata, dict):
                    continue

                version_spec = str(metadata.get("version", "")).strip()
                is_direct = depth == 0 and name in root_dependency_names
                dependency_type = "direct" if is_direct else "transitive"
                key = (name, version_spec, dependency_type)

                if key not in seen:
                    seen.add(key)
                    deps.append({
                        "ecosystem": ecosystem,
                        "name": name,
                        "version_spec": version_spec,
                        "declared_in": str(path),
                        "section": "lockfile",
                        "dependency_type": dependency_type,
                        "is_transitive": dependency_type == "transitive",
                        "purl": build_purl(ecosystem, name, version_spec),
                    })

                nested = metadata.get("dependencies")
                if isinstance(nested, dict) and nested:
                    walk(nested, depth + 1)

        walk(dependencies, depth=0)
        return deps
    
    def _is_ionic_project(self, package_data: Dict) -> bool:
        """
        Verifica se o projeto é baseado em Ionic.
        
        Args:
            package_data: Dados do package.json
            
        Returns:
            True se for projeto Ionic, False caso contrário
        """
        # Verifica dependências do Ionic
        all_deps = {}
        for section in NPM_DEPENDENCY_SECTIONS:
            all_deps.update(package_data.get(section, {}))
        
        ionic_indicators = [
            "@ionic/angular",
            "@ionic/react", 
            "@ionic/vue",
            "ionic-angular",
            "@ionic/core"
        ]
        
        return any(indicator in all_deps for indicator in ionic_indicators)