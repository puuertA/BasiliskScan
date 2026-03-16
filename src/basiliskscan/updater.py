"""Serviço para descoberta de versões mais recentes de dependências."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from urllib.parse import quote

import requests


class DependencyUpdateService:
    """Consulta versões mais recentes para dependências suportadas."""

    def __init__(self, timeout_seconds: int = 6, max_workers: int = 8):
        self.timeout_seconds = timeout_seconds
        self.max_workers = max_workers
        self.session = requests.Session()
        self._cache: Dict[str, Optional[str]] = {}

    def enrich_with_latest_versions(self, dependencies: List[Dict]) -> List[Dict]:
        """Preenche `latest_version` nas dependências quando possível."""
        candidates = [
            dep for dep in dependencies
            if dep.get("ecosystem") in {"npm", "ionic"} and dep.get("name")
        ]

        if not candidates:
            return dependencies

        unique_names = sorted({dep["name"] for dep in candidates})

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(unique_names))) as executor:
            futures = {
                executor.submit(self._get_latest_npm_version, package_name): package_name
                for package_name in unique_names
            }

            for future in as_completed(futures):
                package_name = futures[future]
                try:
                    self._cache[package_name] = future.result()
                except Exception:
                    self._cache[package_name] = None

        for dep in candidates:
            latest = self._cache.get(dep["name"])
            if latest:
                dep["latest_version"] = latest

        return dependencies

    def _get_latest_npm_version(self, package_name: str) -> Optional[str]:
        """Obtém a versão mais recente de um pacote npm via registry."""
        if package_name in self._cache:
            return self._cache[package_name]

        package_encoded = quote(package_name, safe="")
        url = f"https://registry.npmjs.org/{package_encoded}/latest"

        try:
            response = self.session.get(url, timeout=self.timeout_seconds)
            response.raise_for_status()
            payload = response.json()
            latest = payload.get("version")
            return str(latest) if latest else None
        except Exception:
            return None
