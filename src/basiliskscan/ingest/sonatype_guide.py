"""Cliente para consultas de vulnerabilidades na API da Sonatype Guide."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from .base import VulnerabilitySource
from .cache_manager import CacheManager
from .config import get_config


class SonatypeGuideClient(VulnerabilitySource):
    """Cliente de vulnerabilidades baseado na API Sonatype Guide (compatibilidade OSS Index)."""

    GUIDE_API_BASE = "https://api.guide.sonatype.com"
    LEGACY_API_BASE = "https://ossindex.sonatype.org/api/v3"

    ECOSYSTEM_MAP = {
        "npm": "npm",
        "ionic": "npm",
        "maven": "maven",
        "pypi": "pypi",
        "nuget": "nuget",
        "cargo": "cargo",
    }

    def __init__(
        self,
        username: Optional[str] = None,
        token: Optional[str] = None,
        cache_manager: Optional[CacheManager] = None,
        use_cache: bool = True,
    ):
        config = get_config()
        resolved_username, resolved_token = config.get_oss_index_credentials()

        self.username = (username or resolved_username or "").strip() or None
        self.token = (token or resolved_token or "").strip() or None

        super().__init__(api_key=None, cache_manager=cache_manager, use_cache=use_cache)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "BasiliskScan/0.0.1",
            }
        )

    def get_source_name(self) -> str:
        """Retorna o nome da fonte."""
        return "Sonatype Guide"

    def is_available(self) -> bool:
        """Considera disponível quando credenciais foram configuradas."""
        return bool(self.username and self.token)

    def fetch_vulnerabilities(
        self,
        component: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Busca vulnerabilidades para um componente por meio de component report."""
        if not self.username or not self.token:
            return []

        purl = self._build_purl(component, version, ecosystem)
        if not purl:
            return []

        guide_result = self._fetch_from_guide_api(purl, component)
        if guide_result is not None:
            self.last_updated = datetime.now()
            return guide_result

        legacy_result = self._fetch_from_legacy_api(purl)
        self.last_updated = datetime.now()
        return legacy_result

    def _fetch_from_guide_api(self, purl: str, component: str) -> Optional[List[Dict[str, Any]]]:
        """Consulta a Guide API oficial com autenticação Bearer."""
        if not self.token:
            return []

        try:
            response = self.session.get(
                f"{self.GUIDE_API_BASE}/components/vulnerabilities",
                params={"purl": purl},
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=30,
            )
        except requests.RequestException:
            return None

        if response.status_code in {401, 403, 404}:
            return None

        if response.status_code >= 400:
            return []

        payload = response.json() if response.content else {}
        hits = payload.get("hits", []) if isinstance(payload, dict) else []
        if not hits:
            return []

        vulnerabilities = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            vuln_id = str(hit.get("vulnId", "")).strip() or "UNKNOWN"
            aliases = hit.get("aliases") or []
            cve_alias = next((alias for alias in aliases if isinstance(alias, str) and alias.startswith("CVE-")), None)

            vulnerabilities.append(
                {
                    "id": vuln_id,
                    "cve": cve_alias if cve_alias else (vuln_id if vuln_id.startswith("CVE-") else None),
                    "title": vuln_id,
                    "description": hit.get("summary", ""),
                    "cvssScore": float(hit.get("cvssSeverity") or 0.0),
                    "cvssVector": "",
                    "reference": "",
                    "cwe": (hit.get("cwes") or [None])[0],
                }
            )

        if not vulnerabilities:
            return []

        return [
            {
                "coordinates": purl,
                "description": component,
                "vulnerabilities": vulnerabilities,
            }
        ]

    def _fetch_from_legacy_api(self, purl: str) -> List[Dict[str, Any]]:
        """Fallback para API legada OSS Index (Basic Auth)."""
        if not self.username or not self.token:
            return []

        try:
            response = self.session.post(
                f"{self.LEGACY_API_BASE}/component-report",
                json={"coordinates": [purl]},
                auth=(self.username, self.token),
                timeout=30,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException:
            return []

        reports: List[Dict[str, Any]]
        if isinstance(payload, list):
            reports = payload
        elif isinstance(payload, dict):
            reports = [payload]
        else:
            reports = []

        return [
            report
            for report in reports
            if isinstance(report, dict) and report.get("vulnerabilities")
        ]

    def _build_purl(self, component: str, version: Optional[str], ecosystem: Optional[str]) -> Optional[str]:
        normalized_ecosystem = self.ECOSYSTEM_MAP.get((ecosystem or "").strip().lower())
        if not normalized_ecosystem:
            return None

        name = (component or "").strip()
        if not name:
            return None

        if normalized_ecosystem == "maven":
            if ":" not in name:
                return None
            package_name = name
        else:
            package_name = name

        if version:
            return f"pkg:{normalized_ecosystem}/{package_name}@{version}"
        return f"pkg:{normalized_ecosystem}/{package_name}"
