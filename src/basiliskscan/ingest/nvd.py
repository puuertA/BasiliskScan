"""Cliente para a API 2.0 do NVD."""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests
from packaging.version import InvalidVersion, Version

from .base import VulnerabilitySource
from .cache_manager import CacheManager
from .config import get_config


class NVDClient(VulnerabilitySource):
    """Cliente para consultas de CVEs no National Vulnerability Database."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    REQUEST_INTERVAL_WITH_KEY = 0.6
    REQUEST_INTERVAL_WITHOUT_KEY = 6.0
    DEFAULT_RESULTS_PER_PAGE = 50

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_manager: Optional[CacheManager] = None,
        use_cache: bool = True,
    ):
        resolved_api_key = api_key or get_config().get_nvd_api_key()
        super().__init__(resolved_api_key, cache_manager, use_cache)
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})

        self.request_interval = (
            self.REQUEST_INTERVAL_WITH_KEY if self.api_key else self.REQUEST_INTERVAL_WITHOUT_KEY
        )
        self._last_request_ts = 0.0

    def get_source_name(self) -> str:
        """Retorna o nome da fonte."""
        return "NVD"

    def fetch_vulnerabilities(
        self,
        component: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Busca vulnerabilidades no NVD por componente, com filtro adicional por versão."""
        params = {
            "keywordSearch": component,
            "resultsPerPage": self.DEFAULT_RESULTS_PER_PAGE,
        }

        data = self._request(params)
        vulnerabilities = data.get("vulnerabilities", [])

        filtered = [
            entry
            for entry in vulnerabilities
            if self._matches_component(entry, component, ecosystem)
            and self._matches_version(entry, version)
            and self._matches_ecosystem(entry, ecosystem)
        ]

        self.last_updated = datetime.now(timezone.utc)
        return filtered

    def fetch_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Busca um CVE específico no NVD."""
        data = self._request({"cveId": cve_id})
        vulnerabilities = data.get("vulnerabilities", [])
        return vulnerabilities[0] if vulnerabilities else None

    def fetch_recent_vulnerabilities(self, days: int = 7) -> List[Dict[str, Any]]:
        """Busca CVEs modificados recentemente."""
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        data = self._request(
            {
                "lastModStartDate": start_date.isoformat(timespec="seconds"),
                "lastModEndDate": end_date.isoformat(timespec="seconds"),
                "resultsPerPage": self.DEFAULT_RESULTS_PER_PAGE,
            }
        )
        self.last_updated = end_date
        return data.get("vulnerabilities", [])

    def is_available(self) -> bool:
        """Verifica se a API do NVD está acessível."""
        try:
            self._request({"resultsPerPage": 1}, timeout=5)
            return True
        except Exception:
            return False

    def _request(self, params: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
        self._respect_rate_limit()
        response = self.session.get(self.NVD_API_BASE, params=params, timeout=timeout)
        response.raise_for_status()
        return response.json()

    def _respect_rate_limit(self):
        elapsed = time.monotonic() - self._last_request_ts
        remaining = self.request_interval - elapsed
        if remaining > 0:
            time.sleep(remaining)
        self._last_request_ts = time.monotonic()

    def _matches_component(self, entry: Dict[str, Any], component: str, ecosystem: Optional[str]) -> bool:
        component_tokens = self._extract_component_tokens(component)
        if not component_tokens:
            return True

        cpe_matches = self._iter_cpe_matches(entry)
        if cpe_matches:
            for cpe_match in cpe_matches:
                if self._cpe_matches_component(cpe_match, component_tokens):
                    return True
            return False

        for candidate in self._collect_searchable_text(entry):
            if self._text_matches_component(candidate, component_tokens, component, ecosystem):
                return True

        return False

    def _matches_ecosystem(self, entry: Dict[str, Any], ecosystem: Optional[str]) -> bool:
        if not ecosystem:
            return True

        ecosystem_token = ecosystem.lower().strip()
        if not ecosystem_token:
            return True

        searchable = " ".join(self._collect_searchable_text(entry))
        ecosystem_hints = {
            "npm": ["npm", "node.js", "nodejs"],
            "maven": ["maven", "java", "apache"],
            "pypi": ["python", "pypi"],
        }

        for hint in ecosystem_hints.get(ecosystem_token, [ecosystem_token]):
            if hint in searchable:
                return True

        return True

    def _matches_version(self, entry: Dict[str, Any], version: Optional[str]) -> bool:
        if not version:
            return True

        for cpe_match in self._iter_cpe_matches(entry):
            if self._version_matches_cpe(version, cpe_match):
                return True

        searchable = " ".join(self._collect_searchable_text(entry))
        return version.lower() in searchable

    def _collect_searchable_text(self, entry: Dict[str, Any]) -> List[str]:
        cve = entry.get("cve", {})
        descriptions = [
            item.get("value", "").lower()
            for item in cve.get("descriptions", [])
            if item.get("value")
        ]
        references = [
            item.get("url", "").lower()
            for item in cve.get("references", [])
            if item.get("url")
        ]
        cpes = [
            item.get("criteria", "").lower()
            for item in self._iter_cpe_matches(entry)
            if item.get("criteria")
        ]
        return descriptions + references + cpes

    def _cpe_matches_component(self, cpe_match: Dict[str, Any], component_tokens: set[str]) -> bool:
        criteria = cpe_match.get("criteria", "")
        cpe_fields = self._extract_cpe_fields(criteria)
        if not cpe_fields:
            return False

        product_tokens = self._tokenize(cpe_fields.get("product", ""))
        vendor_tokens = self._tokenize(cpe_fields.get("vendor", ""))

        if product_tokens and product_tokens.issubset(component_tokens):
            return True

        combined_tokens = vendor_tokens | product_tokens
        if combined_tokens and combined_tokens.issubset(component_tokens):
            return True

        return False

    def _text_matches_component(
        self,
        candidate: str,
        component_tokens: set[str],
        component: str,
        ecosystem: Optional[str],
    ) -> bool:
        normalized_candidate = self._normalize_text(candidate)
        primary_name = self._primary_component_name(component)

        if not normalized_candidate or not primary_name:
            return False

        exact_pattern = rf"(?<![a-z0-9]){re.escape(primary_name)}(?![a-z0-9])"
        ecosystem_token = (ecosystem or "").lower().strip()

        if ecosystem_token in {"npm", "pypi"}:
            package_patterns = [
                rf"\bpackage\s+{re.escape(primary_name)}\b",
                rf"\bmodule\s+{re.escape(primary_name)}\b",
                rf"\blibrary\s+{re.escape(primary_name)}\b",
                rf"/{re.escape(primary_name)}(?:/|$)",
                rf"\b{re.escape(primary_name)}\s+package\b",
            ]
            return any(re.search(pattern, normalized_candidate) for pattern in package_patterns)

        if re.search(exact_pattern, normalized_candidate):
            candidate_tokens = self._tokenize(normalized_candidate)
            return component_tokens.issuperset(candidate_tokens) or candidate_tokens.issuperset(component_tokens)

        return False

    def _iter_cpe_matches(self, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        cve = entry.get("cve", {})
        configurations = cve.get("configurations", [])
        collected: List[Dict[str, Any]] = []

        def visit_nodes(nodes: List[Dict[str, Any]]):
            for node in nodes:
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", True):
                        collected.append(cpe_match)
                visit_nodes(node.get("children", []))

        for config in configurations:
            visit_nodes(config.get("nodes", []))

        return collected

    def _version_matches_cpe(self, version: str, cpe_match: Dict[str, Any]) -> bool:
        criteria = cpe_match.get("criteria", "")
        criteria_version = self._extract_version_from_cpe(criteria)
        if criteria_version and criteria_version not in {"*", "-"} and criteria_version == version:
            return True

        lower_inclusive = cpe_match.get("versionStartIncluding")
        lower_exclusive = cpe_match.get("versionStartExcluding")
        upper_inclusive = cpe_match.get("versionEndIncluding")
        upper_exclusive = cpe_match.get("versionEndExcluding")

        if not any([lower_inclusive, lower_exclusive, upper_inclusive, upper_exclusive]):
            return criteria_version in {None, "*", "-"}

        if lower_inclusive and self._compare_versions(version, lower_inclusive) < 0:
            return False
        if lower_exclusive and self._compare_versions(version, lower_exclusive) <= 0:
            return False
        if upper_inclusive and self._compare_versions(version, upper_inclusive) > 0:
            return False
        if upper_exclusive and self._compare_versions(version, upper_exclusive) >= 0:
            return False

        return True

    @staticmethod
    def _extract_component_tokens(component: str) -> set[str]:
        if not component:
            return set()

        normalized = component.replace(":", " ").replace("/", " ")
        return NVDClient._tokenize(normalized)

    @staticmethod
    def _primary_component_name(component: str) -> str:
        normalized = component.strip().lower()
        if ":" in normalized:
            normalized = normalized.split(":")[-1]
        if "/" in normalized:
            normalized = normalized.split("/")[-1]
        return NVDClient._normalize_text(normalized)

    @staticmethod
    def _extract_cpe_fields(criteria: str) -> Optional[Dict[str, str]]:
        parts = criteria.split(":")
        if len(parts) < 6:
            return None

        return {
            "part": parts[2],
            "vendor": parts[3],
            "product": parts[4],
            "version": parts[5],
        }

    @staticmethod
    def _normalize_text(value: str) -> str:
        lowered = value.lower().replace("_", " ").replace("-", " ")
        lowered = re.sub(r"[^a-z0-9\s./]", " ", lowered)
        return re.sub(r"\s+", " ", lowered).strip()

    @staticmethod
    def _tokenize(value: str) -> set[str]:
        normalized = NVDClient._normalize_text(value)
        return {token for token in normalized.split() if token}

    @staticmethod
    def _extract_version_from_cpe(criteria: str) -> Optional[str]:
        parts = criteria.split(":")
        return parts[5] if len(parts) > 5 else None

    @staticmethod
    def _compare_versions(left: str, right: str) -> int:
        try:
            left_version = Version(left)
            right_version = Version(right)
            return (left_version > right_version) - (left_version < right_version)
        except InvalidVersion:
            left_parts = [int(part) if part.isdigit() else part for part in re.split(r"[._\-]", left)]
            right_parts = [int(part) if part.isdigit() else part for part in re.split(r"[._\-]", right)]

            max_len = max(len(left_parts), len(right_parts))
            left_parts.extend([0] * (max_len - len(left_parts)))
            right_parts.extend([0] * (max_len - len(right_parts)))

            for left_part, right_part in zip(left_parts, right_parts):
                if left_part == right_part:
                    continue
                return (left_part > right_part) - (left_part < right_part)

            return 0