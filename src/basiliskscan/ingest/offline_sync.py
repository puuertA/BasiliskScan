"""Serviço de sincronização do banco offline com fontes online integradas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .aggregator import VulnerabilityAggregator
from .offline_db import OfflineVulnerabilityDB


class OfflineSyncService:
    """Coordena ingestão, atualização semanal e atualização forçada do banco offline."""

    def __init__(
        self,
        db: Optional[OfflineVulnerabilityDB] = None,
        aggregator: Optional[VulnerabilityAggregator] = None,
        refresh_interval_days: int = 7,
    ):
        self.db = db or OfflineVulnerabilityDB(refresh_interval_days=refresh_interval_days)
        self.aggregator = aggregator or VulnerabilityAggregator()
        self.refresh_interval_days = int(refresh_interval_days)

    def ingest_scan_results(
        self,
        components: List[Dict[str, Any]],
        vulnerabilities_by_name: Dict[str, List[Dict[str, Any]]],
    ) -> Dict[str, int]:
        """Persiste no banco offline os resultados já obtidos durante um scan online."""
        saved_components = 0
        saved_vulnerabilities = 0

        for component in components:
            name = str(component.get("name", "") or "").strip()
            if not name:
                continue

            version = component.get("version")
            ecosystem = component.get("ecosystem")
            vulns = vulnerabilities_by_name.get(name, [])
            self.db.save_component_vulnerabilities(
                name=name,
                version=version,
                ecosystem=ecosystem,
                vulnerabilities=vulns,
                refresh_interval_days=self.refresh_interval_days,
            )
            saved_components += 1
            saved_vulnerabilities += len(vulns)

        return {
            "saved_components": saved_components,
            "saved_vulnerabilities": saved_vulnerabilities,
        }

    def get_vulnerabilities_for_components(self, components: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Obtém vulnerabilidades somente do banco local para execução offline."""
        results: Dict[str, List[Dict[str, Any]]] = {}

        for component in components:
            name = str(component.get("name", "") or "").strip()
            if not name:
                continue

            version = component.get("version")
            ecosystem = component.get("ecosystem")
            results[name] = self.db.get_component_vulnerabilities(name, version, ecosystem)

        return results

    def sync_components(
        self,
        components: List[Dict[str, Any]],
        force: bool = False,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, int]:
        """Sincroniza componentes informados com APIs e grava no banco offline."""
        processed = 0
        synced = 0
        errors = 0
        total_vulns = 0

        for component in components:
            name = str(component.get("name", "") or "").strip()
            if not name:
                continue

            version = component.get("version")
            ecosystem = component.get("ecosystem")
            processed += 1

            try:
                vulns = self.aggregator.fetch_vulnerabilities(
                    component=name,
                    version=version,
                    ecosystem=ecosystem,
                    parallel=True,
                )
                self.db.save_component_vulnerabilities(
                    name=name,
                    version=version,
                    ecosystem=ecosystem,
                    vulnerabilities=vulns,
                    refresh_interval_days=self.refresh_interval_days,
                )
                synced += 1
                total_vulns += len(vulns)
            except Exception:
                errors += 1

            if progress_callback:
                progress_callback(name)

        if force:
            self.db.set_last_full_sync(datetime.now())

        return {
            "processed": processed,
            "synced": synced,
            "errors": errors,
            "total_vulnerabilities": total_vulns,
        }

    def sync_due_components(
        self,
        force: bool = False,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, int]:
        """Sincroniza componentes vencidos (ou todos, quando force=True)."""
        if force:
            components = self.db.get_all_components()
        else:
            components = self.db.get_components_due_for_sync()

        summary = self.sync_components(components=components, force=force, progress_callback=progress_callback)

        if summary["processed"] > 0 and (force or self.db.needs_weekly_sync(self.refresh_interval_days)):
            self.db.set_last_full_sync(datetime.now())

        return summary

    def run_weekly_auto_sync_if_needed(
        self,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Optional[Dict[str, int]]:
        """Executa atualização semanal automática quando necessário."""
        if not self.db.needs_weekly_sync(self.refresh_interval_days):
            return None

        return self.sync_due_components(force=False, progress_callback=progress_callback)

    def close(self):
        self.db.close()
