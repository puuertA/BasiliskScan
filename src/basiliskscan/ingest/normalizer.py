"""
Normalizador de dados de vulnerabilidades de diferentes fontes.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum


class Severity(Enum):
    """Níveis de severidade padronizados."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class VulnerabilityNormalizer:
    """Normaliza dados de vulnerabilidades de diferentes fontes para um formato comum."""
    
    @staticmethod
    def normalize_nvd_vulnerability(nvd_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normaliza dados de vulnerabilidade do NVD para formato comum.
        
        Args:
            nvd_data: Dados brutos do NVD
            
        Returns:
            Dicionário normalizado
        """
        cve = nvd_data.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        
        # Extrai descrição
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Extrai métricas CVSS
        metrics = cve.get("metrics", {})
        cvss_data = {}
        severity = Severity.UNKNOWN.value
        score = 0.0
        
        # Tenta obter CVSS v3.1 primeiro, depois v3.0, depois v2.0
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                metric = metrics[version][0]
                cvss = metric.get("cvssData", {})
                cvss_data = {
                    "version": cvss.get("version", ""),
                    "vector": cvss.get("vectorString", ""),
                    "score": cvss.get("baseScore", 0.0),
                    "severity": cvss.get("baseSeverity", "UNKNOWN")
                }
                score = cvss_data["score"]
                severity = VulnerabilityNormalizer._normalize_severity(
                    cvss_data["severity"]
                )
                break
        
        # Extrai referências
        references = []
        for ref in cve.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", [])
            })
        
        # Extrai datas
        published = cve.get("published", "")
        modified = cve.get("lastModified", "")
        
        # Extrai CPEs (configurações afetadas)
        configurations = cve.get("configurations", [])
        affected_products = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        affected_products.append({
                            "cpe": cpe_match.get("criteria", ""),
                            "version_start": cpe_match.get("versionStartIncluding"),
                            "version_end": cpe_match.get("versionEndIncluding")
                        })
        
        # Extrai CWEs (tipos de fraqueza)
        weaknesses = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    weaknesses.append(desc.get("value", ""))
        
        return {
            "id": cve_id,
            "source": "NVD",
            "title": cve_id,  # NVD não tem título separado
            "description": description,
            "severity": severity,
            "cvss": cvss_data,
            "score": score,
            "published": published,
            "modified": modified,
            "references": references,
            "affected_products": affected_products,
            "cwe": weaknesses,
            "raw_data": nvd_data
        }
    
    @staticmethod
    def normalize_oss_index_vulnerability(
        oss_data: Dict[str, Any], 
        vulnerability: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Normaliza dados de vulnerabilidade do OSS Index para formato comum.
        
        Args:
            oss_data: Dados do componente do OSS Index
            vulnerability: Dados específicos da vulnerabilidade
            
        Returns:
            Dicionário normalizado
        """
        vuln_id = vulnerability.get("id", "UNKNOWN")
        cve = vulnerability.get("cve")
        title = vulnerability.get("title", "")
        description = vulnerability.get("description", "")
        
        # Extrai CVSS
        cvss_score = vulnerability.get("cvssScore", 0.0)
        cvss_vector = vulnerability.get("cvssVector", "")
        
        # Determina severidade baseado no score
        severity = VulnerabilityNormalizer._score_to_severity(cvss_score)
        
        cvss_data = {
            "score": cvss_score,
            "vector": cvss_vector,
            "severity": severity
        }
        
        # Extrai referências
        references = []
        if vulnerability.get("reference"):
            references.append({
                "url": vulnerability["reference"],
                "source": "OSS Index",
                "tags": []
            })
        
        # Extrai informações do componente
        component_info = {
            "purl": oss_data.get("coordinates", ""),
            "description": oss_data.get("description", "")
        }
        
        # CWE
        cwe_id = vulnerability.get("cwe")
        weaknesses = [cwe_id] if cwe_id else []
        
        return {
            "id": cve if cve else vuln_id,
            "source": "OSS Index",
            "title": title,
            "description": description,
            "severity": severity,
            "cvss": cvss_data,
            "score": cvss_score,
            "published": None,  # OSS Index não fornece data de publicação
            "modified": None,
            "references": references,
            "affected_products": [component_info],
            "cwe": weaknesses,
            "raw_data": {
                "component": oss_data,
                "vulnerability": vulnerability
            }
        }
    
    @staticmethod
    def normalize_oss_index_component(oss_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normaliza todas as vulnerabilidades de um componente do OSS Index.
        
        Args:
            oss_data: Dados do componente do OSS Index
            
        Returns:
            Lista de vulnerabilidades normalizadas
        """
        vulnerabilities = oss_data.get("vulnerabilities", [])
        normalized = []
        
        for vuln in vulnerabilities:
            normalized.append(
                VulnerabilityNormalizer.normalize_oss_index_vulnerability(
                    oss_data, vuln
                )
            )
        
        return normalized
    
    @staticmethod
    def normalize_osv_vulnerability(osv_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normaliza dados de vulnerabilidade do OSV para formato comum.
        
        Args:
            osv_data: Dados brutos do OSV
            
        Returns:
            Dicionário normalizado
        """
        vuln_id = osv_data.get("id", "UNKNOWN")
        
        # Extrai summary e details
        summary = osv_data.get("summary", "")
        details = osv_data.get("details", "")
        description = f"{summary}\n\n{details}" if summary and details else (summary or details)
        
        # Extrai aliases (CVEs relacionados)
        aliases = osv_data.get("aliases", [])
        cve_id = None
        for alias in aliases:
            if alias.startswith("CVE-"):
                cve_id = alias
                break
        
        # Extrai severidade do campo severity
        severity_data = osv_data.get("severity", [])
        score = 0.0
        severity = Severity.UNKNOWN.value
        cvss_data = {}
        
        for sev in severity_data:
            sev_type = sev.get("type")
            if sev_type == "CVSS_V3":
                score_str = sev.get("score")
                if score_str:
                    # Parse CVSS v3 vector string (ex: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
                    parts = score_str.split("/")
                    if parts:
                        # Extrai o score base do vector (não é direto, precisamos calcular ou buscar)
                        # OSV geralmente não fornece o score numérico direto
                        # Vamos usar os campos affected para inferir
                        pass
                cvss_data = {
                    "version": "3.1",
                    "vector": score_str,
                    "score": score
                }
            elif sev_type == "CVSS_V2":
                score_str = sev.get("score")
                cvss_data = {
                    "version": "2.0",
                    "vector": score_str,
                    "score": score
                }
        
        # Se não tiver score CVSS, tenta inferir da severidade textual
        database_specific = osv_data.get("database_specific", {})
        severity_text = database_specific.get("severity", "").upper()
        if severity_text:
            severity = VulnerabilityNormalizer._normalize_severity(severity_text)
        
        # Extrai referências
        references = []
        for ref in osv_data.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "source": "OSV",
                "tags": [ref.get("type", "")]
            })
        
        # Extrai datas
        published = osv_data.get("published", "")
        modified = osv_data.get("modified", "")
        
        # Extrai pacotes/produtos afetados
        affected_products = []
        for affected in osv_data.get("affected", []):
            package = affected.get("package", {})
            ecosystem = package.get("ecosystem", "")
            name = package.get("name", "")
            purl = package.get("purl", "")
            
            # Extrai versões afetadas
            ranges = affected.get("ranges", [])
            versions = affected.get("versions", [])
            
            affected_info = {
                "ecosystem": ecosystem,
                "name": name,
                "purl": purl,
                "versions": versions,
                "ranges": ranges
            }
            affected_products.append(affected_info)
        
        # Extrai CWEs do database_specific ou related
        weaknesses = []
        cwe_ids = database_specific.get("cwe_ids", [])
        if cwe_ids:
            weaknesses = cwe_ids
        
        # Se tiver CVE nos aliases, usa como ID primário
        primary_id = cve_id if cve_id else vuln_id
        
        return {
            "id": primary_id,
            "source": "OSV",
            "title": summary or vuln_id,
            "description": description,
            "severity": severity,
            "cvss": cvss_data,
            "score": score,
            "published": published,
            "modified": modified,
            "references": references,
            "affected_products": affected_products,
            "cwe": weaknesses,
            "aliases": aliases,
            "osv_id": vuln_id,
            "raw_data": osv_data
        }
    
    @staticmethod
    def _normalize_severity(severity_str: str) -> str:
        """
        Normaliza string de severidade para o enum padrão.
        
        Args:
            severity_str: String de severidade original
            
        Returns:
            Severidade normalizada
        """
        severity_upper = severity_str.upper()
        
        if severity_upper in ["CRITICAL", "CRITICAL +"]:
            return Severity.CRITICAL.value
        elif severity_upper in ["HIGH", "HIGH +"]:
            return Severity.HIGH.value
        elif severity_upper in ["MEDIUM", "MODERATE"]:
            return Severity.MEDIUM.value
        elif severity_upper in ["LOW", "LOW +"]:
            return Severity.LOW.value
        else:
            return Severity.UNKNOWN.value
    
    @staticmethod
    def _score_to_severity(score: float) -> str:
        """
        Converte score CVSS em severidade.
        
        Args:
            score: Score CVSS (0.0 - 10.0)
            
        Returns:
            Severidade
        """
        if score >= 9.0:
            return Severity.CRITICAL.value
        elif score >= 7.0:
            return Severity.HIGH.value
        elif score >= 4.0:
            return Severity.MEDIUM.value
        elif score > 0:
            return Severity.LOW.value
        else:
            return Severity.UNKNOWN.value
    
    @staticmethod
    def merge_vulnerabilities(
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Mescla vulnerabilidades de múltiplas fontes, removendo duplicatas.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades normalizadas
            
        Returns:
            Lista de vulnerabilidades mescladas
        """
        merged = {}
        
        for vuln in vulnerabilities:
            vuln_id = vuln.get("id")
            
            if vuln_id in merged:
                # Mescla informações de múltiplas fontes
                existing = merged[vuln_id]
                
                # Adiciona fontes
                sources = existing.get("sources", [existing["source"]])
                if vuln["source"] not in sources:
                    sources.append(vuln["source"])
                existing["sources"] = sources
                
                # Usa a severidade mais alta
                if VulnerabilityNormalizer._severity_level(vuln["severity"]) > \
                   VulnerabilityNormalizer._severity_level(existing["severity"]):
                    existing["severity"] = vuln["severity"]
                    existing["cvss"] = vuln["cvss"]
                    existing["score"] = vuln["score"]
                
                # Mescla referências
                existing_refs = {ref["url"] for ref in existing.get("references", [])}
                for ref in vuln.get("references", []):
                    if ref["url"] not in existing_refs:
                        existing["references"].append(ref)
                
                # Mescla produtos afetados
                existing["affected_products"].extend(vuln.get("affected_products", []))
                
            else:
                # Nova vulnerabilidade
                merged[vuln_id] = vuln.copy()
                merged[vuln_id]["sources"] = [vuln["source"]]
        
        return list(merged.values())
    
    @staticmethod
    def _severity_level(severity: str) -> int:
        """Retorna nível numérico da severidade para comparação."""
        severity_levels = {
            Severity.CRITICAL.value: 4,
            Severity.HIGH.value: 3,
            Severity.MEDIUM.value: 2,
            Severity.LOW.value: 1,
            Severity.UNKNOWN.value: 0
        }
        return severity_levels.get(severity, 0)
