"""
Cliente para OSV (Open Source Vulnerabilities) API.
"""

import requests
from typing import List, Dict, Any, Optional
from datetime import datetime
from .base import VulnerabilitySource
from .cache_manager import CacheManager


class OSVClient(VulnerabilitySource):
    """Cliente para a API do OSV (Open Source Vulnerabilities)."""
    
    OSV_API_BASE = "https://api.osv.dev/v1"
    
    # Mapeamento de ecosistemas suportados pelo OSV
    ECOSYSTEM_MAP = {
        "npm": "npm",
        "maven": "Maven",
        "pypi": "PyPI",
        "go": "Go",
        "cargo": "crates.io",
        "rubygems": "RubyGems",
        "packagist": "Packagist",
        "nuget": "NuGet",
        "hex": "Hex",
        "pub": "Pub"
    }
    
    def __init__(
        self, 
        api_key: Optional[str] = None,
        cache_manager: Optional[CacheManager] = None,
        use_cache: bool = True
    ):
        """
        Inicializa o cliente OSV.
        
        Args:
            api_key: Não usado (OSV API é pública), mantido para compatibilidade
            cache_manager: Gerenciador de cache opcional
            use_cache: Se True, usa cache para otimizar consultas
        """
        super().__init__(api_key, cache_manager, use_cache)
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json"
        })
    
    def get_source_name(self) -> str:
        """Retorna o nome da fonte."""
        return "OSV"
    
    def _normalize_ecosystem(self, ecosystem: Optional[str]) -> Optional[str]:
        """
        Normaliza o nome do ecosistema para o formato OSV.
        
        Args:
            ecosystem: Nome do ecosistema
            
        Returns:
            Nome normalizado ou None
        """
        if not ecosystem:
            return None
        
        return self.ECOSYSTEM_MAP.get(ecosystem.lower(), ecosystem)
    
    def fetch_vulnerabilities(
        self, 
        component: str, 
        version: Optional[str] = None,
        ecosystem: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Busca vulnerabilidades no OSV para um componente.
        
        Args:
            component: Nome do componente (ex: 'lodash', 'log4j-core')
            version: Versão específica
            ecosystem: Ecosistema (npm, maven, pypi, etc.)
            
        Returns:
            Lista de vulnerabilidades encontradas
        """
        normalized_ecosystem = self._normalize_ecosystem(ecosystem)
        
        if not normalized_ecosystem:
            # Se não tiver ecosistema, tenta buscar por nome apenas (menos preciso)
            return self._query_by_component(component, version)
        
        # Busca usando package + ecosystem
        return self._query_by_package(component, version, normalized_ecosystem)
    
    def _query_by_package(
        self,
        name: str,
        version: Optional[str],
        ecosystem: str
    ) -> List[Dict[str, Any]]:
        """
        Busca vulnerabilidades usando o endpoint /query.
        
        Args:
            name: Nome do pacote
            version: Versão do pacote
            ecosystem: Ecosistema
            
        Returns:
            Lista de vulnerabilidades
        """
        url = f"{self.OSV_API_BASE}/query"
        
        payload = {
            "package": {
                "name": name,
                "ecosystem": ecosystem
            }
        }
        
        if version:
            payload["version"] = version
        
        try:
            response = self.session.post(url, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            self.last_updated = datetime.now()
            
            # OSV retorna {"vulns": [...]}
            vulnerabilities = data.get("vulns", [])
            
            # Para cada vulnerabilidade, busca detalhes completos
            detailed_vulns = []
            for vuln in vulnerabilities:
                vuln_id = vuln.get("id")
                if vuln_id:
                    details = self._get_vulnerability_details(vuln_id)
                    if details:
                        detailed_vulns.append(details)
            
            return detailed_vulns
            
        except requests.exceptions.RequestException as e:
            print(f"Erro ao buscar vulnerabilidades no OSV: {e}")
            return []
    
    def _query_by_component(
        self,
        component: str,
        version: Optional[str]
    ) -> List[Dict[str, Any]]:
        """
        Busca vulnerabilidades sem especificar ecosistema (menos preciso).
        
        Args:
            component: Nome do componente
            version: Versão
            
        Returns:
            Lista de vulnerabilidades
        """
        # OSV requer ecosistema para consultas precisas
        # Tentamos alguns ecosistemas comuns
        common_ecosystems = ["npm", "Maven", "PyPI"]
        all_vulns = []
        seen_ids = set()
        
        for ecosystem in common_ecosystems:
            vulns = self._query_by_package(component, version, ecosystem)
            for vuln in vulns:
                vuln_id = vuln.get("id")
                if vuln_id not in seen_ids:
                    seen_ids.add(vuln_id)
                    all_vulns.append(vuln)
        
        return all_vulns
    
    def _get_vulnerability_details(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """
        Busca detalhes completos de uma vulnerabilidade específica.
        
        Args:
            vuln_id: ID da vulnerabilidade (ex: 'GHSA-xxxx-xxxx-xxxx')
            
        Returns:
            Dicionário com detalhes da vulnerabilidade ou None
        """
        url = f"{self.OSV_API_BASE}/vulns/{vuln_id}"
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Erro ao buscar detalhes da vulnerabilidade {vuln_id}: {e}")
            return None
    
    def query_by_commit(self, commit_hash: str) -> List[Dict[str, Any]]:
        """
        Busca vulnerabilidades associadas a um commit específico.
        
        Args:
            commit_hash: Hash do commit
            
        Returns:
            Lista de vulnerabilidades
        """
        url = f"{self.OSV_API_BASE}/query"
        
        payload = {
            "commit": commit_hash
        }
        
        try:
            response = self.session.post(url, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulns", [])
            
            # Busca detalhes completos
            detailed_vulns = []
            for vuln in vulnerabilities:
                vuln_id = vuln.get("id")
                if vuln_id:
                    details = self._get_vulnerability_details(vuln_id)
                    if details:
                        detailed_vulns.append(details)
            
            return detailed_vulns
            
        except requests.exceptions.RequestException as e:
            print(f"Erro ao buscar vulnerabilidades por commit: {e}")
            return []
    
    def is_available(self) -> bool:
        """
        Verifica se a API do OSV está disponível.
        
        Returns:
            True se a API está acessível
        """
        try:
            response = self.session.get(f"{self.OSV_API_BASE}/vulns/GHSA-test", timeout=5)
            # A API retorna 404 para IDs inválidos, mas isso confirma que está up
            return True
        except:
            return False
