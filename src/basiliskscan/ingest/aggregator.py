"""
Utilitários para agregação de vulnerabilidades de múltiplas fontes.
"""

from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from .osv import OSVClient
from .normalizer import VulnerabilityNormalizer
from .config import get_config


class VulnerabilityAggregator:
    """Agrega vulnerabilidades de múltiplas fontes."""
    
    def __init__(
        self,
        use_osv: bool = True
    ):
        """
        Inicializa o agregador.
        
        Args:
            use_osv: Usar OSV como fonte
        """
        self.sources = []
        
        if use_osv:
            self.sources.append(OSVClient())
    
    def fetch_vulnerabilities(
        self,
        component: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None,
        parallel: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Busca vulnerabilidades de todas as fontes configuradas.
        
        Args:
            component: Nome do componente
            version: Versão do componente
            ecosystem: Ecosistema (npm, maven, pypi, etc.)
            parallel: Executar buscas em paralelo
            
        Returns:
            Lista de vulnerabilidades normalizadas e mescladas
        """
        all_vulnerabilities = []
        
        if parallel:
            # Executa buscas em paralelo
            with ThreadPoolExecutor(max_workers=len(self.sources)) as executor:
                futures = {
                    executor.submit(
                        self._fetch_from_source,
                        source,
                        component,
                        version,
                        ecosystem
                    ): source
                    for source in self.sources
                }
                
                for future in as_completed(futures):
                    source = futures[future]
                    try:
                        vulns = future.result()
                        all_vulnerabilities.extend(vulns)
                    except Exception as e:
                        print(f"Erro ao buscar de {source.get_source_name()}: {e}")
        else:
            # Executa buscas sequencialmente
            for source in self.sources:
                try:
                    vulns = self._fetch_from_source(
                        source, component, version, ecosystem
                    )
                    all_vulnerabilities.extend(vulns)
                except Exception as e:
                    print(f"Erro ao buscar de {source.get_source_name()}: {e}")
        
        # Mescla vulnerabilidades de diferentes fontes
        return VulnerabilityNormalizer.merge_vulnerabilities(all_vulnerabilities)
    
    def _fetch_from_source(
        self,
        source,
        component: str,
        version: Optional[str],
        ecosystem: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Busca e normaliza vulnerabilidades de uma fonte específica."""
        raw_data = source.fetch_vulnerabilities(component, version, ecosystem)
        normalized = []
        
        if isinstance(source, OSVClient):
            for vuln_data in raw_data:
                normalized.append(
                    VulnerabilityNormalizer.normalize_osv_vulnerability(vuln_data)
                )
        
        return normalized
    
    def fetch_multiple_components(
        self,
        components: List[Dict[str, str]],
        parallel: bool = True
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Busca vulnerabilidades para múltiplos componentes.
        
        Args:
            components: Lista de dicionários com 'name', 'version' e 'ecosystem'
            parallel: Executar buscas em paralelo
            
        Returns:
            Dicionário mapeando componente para suas vulnerabilidades
        """
        results = {}
        
        if parallel:
            with ThreadPoolExecutor(max_workers=min(len(components), 10)) as executor:
                futures = {
                    executor.submit(
                        self.fetch_vulnerabilities,
                        comp['name'],
                        comp.get('version'),
                        comp.get('ecosystem'),
                        parallel=False  # Não paralelizar fontes aqui
                    ): comp['name']
                    for comp in components
                }
                
                for future in as_completed(futures):
                    comp_name = futures[future]
                    try:
                        results[comp_name] = future.result()
                    except Exception as e:
                        print(f"Erro ao buscar {comp_name}: {e}")
                        results[comp_name] = []
        else:
            for comp in components:
                try:
                    results[comp['name']] = self.fetch_vulnerabilities(
                        comp['name'],
                        comp.get('version'),
                        comp.get('ecosystem'),
                        parallel=False
                    )
                except Exception as e:
                    print(f"Erro ao buscar {comp['name']}: {e}")
                    results[comp['name']] = []
        
        return results
    
    def get_available_sources(self) -> List[str]:
        """Retorna lista de fontes disponíveis."""
        available = []
        for source in self.sources:
            if source.is_available():
                available.append(source.get_source_name())
        return available
    
    def get_statistics(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Gera estatísticas sobre vulnerabilidades encontradas.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades
            
        Returns:
            Dicionário com estatísticas
        """
        from collections import Counter
        
        total = len(vulnerabilities)
        
        # Contagem por severidade
        severity_counts = Counter(v['severity'] for v in vulnerabilities)
        
        # Contagem por fonte
        source_counts = {}
        for vuln in vulnerabilities:
            for source in vuln.get('sources', [vuln['source']]):
                source_counts[source] = source_counts.get(source, 0) + 1
        
        # Score médio
        scores = [v['score'] for v in vulnerabilities if v['score'] > 0]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        return {
            'total': total,
            'by_severity': dict(severity_counts),
            'by_source': source_counts,
            'average_score': round(avg_score, 2),
            'max_score': max(scores) if scores else 0,
            'min_score': min(scores) if scores else 0
        }
