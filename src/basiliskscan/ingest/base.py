"""
Classe base para fontes de vulnerabilidades.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
from .cache_manager import CacheManager


class VulnerabilitySource(ABC):
    """Interface base para clientes de fontes de vulnerabilidades."""
    
    def __init__(
        self, 
        api_key: Optional[str] = None,
        cache_manager: Optional[CacheManager] = None,
        use_cache: bool = True
    ):
        """
        Inicializa a fonte de vulnerabilidades.
        
        Args:
            api_key: Chave de API opcional para autenticação
            cache_manager: Gerenciador de cache (cria um padrão se None)
            use_cache: Se True, usa cache para otimizar consultas
        """
        self.api_key = api_key
        self.last_updated: Optional[datetime] = None
        self.use_cache = use_cache
        self.cache_manager = cache_manager or (CacheManager() if use_cache else None)
    
    @abstractmethod
    def fetch_vulnerabilities(
        self, 
        component: str, 
        version: Optional[str] = None,
        ecosystem: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Busca vulnerabilidades para um componente específico.
        
        Args:
            component: Nome do componente/pacote
            version: Versão específica do componente
            ecosystem: Ecosistema (npm, maven, pypi, etc.)
            
        Returns:
            Lista de vulnerabilidades encontradas (formato bruto)
        """
        pass
    
    def get_vulnerabilities(
        self,
        component: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None,
        force_refresh: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Busca vulnerabilidades com suporte a cache.
        
        Args:
            component: Nome do componente/pacote
            version: Versão específica do componente
            ecosystem: Ecosistema (npm, maven, pypi, etc.)
            force_refresh: Se True, ignora cache e força busca na API
            
        Returns:
            Lista de vulnerabilidades encontradas
        """
        source_name = self.get_source_name()
        
        # Verifica cache primeiro (se habilitado e não for refresh forçado)
        if self.use_cache and self.cache_manager and not force_refresh:
            cached = self.cache_manager.get(source_name, component, version, ecosystem)
            if cached is not None:
                return cached
        
        # Busca na API
        vulnerabilities = self.fetch_vulnerabilities(component, version, ecosystem)
        
        # Armazena no cache
        if self.use_cache and self.cache_manager and vulnerabilities:
            self.cache_manager.set(source_name, component, vulnerabilities, version, ecosystem)
        
        return vulnerabilities
    
    @abstractmethod
    def get_source_name(self) -> str:
        """Retorna o nome da fonte de vulnerabilidades."""
        pass
    
    def is_available(self) -> bool:
        """
        Verifica se a fonte está disponível e acessível.
        
        Returns:
            True se a fonte está disponível
        """
        return True
    
    def clear_cache(self):
        """Limpa o cache desta fonte."""
        if self.cache_manager:
            self.cache_manager.clear(source=self.get_source_name())
    
    def get_cache_stats(self) -> Optional[Dict[str, Any]]:
        """
        Retorna estatísticas do cache.
        
        Returns:
            Dicionário com estatísticas ou None se cache desabilitado
        """
        if self.cache_manager:
            return self.cache_manager.get_stats()
        return None
