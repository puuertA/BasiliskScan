"""Gerenciador de configurações do módulo de ingestão."""

from typing import Optional, Dict, Any, Literal
from pathlib import Path
import json

from basiliskscan.auth.credential_manager import CredentialManager


CacheBackend = Literal["sqlite", "json", "hybrid"]


class IngestConfig:
    """Gerencia configurações de ingestão e delega credenciais para auth."""
    
    CONFIG_FILE = ".basiliskscan_ingest.json"
    
    def __init__(self):
        """Inicializa o gerenciador de configurações."""
        self.config_path = Path.home() / self.CONFIG_FILE
        self._config = self._load_config()
        self.credential_manager = CredentialManager()
    
    def _load_config(self) -> Dict[str, Any]:
        """Carrega configurações do arquivo."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Erro ao carregar configurações: {e}")
                return {}
        return {}
    
    def save_config(self):
        """Salva configurações no arquivo."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self._config, f, indent=2)
        except Exception as e:
            print(f"Erro ao salvar configurações: {e}")
    
    def get_nvd_api_key(self) -> Optional[str]:
        """
        Obtém a API key do NVD.
        
        Ordem de prioridade:
        1. Variável de ambiente NVD_API_KEY
        2. Keyring do sistema operacional
        3. ~/.config/basiliskscan/credentials.toml
        
        Returns:
            API key ou None
        """
        return self.credential_manager.get_nvd_api_key()
    
    def set_nvd_api_key(self, api_key: str):
        """
        Define a API key do NVD no arquivo de credenciais central.
        
        Args:
            api_key: API key do NVD
        """
        self.credential_manager.set_credentials("nvd", {"api_key": api_key})
    
    def get_oss_index_credentials(self) -> tuple[Optional[str], Optional[str]]:
        """
        Obtém credenciais do OSS Index.
        
        Ordem de prioridade:
        1. Variáveis de ambiente OSS_INDEX_USERNAME e OSS_INDEX_TOKEN
        2. Keyring do sistema operacional
        3. ~/.config/basiliskscan/credentials.toml
        
        Returns:
            Tupla (username, token) ou (None, None)
        """
        return self.credential_manager.get_oss_index_credentials()
    
    def set_oss_index_credentials(self, username: str, token: str):
        """
        Define credenciais do OSS Index no arquivo de credenciais central.
        
        Args:
            username: Username do OSS Index
            token: Token de autenticação
        """
        self.credential_manager.set_credentials(
            "oss_index",
            {"username": username, "token": token},
        )
    
    def clear_credentials(self):
        """Remove credenciais persistidas na camada central de auth."""
        self.credential_manager.clear_stored_credentials()
    
    def get_all_config(self) -> Dict[str, Any]:
        """Retorna todas as configurações (sem expor valores sensíveis)."""
        safe_config = {}

        nvd_record = self.credential_manager.discover_credentials("nvd")
        if nvd_record:
            safe_config['nvd'] = {
                'api_key_configured': True,
                'source': nvd_record.source.value,
            }

        oss_record = self.credential_manager.discover_credentials("oss_index")
        if oss_record:
            safe_config['oss_index'] = {
                'username': oss_record.data.get('username'),
                'token_configured': bool(oss_record.data.get('token')),
                'source': oss_record.source.value,
            }
        
        if 'cache' in self._config:
            safe_config['cache'] = self._config['cache']
        
        return safe_config
    
    # Configurações de Cache
    
    def get_cache_config(self) -> Dict[str, Any]:
        """
        Retorna configurações de cache.
        
        Returns:
            Dicionário com configurações de cache
        """
        default_config = {
            'enabled': True,
            'backend': 'sqlite',
            'ttl_hours': 24,
            'auto_cleanup': True,
            'cleanup_interval_hours': 6
        }
        
        if 'cache' not in self._config:
            return default_config
        
        return {**default_config, **self._config['cache']}
    
    def set_cache_config(
        self,
        enabled: Optional[bool] = None,
        backend: Optional[CacheBackend] = None,
        ttl_hours: Optional[int] = None,
        auto_cleanup: Optional[bool] = None,
        cleanup_interval_hours: Optional[int] = None
    ):
        """
        Define configurações de cache.
        
        Args:
            enabled: Habilita/desabilita cache
            backend: Backend de cache (sqlite, json, hybrid)
            ttl_hours: Tempo de vida dos dados em horas
            auto_cleanup: Habilita limpeza automática
            cleanup_interval_hours: Intervalo entre limpezas
        """
        if 'cache' not in self._config:
            self._config['cache'] = {}
        
        if enabled is not None:
            self._config['cache']['enabled'] = enabled
        if backend is not None:
            self._config['cache']['backend'] = backend
        if ttl_hours is not None:
            self._config['cache']['ttl_hours'] = ttl_hours
        if auto_cleanup is not None:
            self._config['cache']['auto_cleanup'] = auto_cleanup
        if cleanup_interval_hours is not None:
            self._config['cache']['cleanup_interval_hours'] = cleanup_interval_hours
        
        self.save_config()


# Singleton global
_config_instance = None

def get_config() -> IngestConfig:
    """Obtém a instância singleton do gerenciador de configurações."""
    global _config_instance
    if _config_instance is None:
        _config_instance = IngestConfig()
    return _config_instance
