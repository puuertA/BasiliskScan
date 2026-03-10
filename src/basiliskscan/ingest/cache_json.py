"""
Cache JSON para armazenamento de vulnerabilidades.
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
import threading
import hashlib


class JSONCache:
    """Cache baseado em arquivos JSON para armazenar vulnerabilidades."""
    
    DEFAULT_CACHE_DIR = Path.home() / ".basiliskscan" / "cache" / "json"
    DEFAULT_TTL_HOURS = 24  # Time to live padrão: 24 horas
    
    def __init__(
        self, 
        cache_dir: Optional[Path] = None,
        ttl_hours: int = DEFAULT_TTL_HOURS
    ):
        """
        Inicializa o cache JSON.
        
        Args:
            cache_dir: Diretório para armazenar os arquivos JSON
            ttl_hours: Tempo de vida dos dados em cache (horas)
        """
        self.cache_dir = cache_dir or self.DEFAULT_CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.ttl = timedelta(hours=ttl_hours)
        self._lock = threading.Lock()
    
    def _get_cache_key(
        self,
        source: str,
        component: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None
    ) -> str:
        """
        Gera uma chave única para o cache.
        
        Args:
            source: Nome da fonte
            component: Nome do componente
            version: Versão específica
            ecosystem: Ecosistema
            
        Returns:
            Hash SHA256 da combinação dos parâmetros
        """
        key_parts = [source, component]
        if version:
            key_parts.append(version)
        if ecosystem:
            key_parts.append(ecosystem)
        
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    def _get_cache_file(self, cache_key: str) -> Path:
        """Retorna o caminho do arquivo de cache."""
        return self.cache_dir / f"{cache_key}.json"
    
    def get(
        self,
        source: str,
        component: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Busca vulnerabilidades no cache.
        
        Args:
            source: Nome da fonte (NVD, OSS Index, etc.)
            component: Nome do componente
            version: Versão específica (opcional)
            ecosystem: Ecosistema (opcional)
            
        Returns:
            Lista de vulnerabilidades ou None se não encontrado/expirado
        """
        cache_key = self._get_cache_key(source, component, version, ecosystem)
        cache_file = self._get_cache_file(cache_key)
        
        if not cache_file.exists():
            return None
        
        try:
            with self._lock:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
            
            # Verifica expiração
            expires_at = datetime.fromisoformat(cache_data['expires_at'])
            if datetime.now() > expires_at:
                # Cache expirado, remove o arquivo
                cache_file.unlink(missing_ok=True)
                return None
            
            return cache_data['vulnerabilities']
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            # Arquivo corrompido, remove
            cache_file.unlink(missing_ok=True)
            return None
    
    def set(
        self,
        source: str,
        component: str,
        vulnerabilities: List[Dict[str, Any]],
        version: Optional[str] = None,
        ecosystem: Optional[str] = None
    ):
        """
        Armazena vulnerabilidades no cache.
        
        Args:
            source: Nome da fonte
            component: Nome do componente
            vulnerabilities: Lista de vulnerabilidades
            version: Versão específica (opcional)
            ecosystem: Ecosistema (opcional)
        """
        cache_key = self._get_cache_key(source, component, version, ecosystem)
        cache_file = self._get_cache_file(cache_key)
        
        cache_data = {
            'source': source,
            'component': component,
            'version': version,
            'ecosystem': ecosystem,
            'vulnerabilities': vulnerabilities,
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + self.ttl).isoformat(),
            'count': len(vulnerabilities)
        }
        
        try:
            with self._lock:
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(cache_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Erro ao salvar cache: {e}")
    
    def cleanup_expired(self) -> int:
        """
        Remove arquivos expirados do cache.
        
        Returns:
            Número de arquivos removidos
        """
        deleted_count = 0
        now = datetime.now()
        
        with self._lock:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        cache_data = json.load(f)
                    
                    expires_at = datetime.fromisoformat(cache_data['expires_at'])
                    if now > expires_at:
                        cache_file.unlink()
                        deleted_count += 1
                        
                except Exception:
                    # Remove arquivos corrompidos
                    cache_file.unlink(missing_ok=True)
                    deleted_count += 1
        
        return deleted_count
    
    def clear(self, source: Optional[str] = None):
        """
        Limpa o cache.
        
        Args:
            source: Se especificado, limpa apenas dados dessa fonte
        """
        with self._lock:
            for cache_file in self.cache_dir.glob("*.json"):
                if source:
                    try:
                        with open(cache_file, 'r', encoding='utf-8') as f:
                            cache_data = json.load(f)
                        
                        if cache_data.get('source') == source:
                            cache_file.unlink()
                    except Exception:
                        continue
                else:
                    cache_file.unlink()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Retorna estatísticas do cache.
        
        Returns:
            Dicionário com estatísticas
        """
        total_files = 0
        total_size = 0
        by_source = {}
        expired_count = 0
        now = datetime.now()
        
        with self._lock:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    total_files += 1
                    total_size += cache_file.stat().st_size
                    
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        cache_data = json.load(f)
                    
                    source = cache_data.get('source', 'unknown')
                    
                    if source not in by_source:
                        by_source[source] = {
                            'count': 0,
                            'last_update': None
                        }
                    
                    by_source[source]['count'] += 1
                    
                    created_at = cache_data.get('created_at')
                    if created_at:
                        if (not by_source[source]['last_update'] or 
                            created_at > by_source[source]['last_update']):
                            by_source[source]['last_update'] = created_at
                    
                    # Verifica expiração
                    expires_at = datetime.fromisoformat(cache_data['expires_at'])
                    if now > expires_at:
                        expired_count += 1
                        
                except Exception:
                    continue
        
        return {
            'total_files': total_files,
            'by_source': by_source,
            'expired_files': expired_count,
            'total_size_bytes': total_size
        }
    
    def get_all_cached_items(self) -> List[Dict[str, Any]]:
        """
        Retorna informações sobre todos os itens em cache.
        
        Returns:
            Lista com informações de cada item em cache
        """
        items = []
        
        with self._lock:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        cache_data = json.load(f)
                    
                    items.append({
                        'file': cache_file.name,
                        'source': cache_data.get('source'),
                        'component': cache_data.get('component'),
                        'version': cache_data.get('version'),
                        'ecosystem': cache_data.get('ecosystem'),
                        'count': cache_data.get('count', 0),
                        'created_at': cache_data.get('created_at'),
                        'expires_at': cache_data.get('expires_at')
                    })
                except Exception:
                    continue
        
        return items
