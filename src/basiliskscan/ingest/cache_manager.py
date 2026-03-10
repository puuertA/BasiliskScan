"""
Gerenciador unificado de cache com suporte a SQLite e JSON.
"""

from typing import List, Dict, Any, Optional, Literal
from pathlib import Path
from datetime import datetime, timedelta
import threading
import time

from .cache_sqlite import SQLiteCache
from .cache_json import JSONCache


CacheBackend = Literal["sqlite", "json", "hybrid"]


class CacheManager:
    """
    Gerenciador unificado de cache com suporte a múltiplos backends.
    
    Modos de operação:
    - sqlite: Usa apenas SQLite (recomendado para produção)
    - json: Usa apenas JSON (simples, fácil inspeção manual)
    - hybrid: Usa SQLite como principal e JSON como backup
    """
    
    def __init__(
        self,
        backend: CacheBackend = "sqlite",
        cache_dir: Optional[Path] = None,
        ttl_hours: int = 24,
        auto_cleanup: bool = True,
        cleanup_interval_hours: int = 6
    ):
        """
        Inicializa o gerenciador de cache.
        
        Args:
            backend: Backend a ser usado (sqlite, json, ou hybrid)
            cache_dir: Diretório base para o cache
            ttl_hours: Tempo de vida dos dados em cache (horas)
            auto_cleanup: Se True, executa limpeza automática periódica
            cleanup_interval_hours: Intervalo entre limpezas automáticas
        """
        self.backend = backend
        self.ttl_hours = ttl_hours
        self.auto_cleanup = auto_cleanup
        self.cleanup_interval = timedelta(hours=cleanup_interval_hours)
        
        # Inicializa backends
        if backend in ("sqlite", "hybrid"):
            self.sqlite_cache = SQLiteCache(
                cache_dir=cache_dir,
                ttl_hours=ttl_hours
            )
        else:
            self.sqlite_cache = None
        
        if backend in ("json", "hybrid"):
            json_cache_dir = cache_dir / "json" if cache_dir else None
            self.json_cache = JSONCache(
                cache_dir=json_cache_dir,
                ttl_hours=ttl_hours
            )
        else:
            self.json_cache = None
        
        # Thread de limpeza automática
        self._cleanup_thread = None
        self._cleanup_stop_event = threading.Event()
        self._last_cleanup = datetime.now()
        
        if auto_cleanup:
            self._start_cleanup_thread()
    
    def _start_cleanup_thread(self):
        """Inicia thread de limpeza automática."""
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True
        )
        self._cleanup_thread.start()
    
    def _cleanup_loop(self):
        """Loop de limpeza automática executado em background."""
        while not self._cleanup_stop_event.is_set():
            time_since_last = datetime.now() - self._last_cleanup
            
            if time_since_last >= self.cleanup_interval:
                try:
                    self.cleanup_expired()
                    self._last_cleanup = datetime.now()
                except Exception as e:
                    print(f"Erro na limpeza automática: {e}")
            
            # Aguarda 1 hora ou até stop event
            self._cleanup_stop_event.wait(timeout=3600)
    
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
        # Tenta SQLite primeiro (mais rápido)
        if self.sqlite_cache:
            result = self.sqlite_cache.get(source, component, version, ecosystem)
            if result is not None:
                return result
        
        # Fallback para JSON se hybrid
        if self.backend == "hybrid" and self.json_cache:
            result = self.json_cache.get(source, component, version, ecosystem)
            if result is not None:
                # Replica para SQLite
                if self.sqlite_cache:
                    self.sqlite_cache.set(source, component, result, version, ecosystem)
                return result
        
        # Modo JSON puro
        if self.backend == "json" and self.json_cache:
            return self.json_cache.get(source, component, version, ecosystem)
        
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
        if self.sqlite_cache:
            self.sqlite_cache.set(source, component, vulnerabilities, version, ecosystem)
        
        if self.json_cache:
            self.json_cache.set(source, component, vulnerabilities, version, ecosystem)
    
    def cleanup_expired(self) -> Dict[str, int]:
        """
        Remove entradas expiradas de todos os caches.
        
        Returns:
            Dicionário com contagem de itens removidos por backend
        """
        results = {}
        
        if self.sqlite_cache:
            results['sqlite'] = self.sqlite_cache.cleanup_expired()
        
        if self.json_cache:
            results['json'] = self.json_cache.cleanup_expired()
        
        return results
    
    def clear(self, source: Optional[str] = None):
        """
        Limpa o cache.
        
        Args:
            source: Se especificado, limpa apenas dados dessa fonte
        """
        if self.sqlite_cache:
            self.sqlite_cache.clear(source)
        
        if self.json_cache:
            self.json_cache.clear(source)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Retorna estatísticas consolidadas do cache.
        
        Returns:
            Dicionário com estatísticas por backend
        """
        stats = {
            'backend': self.backend,
            'ttl_hours': self.ttl_hours,
            'auto_cleanup': self.auto_cleanup,
            'last_cleanup': self._last_cleanup.isoformat()
        }
        
        if self.sqlite_cache:
            stats['sqlite'] = self.sqlite_cache.get_stats()
        
        if self.json_cache:
            stats['json'] = self.json_cache.get_stats()
        
        return stats
    
    def force_update(
        self,
        source: str,
        component: str,
        vulnerabilities: List[Dict[str, Any]],
        version: Optional[str] = None,
        ecosystem: Optional[str] = None
    ):
        """
        Força atualização do cache, removendo dados antigos primeiro.
        
        Args:
            source: Nome da fonte
            component: Nome do componente
            vulnerabilities: Lista de vulnerabilidades
            version: Versão específica (opcional)
            ecosystem: Ecosistema (opcional)
        """
        # Remove entradas antigas
        if self.sqlite_cache:
            conn = self.sqlite_cache._get_connection()
            cursor = conn.cursor()
            delete_query = "DELETE FROM vulnerabilities WHERE source = ? AND component = ?"
            params = [source, component]
            
            if version:
                delete_query += " AND version = ?"
                params.append(version)
            if ecosystem:
                delete_query += " AND ecosystem = ?"
                params.append(ecosystem)
            
            cursor.execute(delete_query, params)
            conn.commit()
        
        # Adiciona novos dados
        self.set(source, component, vulnerabilities, version, ecosystem)
    
    def is_stale(
        self,
        source: str,
        component: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None,
        max_age_hours: Optional[int] = None
    ) -> bool:
        """
        Verifica se os dados em cache estão desatualizados.
        
        Args:
            source: Nome da fonte
            component: Nome do componente
            version: Versão específica
            ecosystem: Ecosistema
            max_age_hours: Idade máxima em horas (usa TTL padrão se None)
            
        Returns:
            True se dados não existem ou estão desatualizados
        """
        if max_age_hours is None:
            max_age_hours = self.ttl_hours
        
        max_age = timedelta(hours=max_age_hours)
        
        # Verifica no SQLite
        if self.sqlite_cache:
            conn = self.sqlite_cache._get_connection()
            cursor = conn.cursor()
            
            query = """
                SELECT updated_at 
                FROM vulnerabilities 
                WHERE source = ? AND component = ?
            """
            params = [source, component]
            
            if version:
                query += " AND version = ?"
                params.append(version)
            if ecosystem:
                query += " AND ecosystem = ?"
                params.append(ecosystem)
            
            query += " ORDER BY updated_at DESC LIMIT 1"
            
            cursor.execute(query, params)
            row = cursor.fetchone()
            
            if row:
                updated_at = datetime.fromisoformat(row['updated_at'])
                age = datetime.now() - updated_at
                return age > max_age
        
        # Se não encontrou ou não tem SQLite, considera stale
        return True
    
    def close(self):
        """Finaliza o cache e para threads de limpeza."""
        if self.auto_cleanup and self._cleanup_thread:
            self._cleanup_stop_event.set()
            self._cleanup_thread.join(timeout=5)
        
        if self.sqlite_cache:
            self.sqlite_cache.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
