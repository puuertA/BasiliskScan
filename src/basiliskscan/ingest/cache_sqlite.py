"""
Cache SQLite para armazenamento de vulnerabilidades.
"""

import sqlite3
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
import threading


class SQLiteCache:
    """Cache baseado em SQLite para armazenar vulnerabilidades."""
    
    DEFAULT_CACHE_DIR = Path.home() / ".basiliskscan" / "cache"
    DEFAULT_CACHE_FILE = "vulnerabilities.db"
    DEFAULT_TTL_HOURS = 24  # Time to live padrão: 24 horas
    
    def __init__(
        self, 
        cache_dir: Optional[Path] = None,
        cache_file: str = DEFAULT_CACHE_FILE,
        ttl_hours: int = DEFAULT_TTL_HOURS
    ):
        """
        Inicializa o cache SQLite.
        
        Args:
            cache_dir: Diretório para armazenar o banco de dados
            cache_file: Nome do arquivo do banco de dados
            ttl_hours: Tempo de vida dos dados em cache (horas)
        """
        self.cache_dir = cache_dir or self.DEFAULT_CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = self.cache_dir / cache_file
        self.ttl = timedelta(hours=ttl_hours)
        self._local = threading.local()
        
        self._initialize_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Obtém uma conexão thread-safe."""
        if not hasattr(self._local, 'connection'):
            self._local.connection = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False
            )
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection
    
    def _initialize_database(self):
        """Cria as tabelas necessárias no banco de dados."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Tabela principal de vulnerabilidades
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                component TEXT NOT NULL,
                version TEXT,
                ecosystem TEXT,
                vulnerability_id TEXT,
                data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        
        # Índices para otimizar buscas
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_component_version 
            ON vulnerabilities(component, version)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_source 
            ON vulnerabilities(source)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vulnerability_id 
            ON vulnerabilities(vulnerability_id)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_expires_at 
            ON vulnerabilities(expires_at)
        """)
        
        # Tabela de metadados (última atualização por fonte)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                source TEXT PRIMARY KEY,
                last_full_update TIMESTAMP,
                total_entries INTEGER DEFAULT 0
            )
        """)
        
        conn.commit()
    
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
        conn = self._get_connection()
        cursor = conn.cursor()
        
        query = """
            SELECT data, expires_at 
            FROM vulnerabilities 
            WHERE source = ? 
                AND component = ?
                AND expires_at > ?
        """
        params = [source, component, datetime.now().isoformat()]
        
        if version:
            query += " AND version = ?"
            params.append(version)
        
        if ecosystem:
            query += " AND ecosystem = ?"
            params.append(ecosystem)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        if not rows:
            return None
        
        # Desserializa os dados JSON
        vulnerabilities = []
        for row in rows:
            try:
                vuln_data = json.loads(row['data'])
                vulnerabilities.append(vuln_data)
            except json.JSONDecodeError:
                continue
        
        return vulnerabilities if vulnerabilities else None
    
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
        conn = self._get_connection()
        cursor = conn.cursor()
        
        expires_at = (datetime.now() + self.ttl).isoformat()
        now = datetime.now().isoformat()
        
        # Remove entradas antigas do mesmo componente/versão/fonte
        delete_query = """
            DELETE FROM vulnerabilities 
            WHERE source = ? AND component = ?
        """
        delete_params = [source, component]
        
        if version:
            delete_query += " AND version = ?"
            delete_params.append(version)
        
        if ecosystem:
            delete_query += " AND ecosystem = ?"
            delete_params.append(ecosystem)
        
        cursor.execute(delete_query, delete_params)
        
        # Insere novas vulnerabilidades
        for vuln in vulnerabilities:
            vulnerability_id = self._extract_vulnerability_id(vuln, source)
            data_json = json.dumps(vuln)
            
            cursor.execute("""
                INSERT INTO vulnerabilities 
                (source, component, version, ecosystem, vulnerability_id, data, updated_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                source, component, version, ecosystem, 
                vulnerability_id, data_json, now, expires_at
            ))
        
        conn.commit()
        
        # Atualiza metadados
        self._update_metadata(source)
    
    def _extract_vulnerability_id(self, vuln: Dict[str, Any], source: str) -> Optional[str]:
        """Extrai o ID da vulnerabilidade baseado na fonte."""
        if source == "NVD":
            return vuln.get("cve", {}).get("id")
        elif source in {"OSS Index", "Sonatype Guide"}:
            return vuln.get("id")
        return None
    
    def _update_metadata(self, source: str):
        """Atualiza metadados da fonte."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Conta total de entradas
        cursor.execute("""
            SELECT COUNT(*) as total 
            FROM vulnerabilities 
            WHERE source = ?
        """, (source,))
        total = cursor.fetchone()['total']
        
        # Atualiza ou insere metadados
        cursor.execute("""
            INSERT OR REPLACE INTO metadata (source, last_full_update, total_entries)
            VALUES (?, ?, ?)
        """, (source, datetime.now().isoformat(), total))
        
        conn.commit()
    
    def cleanup_expired(self) -> int:
        """
        Remove entradas expiradas do cache.
        
        Returns:
            Número de entradas removidas
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM vulnerabilities 
            WHERE expires_at < ?
        """, (datetime.now().isoformat(),))
        
        deleted_count = cursor.rowcount
        conn.commit()
        
        return deleted_count
    
    def clear(self, source: Optional[str] = None):
        """
        Limpa o cache.
        
        Args:
            source: Se especificado, limpa apenas dados dessa fonte
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        if source:
            cursor.execute("DELETE FROM vulnerabilities WHERE source = ?", (source,))
            cursor.execute("DELETE FROM metadata WHERE source = ?", (source,))
        else:
            cursor.execute("DELETE FROM vulnerabilities")
            cursor.execute("DELETE FROM metadata")
        
        conn.commit()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Retorna estatísticas do cache.
        
        Returns:
            Dicionário com estatísticas
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Total de entradas
        cursor.execute("SELECT COUNT(*) as total FROM vulnerabilities")
        total = cursor.fetchone()['total']
        
        # Entradas por fonte
        cursor.execute("""
            SELECT source, COUNT(*) as count, MAX(updated_at) as last_update
            FROM vulnerabilities
            GROUP BY source
        """)
        by_source = {
            row['source']: {
                'count': row['count'],
                'last_update': row['last_update']
            }
            for row in cursor.fetchall()
        }
        
        # Entradas expiradas
        cursor.execute("""
            SELECT COUNT(*) as expired 
            FROM vulnerabilities 
            WHERE expires_at < ?
        """, (datetime.now().isoformat(),))
        expired = cursor.fetchone()['expired']
        
        return {
            'total_entries': total,
            'by_source': by_source,
            'expired_entries': expired,
            'db_size_bytes': self.db_path.stat().st_size if self.db_path.exists() else 0
        }
    
    def close(self):
        """Fecha a conexão com o banco de dados."""
        if hasattr(self._local, 'connection'):
            self._local.connection.close()
            del self._local.connection
