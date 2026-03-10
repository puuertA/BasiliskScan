"""
Testes para o sistema de cache do ingest.
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta

from basiliskscan.ingest.cache_sqlite import SQLiteCache
from basiliskscan.ingest.cache_json import JSONCache
from basiliskscan.ingest.cache_manager import CacheManager


class TestSQLiteCache(unittest.TestCase):
    """Testes para o cache SQLite."""
    
    def setUp(self):
        """Cria diretório temporário para testes."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.cache = SQLiteCache(cache_dir=self.temp_dir, ttl_hours=1)
    
    def tearDown(self):
        """Remove diretório temporário."""
        self.cache.close()
        shutil.rmtree(self.temp_dir)
    
    def test_set_and_get(self):
        """Testa armazenamento e recuperação."""
        vulnerabilities = [
            {"id": "CVE-2021-44228", "severity": "CRITICAL"},
            {"id": "CVE-2021-45046", "severity": "CRITICAL"}
        ]
        
        self.cache.set("NVD", "log4j", vulnerabilities, version="2.14.1")
        
        result = self.cache.get("NVD", "log4j", version="2.14.1")
        
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["id"], "CVE-2021-44228")
    
    def test_get_nonexistent(self):
        """Testa busca de item inexistente."""
        result = self.cache.get("NVD", "nonexistent", version="1.0.0")
        self.assertIsNone(result)
    
    def test_clear(self):
        """Testa limpeza do cache."""
        vulnerabilities = [{"id": "CVE-2021-44228"}]
        
        self.cache.set("NVD", "log4j", vulnerabilities)
        self.assertIsNotNone(self.cache.get("NVD", "log4j"))
        
        self.cache.clear()
        self.assertIsNone(self.cache.get("NVD", "log4j"))
    
    def test_stats(self):
        """Testa estatísticas do cache."""
        vulnerabilities = [{"id": "CVE-2021-44228"}]
        
        self.cache.set("NVD", "log4j", vulnerabilities)
        
        stats = self.cache.get_stats()
        
        self.assertIn('total_entries', stats)
        self.assertGreater(stats['total_entries'], 0)
        self.assertIn('by_source', stats)


class TestJSONCache(unittest.TestCase):
    """Testes para o cache JSON."""
    
    def setUp(self):
        """Cria diretório temporário para testes."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.cache = JSONCache(cache_dir=self.temp_dir, ttl_hours=1)
    
    def tearDown(self):
        """Remove diretório temporário."""
        shutil.rmtree(self.temp_dir)
    
    def test_set_and_get(self):
        """Testa armazenamento e recuperação."""
        vulnerabilities = [
            {"id": "CVE-2021-44228", "severity": "CRITICAL"}
        ]
        
        self.cache.set("NVD", "log4j", vulnerabilities, version="2.14.1")
        
        result = self.cache.get("NVD", "log4j", version="2.14.1")
        
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "CVE-2021-44228")
    
    def test_get_nonexistent(self):
        """Testa busca de item inexistente."""
        result = self.cache.get("NVD", "nonexistent", version="1.0.0")
        self.assertIsNone(result)
    
    def test_clear(self):
        """Testa limpeza do cache."""
        vulnerabilities = [{"id": "CVE-2021-44228"}]
        
        self.cache.set("NVD", "log4j", vulnerabilities)
        self.assertIsNotNone(self.cache.get("NVD", "log4j"))
        
        self.cache.clear()
        self.assertIsNone(self.cache.get("NVD", "log4j"))
    
    def test_stats(self):
        """Testa estatísticas do cache."""
        vulnerabilities = [{"id": "CVE-2021-44228"}]
        
        self.cache.set("NVD", "log4j", vulnerabilities)
        
        stats = self.cache.get_stats()
        
        self.assertIn('total_files', stats)
        self.assertGreater(stats['total_files'], 0)


class TestCacheManager(unittest.TestCase):
    """Testes para o gerenciador de cache."""
    
    def setUp(self):
        """Cria diretório temporário para testes."""
        self.temp_dir = Path(tempfile.mkdtemp())
    
    def tearDown(self):
        """Remove diretório temporário."""
        shutil.rmtree(self.temp_dir)
    
    def test_sqlite_backend(self):
        """Testa backend SQLite."""
        cache_manager = CacheManager(
            backend="sqlite",
            cache_dir=self.temp_dir,
            auto_cleanup=False
        )
        
        vulnerabilities = [{"id": "CVE-2021-44228"}]
        cache_manager.set("NVD", "log4j", vulnerabilities)
        
        result = cache_manager.get("NVD", "log4j")
        
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        
        cache_manager.close()
    
    def test_json_backend(self):
        """Testa backend JSON."""
        cache_manager = CacheManager(
            backend="json",
            cache_dir=self.temp_dir,
            auto_cleanup=False
        )
        
        vulnerabilities = [{"id": "CVE-2021-44228"}]
        cache_manager.set("NVD", "log4j", vulnerabilities)
        
        result = cache_manager.get("NVD", "log4j")
        
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        
        cache_manager.close()
    
    def test_hybrid_backend(self):
        """Testa backend híbrido."""
        cache_manager = CacheManager(
            backend="hybrid",
            cache_dir=self.temp_dir,
            auto_cleanup=False
        )
        
        vulnerabilities = [{"id": "CVE-2021-44228"}]
        cache_manager.set("NVD", "log4j", vulnerabilities)
        
        # Deve estar em ambos os backends
        stats = cache_manager.get_stats()
        
        self.assertIn('sqlite', stats)
        self.assertIn('json', stats)
        
        cache_manager.close()
    
    def test_force_update(self):
        """Testa atualização forçada."""
        cache_manager = CacheManager(
            backend="sqlite",
            cache_dir=self.temp_dir,
            auto_cleanup=False
        )
        
        # Primeira versão
        vulns_v1 = [{"id": "CVE-2021-44228"}]
        cache_manager.set("NVD", "log4j", vulns_v1)
        
        # Atualização forçada
        vulns_v2 = [{"id": "CVE-2021-44228"}, {"id": "CVE-2021-45046"}]
        cache_manager.force_update("NVD", "log4j", vulns_v2)
        
        result = cache_manager.get("NVD", "log4j")
        
        self.assertEqual(len(result), 2)
        
        cache_manager.close()
    
    def test_is_stale(self):
        """Testa verificação de dados desatualizados."""
        cache_manager = CacheManager(
            backend="sqlite",
            cache_dir=self.temp_dir,
            ttl_hours=1,
            auto_cleanup=False
        )
        
        vulnerabilities = [{"id": "CVE-2021-44228"}]
        cache_manager.set("NVD", "log4j", vulnerabilities)
        
        # Recém criado, não deve estar stale
        is_stale = cache_manager.is_stale("NVD", "log4j", max_age_hours=2)
        self.assertFalse(is_stale)
        
        # Com limite muito baixo, deve estar stale
        is_stale = cache_manager.is_stale("NVD", "log4j", max_age_hours=0)
        self.assertTrue(is_stale)
        
        cache_manager.close()
    
    def test_context_manager(self):
        """Testa uso como context manager."""
        with CacheManager(backend="sqlite", cache_dir=self.temp_dir, auto_cleanup=False) as cache_manager:
            vulnerabilities = [{"id": "CVE-2021-44228"}]
            cache_manager.set("NVD", "log4j", vulnerabilities)
            
            result = cache_manager.get("NVD", "log4j")
            self.assertIsNotNone(result)


class TestCacheIntegration(unittest.TestCase):
    """Testes de integração do sistema de cache."""
    
    def setUp(self):
        """Cria diretório temporário para testes."""
        self.temp_dir = Path(tempfile.mkdtemp())
    
    def tearDown(self):
        """Remove diretório temporário."""
        shutil.rmtree(self.temp_dir)
    
    def test_multiple_sources(self):
        """Testa cache com múltiplas fontes."""
        cache_manager = CacheManager(
            backend="sqlite",
            cache_dir=self.temp_dir,
            auto_cleanup=False
        )
        
        # Armazena dados de múltiplas fontes
        nvd_vulns = [{"id": "CVE-2021-44228", "source": "NVD"}]
        oss_vulns = [{"id": "OSS-123", "source": "OSS Index"}]
        
        cache_manager.set("NVD", "log4j", nvd_vulns)
        cache_manager.set("OSS Index", "log4j", oss_vulns)
        
        # Recupera de cada fonte
        nvd_result = cache_manager.get("NVD", "log4j")
        oss_result = cache_manager.get("OSS Index", "log4j")
        
        self.assertIsNotNone(nvd_result)
        self.assertIsNotNone(oss_result)
        self.assertEqual(nvd_result[0]["source"], "NVD")
        self.assertEqual(oss_result[0]["source"], "OSS Index")
        
        cache_manager.close()
    
    def test_cleanup_expired(self):
        """Testa limpeza de entradas expiradas."""
        # Cache com TTL muito curto
        cache_manager = CacheManager(
            backend="sqlite",
            cache_dir=self.temp_dir,
            ttl_hours=0.0001,  # ~0.36 segundos
            auto_cleanup=False
        )
        
        vulnerabilities = [{"id": "CVE-2021-44228"}]
        cache_manager.set("NVD", "log4j", vulnerabilities)
        
        # Aguarda expiração
        import time
        time.sleep(1)
        
        # Limpa expirados
        removed = cache_manager.cleanup_expired()
        
        self.assertGreater(removed.get('sqlite', 0), 0)
        
        # Cache deve estar vazio agora
        result = cache_manager.get("NVD", "log4j")
        self.assertIsNone(result)
        
        cache_manager.close()


if __name__ == "__main__":
    unittest.main()
