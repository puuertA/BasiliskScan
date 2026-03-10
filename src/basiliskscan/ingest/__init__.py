"""
Módulo de ingestão de vulnerabilidades de múltiplas fontes.
"""

from .base import VulnerabilitySource
from .osv import OSVClient
from .normalizer import VulnerabilityNormalizer, Severity
from .config import IngestConfig, get_config
from .aggregator import VulnerabilityAggregator
from .cache_manager import CacheManager
from .cache_sqlite import SQLiteCache
from .cache_json import JSONCache

__all__ = [
    'VulnerabilitySource',
    'OSVClient',
    'VulnerabilityNormalizer',
    'Severity',
    'IngestConfig',
    'get_config',
    'VulnerabilityAggregator',
    'CacheManager',
    'SQLiteCache',
    'JSONCache',
]
