"""
Exemplo de uso do sistema de cache do ingest.
"""

from basiliskscan.ingest.cache_manager import CacheManager
from basiliskscan.ingest.nvd import NVDClient
from basiliskscan.ingest.sonatype_guide import SonatypeGuideClient
from basiliskscan.ingest.config import get_config


def exemplo_cache_basico():
    """Exemplo básico de uso do cache."""
    print("=== Exemplo: Cache Básico ===\n")
    
    # Cria gerenciador de cache (padrão: SQLite)
    cache_manager = CacheManager()
    
    # Cria cliente NVD com cache
    config = get_config()
    nvd = NVDClient(
        api_key=config.get_nvd_api_key(),
        cache_manager=cache_manager,
        use_cache=True
    )
    
    # Primeira busca: vai para a API
    print("Primeira busca (API)...")
    vulns = nvd.get_vulnerabilities("log4j", version="2.14.1")
    print(f"Encontradas {len(vulns)} vulnerabilidades\n")
    
    # Segunda busca: usa cache
    print("Segunda busca (cache)...")
    vulns_cached = nvd.get_vulnerabilities("log4j", version="2.14.1")
    print(f"Encontradas {len(vulns_cached)} vulnerabilidades (do cache)\n")
    
    # Estatísticas do cache
    stats = cache_manager.get_stats()
    print(f"Estatísticas: {stats}\n")


def exemplo_cache_json():
    """Exemplo usando cache JSON."""
    print("=== Exemplo: Cache JSON ===\n")
    
    # Cria gerenciador de cache JSON
    cache_manager = CacheManager(backend="json")
    
    config = get_config()
    username, token = config.get_oss_index_credentials()
    
    # Cliente Sonatype Guide com cache JSON
    sonatype_guide = SonatypeGuideClient(
        token=token,
        username=username,
        cache_manager=cache_manager,
        use_cache=True
    )
    
    # Busca com cache JSON
    print("Buscando na Sonatype Guide...")
    vulns = sonatype_guide.get_vulnerabilities("express", ecosystem="npm")
    print(f"Encontradas {len(vulns)} vulnerabilidades\n")
    
    # Estatísticas
    stats = cache_manager.get_stats()
    print(f"Arquivos JSON: {stats.get('json', {}).get('total_files', 0)}\n")


def exemplo_cache_hibrido():
    """Exemplo usando cache híbrido (SQLite + JSON)."""
    print("=== Exemplo: Cache Híbrido ===\n")
    
    # Cache híbrido: SQLite como principal, JSON como backup
    cache_manager = CacheManager(
        backend="hybrid",
        ttl_hours=48,  # 48 horas de TTL
        auto_cleanup=True
    )
    
    config = get_config()
    nvd = NVDClient(
        api_key=config.get_nvd_api_key(),
        cache_manager=cache_manager
    )
    
    # Busca
    print("Buscando vulnerabilidades...")
    vulns = nvd.get_vulnerabilities("spring-core", version="5.3.0")
    print(f"Encontradas {len(vulns)} vulnerabilidades\n")
    
    # Dados foram salvos em ambos os backends
    stats = cache_manager.get_stats()
    print("SQLite:")
    print(f"  - Entradas: {stats.get('sqlite', {}).get('total_entries', 0)}")
    print("\nJSON:")
    print(f"  - Arquivos: {stats.get('json', {}).get('total_files', 0)}\n")


def exemplo_atualizacao_periodica():
    """Exemplo de atualização periódica e cache stale."""
    print("=== Exemplo: Atualização Periódica ===\n")
    
    cache_manager = CacheManager(ttl_hours=1)  # TTL curto para exemplo
    
    config = get_config()
    nvd = NVDClient(
        api_key=config.get_nvd_api_key(),
        cache_manager=cache_manager
    )
    
    component = "jackson-databind"
    
    # Verifica se cache está desatualizado
    is_stale = cache_manager.is_stale("NVD", component, max_age_hours=1)
    print(f"Cache está desatualizado? {is_stale}")
    
    if is_stale:
        print("Atualizando cache...")
        vulns = nvd.get_vulnerabilities(component, force_refresh=True)
        print(f"Cache atualizado com {len(vulns)} vulnerabilidades\n")
    else:
        print("Cache ainda válido, usando dados em cache\n")


def exemplo_limpeza_cache():
    """Exemplo de limpeza de cache."""
    print("=== Exemplo: Limpeza de Cache ===\n")
    
    cache_manager = CacheManager()
    
    # Estatísticas antes da limpeza
    stats_antes = cache_manager.get_stats()
    print(f"Entradas antes: {stats_antes.get('sqlite', {}).get('total_entries', 0)}")
    print(f"Expiradas: {stats_antes.get('sqlite', {}).get('expired_entries', 0)}\n")
    
    # Limpa entradas expiradas
    print("Limpando entradas expiradas...")
    removed = cache_manager.cleanup_expired()
    print(f"Removidas: {removed}\n")
    
    # Estatísticas após limpeza
    stats_depois = cache_manager.get_stats()
    print(f"Entradas depois: {stats_depois.get('sqlite', {}).get('total_entries', 0)}\n")


def exemplo_configuracao():
    """Exemplo de configuração do cache."""
    print("=== Exemplo: Configuração ===\n")
    
    config = get_config()
    
    # Define configurações de cache
    config.set_cache_config(
        enabled=True,
        backend="sqlite",
        ttl_hours=24,
        auto_cleanup=True,
        cleanup_interval_hours=6
    )
    
    print("Configurações de cache definidas:")
    cache_config = config.get_cache_config()
    for key, value in cache_config.items():
        print(f"  - {key}: {value}")
    print()
    
    # Usa as configurações
    cache_config = config.get_cache_config()
    if cache_config['enabled']:
        cache_manager = CacheManager(
            backend=cache_config['backend'],
            ttl_hours=cache_config['ttl_hours'],
            auto_cleanup=cache_config['auto_cleanup'],
            cleanup_interval_hours=cache_config['cleanup_interval_hours']
        )
        print(f"Cache Manager criado com backend: {cache_config['backend']}\n")


def exemplo_sem_cache():
    """Exemplo desabilitando o cache."""
    print("=== Exemplo: Sem Cache ===\n")
    
    config = get_config()
    
    # Cliente sem cache
    nvd = NVDClient(
        api_key=config.get_nvd_api_key(),
        use_cache=False
    )
    
    print("Buscando sem cache...")
    vulns = nvd.get_vulnerabilities("struts")
    print(f"Encontradas {len(vulns)} vulnerabilidades")
    print("Todas as buscas vão direto para a API (sem cache)\n")


def exemplo_force_refresh():
    """Exemplo de força refresh (ignora cache)."""
    print("=== Exemplo: Force Refresh ===\n")
    
    cache_manager = CacheManager()
    config = get_config()
    
    nvd = NVDClient(
        api_key=config.get_nvd_api_key(),
        cache_manager=cache_manager
    )
    
    component = "commons-fileupload"
    
    # Primeira busca (API)
    print("Primeira busca (API)...")
    vulns1 = nvd.get_vulnerabilities(component)
    print(f"Encontradas {len(vulns1)} vulnerabilidades\n")
    
    # Segunda busca (cache)
    print("Segunda busca (cache)...")
    vulns2 = nvd.get_vulnerabilities(component)
    print(f"Encontradas {len(vulns2)} vulnerabilidades (cache)\n")
    
    # Terceira busca (force refresh - ignora cache)
    print("Terceira busca (force refresh)...")
    vulns3 = nvd.get_vulnerabilities(component, force_refresh=True)
    print(f"Encontradas {len(vulns3)} vulnerabilidades (API novamente)\n")


if __name__ == "__main__":
    print("Exemplos de uso do sistema de cache\n")
    print("=" * 60)
    print()
    
    # Execute os exemplos que desejar
    # Descomente a linha do exemplo que quiser executar:
    
    # exemplo_cache_basico()
    # exemplo_cache_json()
    # exemplo_cache_hibrido()
    # exemplo_atualizacao_periodica()
    # exemplo_limpeza_cache()
    exemplo_configuracao()
    # exemplo_sem_cache()
    # exemplo_force_refresh()
    
    print("=" * 60)
    print("\nExemplos concluídos!")
