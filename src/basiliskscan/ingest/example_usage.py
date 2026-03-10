"""
Exemplo de uso do módulo de ingestão de vulnerabilidades.
"""

from basiliskscan.ingest import (
    OSVClient,
    VulnerabilityNormalizer,
    VulnerabilityAggregator
)


def example_aggregator_simple():
    """Exemplo simples usando o agregador."""
    print("=== Exemplo Agregador Simples ===\n")
    
    # Inicializa o agregador (usa OSV por padrão)
    aggregator = VulnerabilityAggregator()
    
    # Verifica fontes disponíveis
    available = aggregator.get_available_sources()
    print(f"Fontes disponíveis: {', '.join(available)}\n")
    
    # Busca vulnerabilidades para um componente
    print("Buscando vulnerabilidades para 'log4j-core'...")
    vulns = aggregator.fetch_vulnerabilities("log4j-core", version="2.14.1", ecosystem="maven")
    
    print(f"Encontradas {len(vulns)} vulnerabilidades\n")
    
    # Exibe algumas vulnerabilidades
    for vuln in vulns[:3]:
        print(f"ID: {vuln['id']}")
        print(f"OSV ID: {vuln.get('osv_id', 'N/A')}")
        print(f"Fontes: {', '.join(vuln.get('sources', []))}")
        print(f"Severidade: {vuln['severity']} (Score: {vuln['score']})")
        print(f"Descrição: {vuln['description'][:100]}...")
        print()
    
    # Gera estatísticas
    if vulns:
        stats = aggregator.get_statistics(vulns)
        print("\nEstatísticas:")
        print(f"  Total: {stats['total']}")
        print(f"  Por severidade: {stats['by_severity']}")
        print(f"  Score médio: {stats['average_score']}")


def example_aggregator_multiple():
    """Exemplo buscando múltiplos componentes."""
    print("=== Exemplo Múltiplos Componentes ===\n")
    
    aggregator = VulnerabilityAggregator()
    
    # Define componentes para buscar
    components = [
        {"name": "express", "version": "4.17.1", "ecosystem": "npm"},
        {"name": "spring-core", "version": "5.2.0", "ecosystem": "maven"},
        {"name": "requests", "version": "2.25.0", "ecosystem": "pypi"}
    ]
    
    print(f"Buscando vulnerabilidades para {len(components)} componentes...\n")
    
    # Busca em paralelo
    results = aggregator.fetch_multiple_components(components, parallel=True)
    
    # Exibe resultados
    for comp_name, vulns in results.items():
        print(f"{comp_name}: {len(vulns)} vulnerabilidades")
        if vulns:
            stats = aggregator.get_statistics(vulns)
            print(f"  Severidades: {stats['by_severity']}")
        print()


def example_osv_usage():
    """Exemplo de uso do cliente OSV."""
    print("=== Exemplo OSV ===\n")
    
    # Inicializa o cliente OSV
    osv = OSVClient()
    
    # Verifica disponibilidade
    if osv.is_available():
        print("✓ OSV API está disponível\n")
    else:
        print("✗ OSV API não está disponível\n")
        return
    
    # Busca vulnerabilidades para um componente npm
    print("Buscando vulnerabilidades para 'lodash'...")
    vulns = osv.fetch_vulnerabilities("lodash", version="4.17.20", ecosystem="npm")
    
    print(f"Encontradas {len(vulns)} vulnerabilidades\n")
    
    # Normaliza e exibe algumas vulnerabilidades
    for vuln_data in vulns[:3]:  # Mostra apenas as 3 primeiras
        normalized = VulnerabilityNormalizer.normalize_osv_vulnerability(vuln_data)
        print(f"ID: {normalized['id']}")
        print(f"OSV ID: {normalized.get('osv_id', 'N/A')}")
        print(f"Severidade: {normalized['severity']} (Score: {normalized['score']})")
        print(f"Descrição: {normalized['description'][:100]}...")
        if normalized.get('aliases'):
            print(f"Aliases: {', '.join(normalized['aliases'])}")
        print()


def example_osv_maven():
    """Exemplo de uso do OSV com pacotes Maven."""
    print("=== Exemplo OSV - Maven ===\n")
    
    osv = OSVClient()
    
    # Busca vulnerabilidades para um componente Maven
    print("Buscando vulnerabilidades para 'log4j-core'...")
    vulns = osv.fetch_vulnerabilities("log4j-core", version="2.14.1", ecosystem="maven")
    
    print(f"Encontradas {len(vulns)} vulnerabilidades\n")
    
    # Normaliza e exibe vulnerabilidades
    for vuln_data in vulns[:5]:
        normalized = VulnerabilityNormalizer.normalize_osv_vulnerability(vuln_data)
        print(f"ID: {normalized['id']}")
        print(f"Título: {normalized['title']}")
        print(f"Severidade: {normalized['severity']}")
        
        # Exibe pacotes afetados
        if normalized.get('affected_products'):
            for affected in normalized['affected_products'][:2]:
                print(f"  Afetado: {affected.get('ecosystem')} - {affected.get('name')}")
                if affected.get('versions'):
                    print(f"  Versões: {', '.join(affected['versions'][:3])}")
        print()


if __name__ == "__main__":
    # Executa exemplo do agregador (mais simples)
    example_aggregator_simple()
    print("\n" + "="*50 + "\n")
    
    example_aggregator_multiple()
    print("\n" + "="*50 + "\n")
    
    # Executa exemplos individuais do OSV
    example_osv_usage()
    print("\n" + "="*50 + "\n")
    
    example_osv_maven()

