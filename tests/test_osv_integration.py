#!/usr/bin/env python3
"""
Script de teste rápido para validar a integração com OSV.
"""

from basiliskscan.ingest import OSVClient, VulnerabilityNormalizer, VulnerabilityAggregator


def test_osv_client():
    """Testa o cliente OSV diretamente."""
    print("=" * 70)
    print("Teste 1: Cliente OSV direto")
    print("=" * 70)
    
    osv = OSVClient()
    
    # Verifica disponibilidade
    print("\nVerificando disponibilidade da API OSV...")
    if osv.is_available():
        print("✓ OSV API está disponível")
    else:
        print("✗ OSV API não está disponível")
        return False
    
    # Testa busca para lodash (vulnerabilidade conhecida)
    print("\nBuscando vulnerabilidades para lodash 4.17.20...")
    try:
        vulns = osv.fetch_vulnerabilities("lodash", version="4.17.20", ecosystem="npm")
        print(f"✓ Encontradas {len(vulns)} vulnerabilidades")
        
        if vulns:
            # Mostra a primeira
            vuln = vulns[0]
            print(f"\nExemplo de vulnerabilidade encontrada:")
            print(f"  ID: {vuln.get('id')}")
            print(f"  Summary: {vuln.get('summary', 'N/A')[:80]}")
            print(f"  Modified: {vuln.get('modified', 'N/A')}")
        
        return True
    except Exception as e:
        print(f"✗ Erro ao buscar vulnerabilidades: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_normalizer():
    """Testa o normalizador com dados OSV."""
    print("\n" + "=" * 70)
    print("Teste 2: Normalização de dados OSV")
    print("=" * 70)
    
    osv = OSVClient()
    
    print("\nBuscando e normalizando vulnerabilidades para log4j-core 2.14.1...")
    try:
        vulns = osv.fetch_vulnerabilities("log4j-core", version="2.14.1", ecosystem="maven")
        
        if not vulns:
            print("⚠ Nenhuma vulnerabilidade encontrada (isso pode ser normal)")
            return True
        
        print(f"✓ Encontradas {len(vulns)} vulnerabilidades")
        
        # Normaliza primeira vulnerabilidade
        normalized = VulnerabilityNormalizer.normalize_osv_vulnerability(vulns[0])
        
        print(f"\nVulnerabilidade normalizada:")
        print(f"  ID: {normalized['id']}")
        print(f"  Fonte: {normalized['source']}")
        print(f"  Título: {normalized['title']}")
        print(f"  Severidade: {normalized['severity']}")
        print(f"  Score: {normalized['score']}")
        print(f"  Descrição: {normalized['description'][:100]}...")
        
        if normalized.get('aliases'):
            print(f"  Aliases: {', '.join(normalized['aliases'][:3])}")
        
        if normalized.get('affected_products'):
            print(f"  Produtos afetados: {len(normalized['affected_products'])}")
        
        return True
    except Exception as e:
        print(f"✗ Erro ao normalizar: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_aggregator():
    """Testa o agregador com OSV."""
    print("\n" + "=" * 70)
    print("Teste 3: Agregador com OSV")
    print("=" * 70)
    
    print("\nInicializando agregador...")
    aggregator = VulnerabilityAggregator()
    
    # Verifica fontes
    available = aggregator.get_available_sources()
    print(f"✓ Fontes disponíveis: {', '.join(available)}")
    
    if "OSV" not in available:
        print("✗ OSV não está disponível no agregador")
        return False
    
    # Testa busca
    print("\nBuscando vulnerabilidades para express 4.17.1...")
    try:
        vulns = aggregator.fetch_vulnerabilities("express", version="4.17.1", ecosystem="npm")
        print(f"✓ Encontradas {len(vulns)} vulnerabilidades")
        
        if vulns:
            # Gera estatísticas
            stats = aggregator.get_statistics(vulns)
            print(f"\nEstatísticas:")
            print(f"  Total: {stats['total']}")
            print(f"  Por severidade: {stats['by_severity']}")
            print(f"  Score médio: {stats['average_score']}")
            
            # Mostra vulnerabilidade mais crítica
            critical = sorted(vulns, key=lambda v: v['score'], reverse=True)[0]
            print(f"\nVulnerabilidade mais crítica:")
            print(f"  {critical['id']} - {critical['severity']} (Score: {critical['score']})")
        
        return True
    except Exception as e:
        print(f"✗ Erro ao usar agregador: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Executa todos os testes."""
    print("\n🔍 Iniciando testes de integração OSV\n")
    
    results = []
    
    # Executa testes
    results.append(("Cliente OSV", test_osv_client()))
    results.append(("Normalizador", test_normalizer()))
    results.append(("Agregador", test_aggregator()))
    
    # Resumo
    print("\n" + "=" * 70)
    print("RESUMO DOS TESTES")
    print("=" * 70)
    
    for test_name, result in results:
        status = "✓ PASSOU" if result else "✗ FALHOU"
        print(f"{test_name}: {status}")
    
    all_passed = all(result for _, result in results)
    
    if all_passed:
        print("\n🎉 Todos os testes passaram!")
        return 0
    else:
        print("\n⚠ Alguns testes falharam")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
