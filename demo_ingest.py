#!/usr/bin/env python3
"""
Script de demonstração rápida do módulo de ingestão.
Busca vulnerabilidades para componentes comuns e exibe estatísticas.
"""

import sys
from basiliskscan.ingest import VulnerabilityAggregator


def main():
    print("=" * 70)
    print("  BasiliskScan - Demonstração do Módulo de Ingestão")
    print("=" * 70)
    print()
    
    # Inicializa agregador
    print("Inicializando agregador de vulnerabilidades...")
    aggregator = VulnerabilityAggregator()
    
    # Verifica fontes disponíveis
    available = aggregator.get_available_sources()
    if not available:
        print("❌ Nenhuma fonte de vulnerabilidades disponível!")
        print("   Verifique sua conexão com a internet.")
        return 1
    
    print(f"✓ Fontes disponíveis: {', '.join(available)}")
    print()
    
    # Componentes de teste
    test_cases = [
        {
            "name": "log4j-core",
            "version": "2.14.1",
            "ecosystem": "maven",
            "description": "Apache Log4j (vulnerabilidade famosa Log4Shell)"
        },
        {
            "name": "express",
            "version": "4.17.1",
            "ecosystem": "npm",
            "description": "Express.js framework"
        },
        {
            "name": "lodash",
            "version": "4.17.20",
            "ecosystem": "npm",
            "description": "Lodash utility library"
        },
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"[{i}/{len(test_cases)}] Testando: {test['description']}")
        print(f"      Componente: {test['name']} v{test.get('version', 'latest')}")
        
        try:
            vulns = aggregator.fetch_vulnerabilities(
                test['name'],
                version=test.get('version'),
                ecosystem=test.get('ecosystem'),
                parallel=True
            )
            
            if vulns:
                print(f"      ✓ Encontradas {len(vulns)} vulnerabilidades")
                
                # Estatísticas
                stats = aggregator.get_statistics(vulns)
                print(f"      Severidades: ", end="")
                for sev, count in stats['by_severity'].items():
                    print(f"{sev}={count} ", end="")
                print()
                print(f"      Score médio: {stats['average_score']:.1f}/10.0")
                
                # Exibe as 2 mais críticas
                critical_vulns = sorted(vulns, key=lambda v: v['score'], reverse=True)[:2]
                for vuln in critical_vulns:
                    print(f"        - {vuln['id']} ({vuln['severity']}, {vuln['score']})")
            else:
                print(f"      ✓ Nenhuma vulnerabilidade encontrada")
            
        except Exception as e:
            print(f"      ❌ Erro: {e}")
        
        print()
    
    print("=" * 70)
    print("  Demonstração concluída!")
    print("=" * 70)
    print()
    print("💡 Dicas:")
    print("  - O OSV.dev é uma base de dados pública e gratuita")
    print("  - Suporta múltiplos ecosistemas: npm, Maven, PyPI, Go, etc.")
    print()
    print("  - Veja mais exemplos em: src/basiliskscan/ingest/example_usage.py")
    print("  - Documentação completa: src/basiliskscan/ingest/README.md")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
