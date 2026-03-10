# Módulo de Ingestão de Vulnerabilidades

Este módulo fornece funcionalidade para ingerir dados de vulnerabilidades de múltiplas fontes externas.

## Fontes Suportadas

### 1. NVD (National Vulnerability Database)
- API 2.0 do NIST
- Dados completos de CVEs
- Suporte a CVSS v2, v3.0 e v3.1
- Rate limiting automático

### 2. OSS Index (Sonatype)
- API v3 do OSS Index
- Suporte a múltiplos ecosistemas (npm, maven, pypi, etc.)
- Package URL (purl) support
- Batch queries (até 128 componentes por request)

## Instalação

As dependências já estão incluídas no `pyproject.toml`. Para usar:

```bash
pip install -e .
```

## Uso Básico

### Cliente NVD

```python
from basiliskscan.ingest import NVDClient, VulnerabilityNormalizer

# Inicializar cliente (API key opcional mas recomendada)
nvd = NVDClient(api_key="sua-api-key")

# Buscar vulnerabilidades
vulns = nvd.fetch_vulnerabilities("log4j", version="2.14.1")

# Normalizar dados
for vuln_data in vulns:
    normalized = VulnerabilityNormalizer.normalize_nvd_vulnerability(vuln_data)
    print(f"{normalized['id']}: {normalized['severity']}")

# Buscar CVE específico
cve = nvd.fetch_cve_by_id("CVE-2021-44228")

# Buscar vulnerabilidades recentes
recent = nvd.fetch_recent_vulnerabilities(days=7)
```

### Cliente OSS Index

```python
from basiliskscan.ingest import OSSIndexClient, VulnerabilityNormalizer

# Inicializar cliente
oss = OSSIndexClient(username="seu-username", api_key="seu-token")

# Buscar vulnerabilidades para um componente
components = oss.fetch_vulnerabilities(
    "express",
    version="4.17.1",
    ecosystem="npm"
)

# Normalizar dados
for component in components:
    vulns = VulnerabilityNormalizer.normalize_oss_index_component(component)
    for vuln in vulns:
        print(f"{vuln['id']}: {vuln['severity']}")

# Buscar por Package URL
purls = [
    "pkg:npm/express@4.17.1",
    "pkg:maven/org.springframework/spring-core@5.2.0"
]
results = oss.fetch_by_purl(purls)
```

### Normalização de Dados

```python
from basiliskscan.ingest import VulnerabilityNormalizer

# Normalizar vulnerabilidade do NVD
nvd_vuln = nvd.fetch_cve_by_id("CVE-2021-44228")
normalized_nvd = VulnerabilityNormalizer.normalize_nvd_vulnerability(nvd_vuln)

# Normalizar vulnerabilidades do OSS Index
oss_components = oss.fetch_vulnerabilities("express", ecosystem="npm")
for component in oss_components:
    normalized_oss = VulnerabilityNormalizer.normalize_oss_index_component(component)

# Mesclar vulnerabilidades de múltiplas fontes
all_vulns = normalized_nvd + normalized_oss
merged = VulnerabilityNormalizer.merge_vulnerabilities(all_vulns)
```

## Formato Normalizado

Todas as vulnerabilidades são normalizadas para o seguinte formato:

```python
{
    "id": "CVE-2021-44228",           # ID da vulnerabilidade
    "source": "NVD",                   # Fonte original
    "title": "Log4j RCE",              # Título
    "description": "...",              # Descrição completa
    "severity": "CRITICAL",            # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    "score": 10.0,                     # Score CVSS
    "cvss": {                          # Dados CVSS completos
        "version": "3.1",
        "vector": "CVSS:3.1/AV:N/...",
        "score": 10.0,
        "severity": "CRITICAL"
    },
    "published": "2021-12-10T...",     # Data de publicação
    "modified": "2022-01-05T...",      # Data de modificação
    "references": [...],               # Links de referência
    "affected_products": [...],        # Produtos/versões afetados
    "cwe": ["CWE-502"],               # Tipos de fraqueza
    "raw_data": {...}                  # Dados originais completos
}
```

## Rate Limiting

### NVD
- Sem API key: 5 requests / 30 segundos
- Com API key: 50 requests / 30 segundos
- Rate limiting implementado automaticamente

### OSS Index
- Sem autenticação: sem limite documentado, mas recomenda-se moderação
- Com autenticação: rate limits mais altos
- Batch queries recomendadas (até 128 componentes)

## API Keys

### NVD
Obtenha uma API key em: https://nvd.nist.gov/developers/request-an-api-key

```python
nvd = NVDClient(api_key="sua-nvd-api-key")
```

### OSS Index
Crie uma conta em: https://ossindex.sonatype.org/

```python
oss = OSSIndexClient(
    username="seu-email",
    api_key="seu-token"
)
```

## Exemplos

Veja `example_usage.py` para exemplos completos de uso.

## Estrutura do Módulo

```
ingest/
├── __init__.py           # Exports principais
├── base.py              # Interface base VulnerabilitySource
├── nvd.py               # Cliente NVD
├── oss_index.py         # Cliente OSS Index
├── normalizer.py        # Normalizador de dados
├── example_usage.py     # Exemplos de uso
└── README.md           # Esta documentação
```
