# BasiliskScan (PT-BR)

Este arquivo contem a documentacao em portugues.

A documentacao principal para o PyPI esta em ingles no arquivo `README.md`.

## Banco Offline de Vulnerabilidades

- Caminho padrão do banco: `~/.basiliskscan/offline/offline_vulnerabilities.db`
- Override opcional: `BASILISKSCAN_OFFLINE_DB_DIR`

O banco vem embutido no pacote em `src/basiliskscan/data/offline/offline_vulnerabilities.db` e é copiado automaticamente no primeiro uso.

## Instalacao

```bash
pip install basiliskscan
```

### Instalacao automatica no Windows

Para instalar e deixar o `bscan` pronto no PowerShell, rode:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
./scripts/install_basiliskscan.ps1 -Editable
```

Isso instala o projeto em modo editavel, ajusta o PATH do usuario e cria o launcher `bscan`.

## Uso rapido

```bash
bscan --help
bscan scan
```

## Arquitetura (inspirada em MVC para CLI)

O projeto foi organizado em camadas para manter a CLI enxuta e facilitar testes:

- `controllers/`: orquestra fluxos (scan, offline DB, credenciais)
- `services/`: regras de negocio e integracoes (scanner, updater, ingest)
- `parsers/`: parsers por ecossistema focados apenas em extrair dependencias
- `reports/`: gerador de relatorio HTML e assets
- `views/`: UI do terminal, textos de ajuda e utilitarios de apresentacao
- `models/`: modelos de dominio (componentes, vulnerabilidades)

## Link util

- Repositorio: https://github.com/PuertA/basiliskscan
- Issues: https://github.com/PuertA/basiliskscan/issues

