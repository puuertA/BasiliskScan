# BasiliskScan 🔍

<div align="center">

<img src="https://github.com/puuertA/BasiliskScan/blob/main/resources/logo.png" alt="BasiliskScan Logo" width="500" height="500">

```
                            ██████╗  █████╗ ███████╗██╗██╗     ██╗███████╗██╗  ██╗
                            ██╔══██╗██╔══██╗██╔════╝██║██║     ██║██╔════╝██║ ██╔╝
                            ██████╔╝███████║███████╗██║██║     ██║███████╗█████╔╝ 
                            ██╔══██╗██╔══██║╚════██║██║██║     ██║╚════██║██╔═██╗ 
                            ██████╔╝██║  ██║███████║██║███████╗██║███████║██║  ██╗
                            ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
```

**Uma ferramenta avançada de linha de comando para análise abrangente de dependências em projetos de software**

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.0.1-red.svg)](https://github.com/PuertA/basiliskscan)

</div>

## 📋 Sobre o Projeto

BasiliskScan é uma ferramenta poderosa e intuitiva desenvolvida para identificar, catalogar e reportar dependências vulneráveis e desatualizadas em projetos de software. Com suporte a múltiplos ecossistemas e uma interface rica em recursos, o BasiliskScan é essencial para manter a segurança e atualização de suas dependências.

### 🎯 Objetivos Principais

- **Análise Abrangente**: Varredura recursiva de projetos identificando todas as dependências
- **Múltiplos Ecossistemas**: Suporte para Node.js (npm) e Python (pip)
- **Relatórios Interativos**: Saída em HTML com interface rica e navegação por abas
- **Interface Rica**: Barras de progresso e feedback visual em tempo real
- **Filtragem Inteligente**: Ignora automaticamente diretórios desnecessários

## ✨ Recursos Principais

### 🔍 **Detecção Automática**
- Identifica automaticamente arquivos de dependências suportados
- Percorre recursivamente toda a estrutura do projeto
- Filtra inteligentemente diretórios irrelevantes (`node_modules`, `.git`, `__pycache__`, etc.)

### 📦 **Ecossistemas Suportados**
- **Node.js**: `package.json` (dependencies, devDependencies, peerDependencies)
- **Python**: `requirements.txt` (versões fixas e flexíveis)

### 🔐 **Módulo de Ingestão de Vulnerabilidades** *(NOVO!)*
- **NVD (National Vulnerability Database)**: Integração com API 2.0 do NIST
- **OSS Index**: Suporte a Sonatype OSS Index API v3
- **Normalização**: Dados padronizados de múltiplas fontes
- **Agregação**: Busca paralela e mesclagem inteligente de vulnerabilidades
- Ver: [Documentação do Módulo de Ingestão](src/basiliskscan/ingest/README.md)

### 📊 **Relatórios Interativos**
- Saída em formato HTML com interface moderna e responsiva
- Navegação por abas para diferentes categorias de componentes
- Logo personalizado e visual profissional
- Metadados completos e estatísticas detalhadas por ecossistema
- Preparado para futuras funcionalidades de vulnerabilidades

### 🎨 **Interface Rica**
- Barras de progresso em tempo real durante o scan
- Código de cores para diferentes tipos de informação
- Mensagens de status claras e informativas
- Logo ASCII artístico no terminal
- Relatórios HTML interativos com design moderno

## 🚀 Instalação

### Pré-requisitos
- Python 3.10 ou superior
- pip (gerenciador de pacotes Python)

### Instalação via PyPI (em breve)
```bash
pip install basiliskscan
```

### Instalação para Desenvolvimento
```bash
# Clone o repositório
git clone https://github.com/PuertA/basiliskscan.git
cd basiliskscan

# Instale em modo desenvolvimento
pip install -e .
```

### Verificação da Instalação
```bash
# Teste a instalação
bscan --version
bscan --help
```

### Configurando a API key do NVD
Crie um arquivo `.env` no diretório onde você executa o `bscan`:

```env
NVD_API_KEY=sua-api-key-do-nvd
```

O BasiliskScan carrega esse arquivo automaticamente ao iniciar a CLI e usa a chave nas consultas ao NVD.

## 📖 Guia de Uso

### Comando Básico
```bash
# Varredura do diretório atual
bscan scan

# Varredura de um projeto específico
bscan scan --project /caminho/para/projeto

# Varredura com arquivo de saída personalizado
bscan scan --project ./meu-app --output relatorio-deps.html
```

### Opções Disponíveis

| Opção | Alias | Descrição | Padrão |
|-------|-------|-----------|--------|
| `--project` | `-p` | Diretório do projeto a ser analisado | `.` (atual) |
| `--url` | `-u` | Modo alternativo de especificação do projeto | - |
| `--output` | `-o` | Arquivo de saída para o relatório HTML | `dependencies_report.html` |
| `--offline` | - | Usa apenas o banco local de vulnerabilidades (sem consultas online) | `false` |
| `--help` | `-h` | Exibe ajuda detalhada | - |

### Exemplos Práticos

#### 1. Análise Básica
```bash
bscan scan
```

#### 2. Projeto Específico com Saída Customizada
```bash
bscan scan --project ../meu-backend --output backend-deps.html
```

#### 3. Usando Modo URL (compatibilidade wapiti)
```bash
bscan scan --url /opt/aplicacoes/webapp --output webapp-analysis.html
```

#### 4. Análise de Projeto Python
```bash
bscan scan --project ./api-python --output api-dependencies.html
```

#### 5. Visualizando o Relatório
```bash
# Após a execução, abra o arquivo HTML gerado no seu navegador
# O relatório inclui logo, navegação por abas e interface interativa

# Exemplo: abrir no navegador padrão (Windows)
start dependencies_report.html

# Exemplo: abrir no navegador padrão (Linux/Mac)
open dependencies_report.html
```

### Banco Offline de Vulnerabilidades

O BasiliskScan mantém um banco local consolidado para permitir execução offline.

- Caminho padrão do banco: `resources/offline/offline_vulnerabilities.db`
- Override opcional por variável de ambiente: `BASILISKSCAN_OFFLINE_DB_DIR`

```bash
# Ver status e estatísticas do banco local
bscan offline-db --status

# Sincronização semanal/manual de componentes vencidos
bscan offline-db --sync

# Força atualização completa de todos os componentes rastreados
bscan offline-db --sync --force

# Atualiza banco com base nas dependências de um projeto específico
bscan offline-db --sync --project ./meu-projeto

# Executa o scan usando somente dados locais
bscan scan --offline
```

## 📊 Formato de Saída

O BasiliskScan gera relatórios em formato HTML interativo com:

### 🎨 **Interface Moderna**
- **Design responsivo** com tema escuro profissional
- **Logo personalizado** do BasiliskScan no topo
- **Navegação por abas** para diferentes categorias:
  - 📦 **Todos os Componentes**: Lista completa de dependências encontradas
  - 🚨 **Componentes Vulneráveis**: Preparado para futuras integrações de segurança
  - ⚠️ **Componentes Desatualizados**: Preparado para verificação de versões

### 📋 **Informações Detalhadas**
- **Metadados do Scan**: Data, ferramenta, versão, diretório analisado
- **Estatísticas Resumidas**: Contadores visuais de componentes por categoria
- **Detalhes dos Componentes**: Nome, versão, ecossistema, arquivo de origem
- **Badges Coloridos**: Identificação visual por ecossistema (npm, pypi, etc.)

### 🔍 **Componentes Interativos**
- **Hover Effects**: Destaque visual ao passar mouse sobre componentes
- **Animações Suaves**: Logo animado e transições elegantes
- **Estrutura Extensível**: Preparada para futuras funcionalidades de vulnerabilidades

## 🏗️ Arquitetura do Projeto

O BasiliskScan foi desenvolvido com uma arquitetura modular e extensível:

```
src/basiliskscan/
├── cli.py                 # Ponto de entrada CLI principal
├── config.py              # Configurações e constantes globais
├── help_text.py          # Textos de ajuda e mensagens
├── parsers.py            # Parsers para arquivos de dependências
├── scanner.py            # Sistema de varredura e descoberta
├── reporter.py           # Geração de relatórios e saídas
├── ui.py                 # Interface de usuário e componentes visuais
└── commands/
    └── scan.py           # Implementação do comando scan
```

### Componentes Principais

- **🔍 Scanner**: Descoberta e coleta de arquivos de dependências
- **📝 Parsers**: Análise específica por tipo de arquivo (package.json, requirements.txt)
- **📊 Reporter**: Geração de relatórios estruturados e apresentação de resultados
- **🎨 UI**: Interface rica com barras de progresso e feedback visual

## 🛠️ Desenvolvimento

### Configuração do Ambiente
```bash
# Clone o projeto
git clone https://github.com/PuertA/basiliskscan.git
cd basiliskscan

# Crie um ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

# Instale dependências de desenvolvimento
pip install -e ".[dev]"
```

### Demonstração do Módulo de Ingestão
```bash
# Execute a demonstração
python demo_ingest.py

# Ou rode os exemplos completos
python -m basiliskscan.ingest.example_usage
```

### Estrutura de Dependências
- **click**: Interface de linha de comando
- **requests**: Requisições HTTP para APIs de vulnerabilidades
- **packaging**: Manipulação de versões de pacotes
- **rich**: Interface rica e colorida no terminal
- **python-dateutil**: Manipulação de datas

### Contribuindo

1. **Fork** o projeto
2. Crie uma **branch** para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. **Commit** suas mudanças (`git commit -am 'Adiciona nova funcionalidade'`)
4. **Push** para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um **Pull Request**

## 🔮 Roadmap

### Versão 0.1.0 (EM DESENVOLVIMENTO)
- [x] **Módulo de ingestão de vulnerabilidades**
  - [x] Cliente NVD (National Vulnerability Database)
  - [x] Cliente OSS Index (Sonatype)
  - [x] Normalização de dados de múltiplas fontes
  - [x] Agregador com busca paralela
- [ ] Integração do módulo de ingestão com o scanner
- [ ] Correlação automática de versões vulneráveis
- [ ] Suporte a mais formatos de dependências (Pipfile, yarn.lock, composer.json)
- [ ] Relatórios em formatos adicionais (CSV, XML, JSON)
- [ ] Cache de resultados para execuções subsequentes

### Versão 0.2.0
- [ ] Análise de dependências transitivas
- [ ] Verificação de licenças de pacotes
- [ ] Comando de atualização automática de dependências
- [ ] Interface web para visualização de relatórios
- [ ] GitHub Advisory Database integration

### Versão 1.0.0
- [ ] Sistema de plugins extensível
- [ ] Integração com CI/CD
- [ ] API REST para integração com outras ferramentas
- [ ] Dashboard de monitoramento contínuo

## 📝 Casos de Uso

### 🏢 **Empresas e Organizações**
- Auditoria de segurança em projetos corporativos
- Compliance e verificação de licenças
- Monitoramento contínuo de dependências em CI/CD

### 👨‍💻 **Desenvolvedores**
- Análise rápida de projetos herdados
- Verificação de saúde de dependências antes de releases
- Identificação de dependências obsoletas

### 🎓 **Pesquisadores e Academia**
- Estudos sobre ecossistemas de software
- Análise de vulnerabilidades em larga escala
- Pesquisa sobre evolução de dependências

## ⚠️ Limitações Conhecidas

- Atualmente suporta apenas `package.json` e `requirements.txt`
- Não analisa dependências transitivas (ainda)
- Não verifica vulnerabilidades em tempo real
- Limitado a projetos no sistema de arquivos local

## 📄 Licença

Este projeto está licenciado sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## 👥 Autores

- **PuertA** - *Desenvolvimento inicial* - [GitHub](https://github.com/PuertA)

## 🤝 Agradecimentos

- Comunidade Python e click pela excelente documentação
- Projeto Rich pela biblioteca de interface rica
- Comunidade open source por inspiração e feedback

## 📞 Contato

- **Issues**: [GitHub Issues](https://github.com/PuertA/basiliskscan/issues)
- **Discussions**: [GitHub Discussions](https://github.com/PuertA/basiliskscan/discussions)

---

<div align="center">

**Feito com ❤️ para a comunidade de desenvolvedores**

⭐ **Se este projeto foi útil, considere dar uma estrela!** ⭐

</div>
