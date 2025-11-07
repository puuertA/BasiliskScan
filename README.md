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
- **Relatórios Detalhados**: Saída estruturada em JSON com metadados completos
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

### 📊 **Relatórios Estruturados**
- Saída em formato JSON estruturado
- Metadados completos do projeto analisado
- Estatísticas detalhadas por ecossistema
- Timestamp e informações de execução

### 🎨 **Interface Rica**
- Barras de progresso em tempo real
- Código de cores para diferentes tipos de informação
- Mensagens de status claras e informativas
- Logo ASCII artístico

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

## 📖 Guia de Uso

### Comando Básico
```bash
# Varredura do diretório atual
bscan scan

# Varredura de um projeto específico
bscan scan --project /caminho/para/projeto

# Varredura com arquivo de saída personalizado
bscan scan --project ./meu-app --output relatorio-deps.json
```

### Opções Disponíveis

| Opção | Alias | Descrição | Padrão |
|-------|-------|-----------|--------|
| `--project` | `-p` | Diretório do projeto a ser analisado | `.` (atual) |
| `--url` | `-u` | Modo alternativo de especificação do projeto | - |
| `--output` | `-o` | Arquivo de saída para o relatório JSON | `dependencies_report.json` |
| `--help` | `-h` | Exibe ajuda detalhada | - |

### Exemplos Práticos

#### 1. Análise Básica
```bash
bscan scan
```

#### 2. Projeto Específico com Saída Customizada
```bash
bscan scan --project ../meu-backend --output backend-deps.json
```

#### 3. Usando Modo URL (compatibilidade wapiti)
```bash
bscan scan --url /opt/aplicacoes/webapp --output webapp-analysis.json
```

#### 4. Análise de Projeto Python
```bash
bscan scan --project ./api-python --output api-dependencies.json
```

## 📊 Formato de Saída

O BasiliskScan gera relatórios em formato JSON estruturado:

```json
{
  "scan_metadata": {
    "tool_name": "BasiliskScan",
    "version": "0.0.1",
    "scan_timestamp": "2025-11-06T10:30:45",
    "target_directory": "/caminho/para/projeto",
    "output_file": "dependencies_report.json",
    "execution_time_seconds": 2.45
  },
  "project_statistics": {
    "total_dependencies": 25,
    "ecosystems": {
      "npm": 20,
      "pip": 5
    },
    "files_processed": {
      "package.json": 2,
      "requirements.txt": 1
    }
  },
  "dependencies": [
    {
      "name": "express",
      "version": "^4.18.0",
      "type": "dependency",
      "ecosystem": "npm",
      "file_path": "/projeto/package.json",
      "file_type": "package.json"
    }
  ]
}
```

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

### Estrutura de Dependências
- **click**: Interface de linha de comando
- **requests**: Requisições HTTP (funcionalidades futuras)
- **packaging**: Manipulação de versões de pacotes
- **rich**: Interface rica e colorida no terminal

### Contribuindo

1. **Fork** o projeto
2. Crie uma **branch** para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. **Commit** suas mudanças (`git commit -am 'Adiciona nova funcionalidade'`)
4. **Push** para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um **Pull Request**

## 🔮 Roadmap

### Versão 0.1.0
- [ ] Suporte a mais formatos de dependências (Pipfile, yarn.lock, composer.json)
- [ ] Integração com APIs de vulnerabilidades (CVE, npm audit)
- [ ] Relatórios em múltiplos formatos (CSV, XML, HTML)
- [ ] Cache de resultados para execuções subsequentes

### Versão 0.2.0
- [ ] Análise de dependências transitivas
- [ ] Verificação de licenças de pacotes
- [ ] Comando de atualização automática de dependências
- [ ] Interface web para visualização de relatórios

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
