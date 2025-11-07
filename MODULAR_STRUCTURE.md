# Estrutura Modular do BasiliskScan - Documentação

## 📁 Nova Estrutura de Arquivos

```
src/basiliskscan/
├── __init__.py                 # Ponto de entrada do package
├── cli.py                      # CLI principal (simplificado)
├── config.py                   # Configurações e constantes globais
├── help_text.py               # Textos de help e mensagens
├── parsers.py                 # Parsers de arquivos de dependências
├── scanner.py                 # Descoberta e coleta de arquivos
├── reporter.py                # Geração de relatórios
├── ui.py                      # Interface e classes Click customizadas
└── commands/                  # Comandos CLI organizados
    ├── __init__.py
    └── scan.py                # Comando de varredura
```

## 🔄 Responsabilidades dos Módulos

### 📋 `config.py`
**Propósito**: Centralizações de configurações
- Constantes globais (IGNORED_DIRS, SUPPORTED_FILES)
- Informações da aplicação (nome, versão, descrição)
- Mapeamentos (ecossistemas → emojis)
- Configurações padrão

### 🔍 `parsers.py`
**Propósito**: Análise de arquivos de dependências
- `DependencyParser.parse_package_json()` - Parser para package.json
- `DependencyParser.parse_requirements_txt()` - Parser para requirements.txt
- `get_parser_for_file()` - Factory para selecionar parser apropriado
- Tratamento robusto de erros de parsing

### 📂 `scanner.py`  
**Propósito**: Descoberta e varredura de projetos
- `DependencyScanner.find_dependency_files()` - Busca arquivos suportados
- `DependencyScanner.collect_dependencies()` - Orquestra a coleta completa
- `DependencyScanner.get_project_statistics()` - Calcula estatísticas
- Caminhada recursiva com filtros inteligentes

### 📊 `reporter.py`
**Propósito**: Geração e apresentação de relatórios  
- `ReportGenerator.generate_report_data()` - Estrutura dados do relatório
- `ReportGenerator.save_report_to_file()` - Persistência em JSON
- `ReportGenerator.display_scan_results()` - Output formatado no console
- `SummaryReporter.generate_dependency_summary()` - Resumos estatísticos

### 🎨 `ui.py`
**Propósito**: Interface de usuário e experiência
- `BasiliskCommand` / `BasiliskGroup` - Classes Click personalizadas
- `UIHelper` - Mensagens formatadas (sucesso, erro, aviso)
- Funções de validação (`validate_target_path()`)  
- Tratamento de erros padronizado

### ⚡ `commands/scan.py`
**Propósito**: Implementação do comando de varredura
- Lógica completa do comando `bscan scan`
- Orquestração de todos os componentes
- Tratamento de parâmetros CLI
- Fluxo de execução da varredura

### 🚪 `cli.py` (Refatorado)
**Propósito**: Ponto de entrada minimalista
- Configuração do grupo CLI principal  
- Registro de comandos
- Apenas 25 linhas vs 150+ anteriores!

## ✅ Benefícios da Refatoração

### 🏗️ **Melhor Organização**
- **Separação clara de responsabilidades** - Cada módulo tem uma função específica
- **Redução de acoplamento** - Módulos independentes com interfaces bem definidas
- **Facilidade de manutenção** - Mudanças isoladas em funcionalidades específicas

### 🧪 **Testabilidade Aprimorada**
- **Testagem isolada** - Cada parser, scanner e reporter pode ser testado independentemente
- **Mocks facilitados** - Interfaces claras permitem substituições para testes
- **Cobertura granular** - Testes específicos para cada responsabilidade

### 📈 **Escalabilidade**
- **Novos parsers** - Adicionar suporte a novos formatos (Pipfile, yarn.lock, etc.)
- **Novos comandos** - Fácil adição de comandos como `validate`, `update`, `audit`
- **Novos formatos de saída** - CSV, XML, YAML além do JSON atual

### 🔧 **Extensibilidade**
- **Plugins** - Arquitetura preparada para sistema de plugins
- **Configurações** - Centralizadas e facilmente expandíveis  
- **Parsers customizados** - Interface clara para novos tipos de arquivo

### 📝 **Manutenibilidade**
- **Código mais limpo** - Funções menores e com propósito único
- **Debugging facilitado** - Problemas isolados em módulos específicos  
- **Documentação modular** - Cada arquivo documenta sua área de responsabilidade

## 🛠️ Como Adicionar Novas Funcionalidades

### Novo Parser (ex: Pipfile)
1. Adicionar `parse_pipfile()` em `parsers.py`
2. Atualizar `get_parser_for_file()` 
3. Adicionar "Pipfile" em `SUPPORTED_FILES` no `config.py`

### Novo Comando (ex: validate)
1. Criar `commands/validate.py` 
2. Implementar `validate_command()`
3. Registrar em `cli.py`: `cli.add_command(validate_command)`

### Novo Formato de Saída (ex: CSV)
1. Adicionar `CsvReporter` em `reporter.py`
2. Implementar `save_report_to_csv()`  
3. Adicionar opção `--format` no comando scan

Esta estrutura modular torna o BasiliskScan muito mais profissional, extensível e fácil de manter! 🚀