# src/basiliskscan/help_text.py

LOGO = r"""
██████╗  █████╗ ███████╗██╗██╗     ██╗███████╗██╗  ██╗
██╔══██╗██╔══██╗██╔════╝██║██║     ██║██╔════╝██║ ██╔╝
██████╔╝███████║███████╗██║██║     ██║███████╗█████╔╝ 
██╔══██╗██╔══██║╚════██║██║██║     ██║╚════██║██╔═██╗ 
██████╔╝██║  ██║███████║██║███████╗██║███████║██║  ██╗
╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
"""

APP_DESCRIPTION = """\
🔍 BasiliskScan - Ferramenta Avançada de Análise de Dependências

Uma poderosa ferramenta de linha de comando para análise abrangente de projetos de software,
especializada em identificar, catalogar e reportar dependências vulneráveis e desatualizadas.

RECURSOS PRINCIPAIS:

  • Suporte a múltiplos ecossistemas (npm, pip, etc.)

  • Detecção automática de arquivos de dependências

  • Relatórios interativos em HTML com abas dinâmicas

  • Interface rica com barras de progresso

  • Filtragem inteligente de diretórios desnecessários

ARQUIVOS SUPORTADOS:

  • package.json (Node.js/npm)

  • requirements.txt (Python/pip)

Para começar, use: bscan scan --help
"""

SCAN_HELP = """\
🚀 Executa uma varredura completa de dependências no projeto alvo

Esta operação percorre recursivamente o diretório especificado, identifica
arquivos de dependências suportados e extrai informações detalhadas sobre
cada dependência declarada, gerando um relatório estruturado.

📋 COMPORTAMENTO DA VARREDURA:

  🔍 Ignora automaticamente diretórios comuns (node_modules, .git, __pycache__, etc.)

  📦 Processa dependências, devDependencies e peerDependencies do package.json  

  🐍 Analisa requirements.txt com suporte a versões fixas e flexíveis

  ⏱️  Exibe progresso em tempo real com interface rica

  📊 Gera relatório HTML interativo com abas e navegação dinâmica

💡 EXEMPLOS DE USO:

  bscan scan                              # Varre o diretório atual

  bscan scan --project ./meu-projeto      # Varre um diretório específico  

  bscan scan -p ../backend -o deps.html   # Projeto + saída personalizada

  bscan scan --url /opt/apps/webapp       # Modo compatibilidade wapiti

  bscan scan -u ~/projetos/api --output relatorio.html  # URL + saída customizada

⚠️  DICAS IMPORTANTES:

  • Use caminhos absolutos para evitar ambiguidades

  • O arquivo de saída será sobrescrito se já existir  

  • Para projetos grandes, a varredura pode levar alguns segundos

  • Certifique-se de ter permissão de leitura no diretório alvo
"""

# Textos específicos para opções
PROJECT_OPTION_HELP = """Especifica o diretório raiz do projeto a ser analisado.

Deve ser um diretório existente e acessível. O scanner percorrerá
recursivamente todos os subdiretórios procurando por arquivos de dependências."""

URL_OPTION_HELP = """Modo alternativo de especificação do alvo (compatibilidade com wapiti).

Quando especificado, este parâmetro sobrepõe o --project e trata o valor
como caminho direto para o diretório do projeto."""

OUTPUT_OPTION_HELP = """Define o arquivo de saída para o relatório HTML gerado.

O arquivo será um relatório interativo com abas navegáveis, contendo
informações detalhadas sobre dependências, vulnerabilidades e componentes desatualizados."""
