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

Ferramenta de linha de comando para mapear dependências, consultar vulnerabilidades
e gerar relatórios HTML detalhados para projetos Node.js/Ionic e Java.

RECURSOS PRINCIPAIS:

  • Detecção automática de manifests e lockfiles suportados

  • Busca de vulnerabilidades agregando OSV + NVD + Sonatype Guide

  • Cache local para acelerar consultas repetidas de vulnerabilidades

  • Verificação de versões mais recentes para pacotes npm/Ionic

  • Relatórios interativos em HTML com abas, métricas e recomendações

ARQUIVOS SUPORTADOS:

  • Node.js/Ionic: package.json, package-lock.json, npm-shrinkwrap.json

  • Java: pom.xml, build.xml, build.gradle, build.gradle.kts, gradle.lockfile

CONFIGURAÇÃO OPCIONAL:

  • Defina NVD_API_KEY em .env para ampliar consultas ao NVD

  • Para Sonatype Guide, use `bscan sonatype-guide-key --prompt`

  • O OSV funciona sem credenciais e o cache do módulo de ingestão é usado automaticamente

Para começar, use: bscan scan --help
"""

SCAN_HELP = """\
🚀 Executa uma varredura completa de dependências no projeto alvo

Esta operação percorre recursivamente o diretório especificado, identifica
manifests e lockfiles suportados, extrai dependências diretas e transitivas
quando disponíveis e gera um relatório estruturado no final.

📋 COMPORTAMENTO DA VARREDURA:

  🔍 Ignora automaticamente diretórios comuns (node_modules, .git, __pycache__, etc.)

  📦 Analisa projetos Node.js/Ionic e Java a partir de manifests e lockfiles suportados

  🧬 Oculta dependências transitivas por padrão quando vierem de lockfiles; use --include-transitive para incluí-las

  🛡️ Consulta vulnerabilidades agregando OSV + NVD + Sonatype Guide, com cache local para acelerar novas execuções

  🔑 Carrega NVD_API_KEY automaticamente de um arquivo .env quando disponível

  ⬆️ Consulta versões mais recentes para dependências npm/Ionic

  ⏱️  Exibe progresso em tempo real com interface rica

  📊 Salva um relatório HTML interativo na pasta reports/ com nome timestampado por padrão

💡 EXEMPLOS DE USO:

  bscan scan                              # Varre o diretório atual

  bscan scan --project ./meu-projeto      # Varre um diretório específico  

  bscan scan -p ../backend -o deps.html   # Projeto + saída personalizada

  bscan scan --url /opt/apps/webapp       # Modo compatibilidade wapiti

  bscan scan --skip-vulns                 # Pula consultas de vulnerabilidades e acelera a execução

  bscan scan --include-transitive         # Inclui dependências transitivas no relatório e na análise

  bscan scan --offline                    # Usa somente o banco local de vulnerabilidades (sem consultas online)

  bscan scan -u ~/projetos/api --output relatorio.html  # URL + saída customizada

⚠️  DICAS IMPORTANTES:

  • Se --url for informado, ele tem prioridade sobre --project

  • A NVD API key é opcional, mas melhora a integração com o NVD

  • O arquivo informado em --output é salvo dentro de reports/

  • Para projetos grandes, a varredura e as consultas online podem levar alguns segundos
"""

# Textos específicos para opções
PROJECT_OPTION_HELP = """Especifica o diretório raiz do projeto a ser analisado.

Deve ser um diretório existente e acessível. O scanner percorrerá
recursivamente os subdiretórios procurando manifests e lockfiles suportados
como package.json, pom.xml, build.gradle e gradle.lockfile."""

URL_OPTION_HELP = """Modo alternativo de especificação do alvo (compatibilidade com wapiti).

Quando especificado, este parâmetro sobrepõe o --project e trata o valor
como caminho direto para o diretório do projeto."""

OUTPUT_OPTION_HELP = """Define o arquivo de saída para o relatório HTML gerado.

O nome informado será salvo dentro da pasta reports/. O relatório inclui
dependências encontradas, vulnerabilidades agregadas, componentes desatualizados
e indicadores sobre dependências transitivas quando aplicável."""

SKIP_VULNS_OPTION_HELP = """Pula a etapa de consulta a vulnerabilidades externas.

Útil para execuções mais rápidas ou ambientes offline. O relatório ainda
mostra dependências encontradas e, quando possível, versões mais recentes."""

INCLUDE_TRANSITIVE_OPTION_HELP = """Inclui dependências transitivas no relatório e na análise.

Por padrão, dependências transitivas extraídas de lockfiles são ocultadas para
reduzir ruído visual. Ative esta opção para auditorias mais profundas."""

OFFLINE_OPTION_HELP = """Executa análise de vulnerabilidades usando apenas o banco local offline.

Não consulta APIs externas durante o scan. Ideal para ambientes sem internet.
Use o comando `bscan offline-db --sync --force` para atualizar o banco local."""
