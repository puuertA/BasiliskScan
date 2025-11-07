# src/basiliskscan/reporter.py
"""Módulo responsável pela geração de relatórios e apresentação de resultados."""

import pathlib
from datetime import datetime
from typing import Dict, List
from rich.console import Console

from .config import APP_NAME, APP_VERSION, ECOSYSTEM_EMOJIS


class ReportGenerator:
    """Gerador de relatórios de análise de dependências."""
    
    def __init__(self, console: Console = None):
        """
        Inicializa o gerador de relatórios.
        
        Args:
            console: Console do Rich para output formatado
        """
        self.console = console or Console()
    
    def generate_report_data(
        self, 
        target_path: pathlib.Path, 
        dependencies: List[Dict], 
        ecosystems: Dict, 
        output_file: str
    ) -> Dict:
        """
        Gera os dados estruturados do relatório.
        
        Args:
            target_path: Caminho do projeto analisado
            dependencies: Lista de dependências encontradas
            ecosystems: Estatísticas por ecossistema
            output_file: Arquivo de saída
            
        Returns:
            Dicionário com dados estruturados do relatório
        """
        return {
            "scan_metadata": {
                "tool": APP_NAME,
                "version": APP_VERSION,
                "scan_date": datetime.now().isoformat(),
                "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target_path": str(target_path),
                "output_file": output_file
            },
            "project_info": {
                "path": str(target_path),
                "dependency_count": len(dependencies),
                "ecosystems_found": ecosystems
            },
            "dependencies": dependencies
        }
    
    def generate_html_report(self, report_data: Dict) -> str:
        """
        Gera o HTML do relatório com abas interativas.
        
        Args:
            report_data: Dados do relatório
            
        Returns:
            String com o HTML completo do relatório
        """
        scan_metadata = report_data["scan_metadata"]
        project_info = report_data["project_info"]
        dependencies = report_data["dependencies"]
        
        # Separar componentes vulneráveis e desatualizados (preparação para futura integração)
        vulnerable_components = []  # Para futura integração com API
        outdated_components = []    # Para futura integração com API
        
        project_name = pathlib.Path(scan_metadata["target_path"]).name
        
        html_content = f'''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Basilisk - Relatório de Componentes - {project_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f1419 0%, #1a1a2e 50%, #16213e 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #1e1e1e;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.4);
            overflow: hidden;
            border: 1px solid #333;
        }}
        
        .header {{
            background: linear-gradient(135deg, #0f1419 0%, #1a1a2e 50%, #16213e 100%);
            color: #e0e0e0;
            padding: 40px;
            text-align: center;
            position: relative;
        }}
        
        .logo {{
            width: 100px;
            height: 100px;
            margin: 0 auto 20px;
            background-image: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgdmlld0JveD0iMCAwIDEwMCAxMDAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxkZWZzPgo8bGluZWFyR3JhZGllbnQgaWQ9InNoaWVsZCIgeDE9IjAlIiB5MT0iMCUiIHgyPSIxMDAlIiB5Mj0iMTAwJSI+CjxzdG9wIG9mZnNldD0iMCUiIHN0eWxlPSJzdG9wLWNvbG9yOiMxZTFlMWU7c3RvcC1vcGFjaXR5OjEiIC8+CjxzdG9wIG9mZnNldD0iNTAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMmEyYTJhO3N0b3Atb3BhY2l0eToxIiAvPgo8c3RvcCBvZmZzZXQ9IjEwMCUiIHN0eWxlPSJzdG9wLWNvbG9yOiM0MDQwNDA7c3RvcC1vcGFjaXR5OjEiIC8+CjwvbGluZWFyR3JhZGllbnQ+CjxsaW5lYXJHcmFkaWVudCBpZD0ic25ha2UiIHgxPSIwJSIgeTE9IjAlIiB4Mj0iMTAwJSIgeTI9IjEwMCUiPgo8c3RvcCBvZmZzZXQ9IjAlIiBzdHlsZT0ic3RvcC1jb2xvcjojNzZiOTAwO3N0b3Atb3BhY2l0eToxIiAvPgo8c3RvcCBvZmZzZXQ9IjUwJSIgc3R5bGU9InN0b3AtY29sb3I6Izg5Y2EyNjtzdG9wLW9wYWNpdHk6MSIgLz4KPHN0b3Agb2Zmc2V0PSIxMDAlIiBzdHlsZT0ic3RvcC1jb2xvcjojNjFhM2QzO3N0b3Atb3BhY2l0eToxIiAvPgo8L2xpbmVhckdyYWRpZW50Pgo8bGluZWFyR3JhZGllbnQgaWQ9ImV5ZSIgeDE9IjAlIiB5MT0iMCUiIHgyPSIxMDAlIiB5Mj0iMTAwJSI+CjxzdG9wIG9mZnNldD0iMCUiIHN0eWxlPSJzdG9wLWNvbG9yOiNmZmM1MDA7c3RvcC1vcGFjaXR5OjEiIC8+CjxzdG9wIG9mZnNldD0iMTAwJSIgc3R5bGU9InN0b3AtY29sb3I6I2Y5Y2E0MztzdG9wLW9wYWNpdHk6MSIgLz4KPC9saW5lYXJHcmFkaWVudD4KPHN0b3Agb2Zmc2V0PSIwJSIgc3R5bGU9InN0b3AtY29sb3I6I2ZmNDc1NjtzdG9wLW9wYWNpdHk6MSIgLz4KPHN0b3Agb2Zmc2V0PSI1MCUiIHN0eWxlPSJzdG9wLWNvbG9yOiNmZjM4NGU7c3RvcC1vcGFjaXR5OjEiIC8+CjxzdG9wIG9mZnNldD0iMTAwJSIgc3R5bGU9InN0b3AtY29sb3I6I2RjMzU0NTtzdG9wLW9wYWNpdHk6MSIgLz4KPC9saW5lYXJHcmFkaWVudD4KPC9kZWZzPgo8IS0tIE91dGVyIFNoaWVsZCAtLT4KPHA+YXRoIGQ9Ik01MCw1IEwxNSwxOCBMMTUsNjUgQzE1LDc4IDMwLDkwIDUwLDkwIEM3MCw5MCA4NSw3OCA4NSw2NSBMODUsMTggTDUwLDVaIiBmaWxsPSJ1cmwoI3NoaWVsZCkiIHN0cm9rZT0iIzQwNDA0MCIgc3Ryb2tlLXdpZHRoPSIyIi8+CjwhLS0gSW5uZXIgU2hpZWxkIC0tPgo8cGF0aCBkPSJNNTAsMTIgTDIyLDIyIEwyMiw2MiBDMjIsNzIgMzMsODAgNTAsODAgQzY3LDgwIDc4LDcyIDc4LDYyIEw3OCwyMiBMNTAsMTJaIiBmaWxsPSJub25lIiBzdHJva2U9IiM2MDYwNjAiIHN0cm9rZS13aWR0aD0iMSIvPgo8IS0tIEJhc2lsaXNrIEhlYWQgLS0+CjxlbGxpcHNlIGN4PSI1MCIgY3k9IjQwIiByeD0iMTgiIHJ5PSIxMiIgZmlsbD0idXJsKCNzbmFrZSkiLz4KPCEtLSBTbmFrZSBTY2FsZXMgLS0+CjxlbGxpcHNlIGN4PSI0OCIgY3k9IjM4IiByeD0iMTQiIHJ5PSI4IiBmaWxsPSJub25lIiBzdHJva2U9IiM0YTkwZDkiIHN0cm9rZS13aWR0aD0iMS41IiBvcGFjaXR5PSIwLjYiLz4KPGVsbGlwc2UgY3g9IjUyIiBjeT0iNDIiIHJ4PSIxMCIgcnk9IjYiIGZpbGw9Im5vbmUiIHN0cm9rZT0iIzZhYTZjZCIgc3Ryb2tlLXdpZHRoPSIxIiBvcGFjaXR5PSIwLjQiLz4KPCEtLSBFeWUgLS0+CjxjaXJjbGUgY3g9IjU2IiBjeT0iMzciIHI9IjQiIGZpbGw9InVybCgjZXllKSIvPgo8Y2lyY2xlIGN4PSI1NyIgY3k9IjM2IiByPSIyIiBmaWxsPSIjMjEyMTIxIi8+CjxjaXJjbGUgY3g9IjU3LjUiIGN5PSIzNS41IiByPSIwLjUiIGZpbGw9IiNmZmZmZmYiLz4KPCEtLSBNb3V0aCBhbmQgRmFuZ3MgLS0+CjxwYXRoIGQ9Ik00MCw0MyBRNDcsNDggNTQsNDYiIHN0cm9rZT0iI2ZmNDc1NiIgc3Ryb2tlLXdpZHRoPSIzIiBmaWxsPSJub25lIi8+CjxwYXRoIGQ9Ik00Miw0NSBMNDAsNTEiIHN0cm9rZT0iI2VkZWRlZCIgc3Ryb2tlLXdpZHRoPSIyIi8+CjxwYXRoIGQ9Ik00OCw0NyBMNDYsNTMiIHN0cm9rZT0iI2VkZWRlZCIgc3Ryb2tlLXdpZHRoPSIyIi8+CjwhLS0gQm9keSBTY2FsZXMgLS0+CjxyZWN0IHg9IjQyIiB5PSI1NSIgd2lkdGg9IjE2IiBoZWlnaHQ9IjQiIHJ4PSIyIiBmaWxsPSJ1cmwoI3NuYWtlKSIgb3BhY2l0eT0iMC44Ii8+CjxyZWN0IHg9IjQ1IiB5PSI2MSIgd2lkdGg9IjEwIiBoZWlnaHQ9IjMiIHJ4PSIxLjUiIGZpbGw9InVybCgjc25ha2UpIiBvcGFjaXR5PSIwLjciLz4KPHJlY3QgeD0iNDciIHk9IjY2IiB3aWR0aD0iNiIgaGVpZ2h0PSIyIiByeD0iMSIgZmlsbD0idXJsKCNzbmFrZSkiIG9wYWNpdHk9IjAuNiIvPgo8cmVjdCB4PSI0OCIgeT0iNzAiIHdpZHRoPSI0IiBoZWlnaHQ9IjIiIHJ4PSIxIiBmaWxsPSJ1cmwoI3NuYWtlKSIgb3BhY2l0eT0iMC41Ii8+CjxyZWN0IHg9IjQ5IiB5PSI3NCIgd2lkdGg9IjIiIGhlaWdodD0iMiIgcng9IjEiIGZpbGw9InVybCgjc25ha2UpIiBvcGFjaXR5PSIwLjQiLz4KPC9zdmc+');
            background-size: contain;
            background-repeat: no-repeat;
            background-position: center;
            filter: drop-shadow(0 6px 12px rgba(0,0,0,0.5));
            animation: logoGlow 3s ease-in-out infinite alternate;
        }}
        
        @keyframes logoGlow {{
            from {{
                filter: drop-shadow(0 6px 12px rgba(74, 144, 217, 0.3));
            }}
            to {{
                filter: drop-shadow(0 6px 20px rgba(74, 144, 217, 0.6));
            }}
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 20px;
        }}
        
        .scan-info {{
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }}
        
        .scan-info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            text-align: left;
        }}
        
        .scan-info-item {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 8px;
        }}
        
        .scan-info-item .label {{
            font-weight: 600;
            opacity: 0.8;
            font-size: 0.9em;
        }}
        
        .scan-info-item .value {{
            font-size: 1.1em;
            margin-top: 5px;
        }}
        
        .summary {{
            background: #2a2a2a;
            padding: 30px;
            border-bottom: 1px solid #404040;
        }}
        
        .summary h2 {{
            color: #e0e0e0;
            margin-bottom: 20px;
        }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }}
        
        .summary-card {{
            background: #333;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
            text-align: center;
            border-left: 4px solid #4a90d9;
        }}
        
        .summary-card.vulnerable {{
            border-left-color: #ff4757;
        }}
        
        .summary-card.outdated {{
            border-left-color: #ffa502;
        }}
        
        .summary-card .number {{
            font-size: 3em;
            font-weight: 700;
            color: #e0e0e0;
            margin-bottom: 10px;
        }}
        
        .summary-card.vulnerable .number {{
            color: #ff4757;
        }}
        
        .summary-card.outdated .number {{
            color: #ffa502;
        }}
        
        .summary-card .label {{
            font-size: 1.1em;
            color: #b0b0b0;
            font-weight: 500;
        }}
        
        .tabs {{
            background: #1e1e1e;
        }}
        
        .tab-buttons {{
            display: flex;
            background: #2a2a2a;
            border-bottom: 1px solid #404040;
        }}
        
        .tab-button {{
            flex: 1;
            padding: 20px;
            background: none;
            border: none;
            font-size: 1.1em;
            font-weight: 600;
            color: #888;
            cursor: pointer;
            transition: all 0.3s ease;
        }}
        
        .tab-button.active {{
            background: #1e1e1e;
            color: #e0e0e0;
            border-bottom: 3px solid #4a90d9;
        }}
        
        .tab-button:hover {{
            background: #404040;
            color: #b0b0b0;
        }}
        
        .tab-content {{
            display: none;
            padding: 30px;
            background: #1e1e1e;
        }}
        
        .tab-content.active {{
            display: block;
        }}
        
        .tab-content h3 {{
            color: #e0e0e0;
            margin-bottom: 25px;
        }}
        
        .component-list {{
            display: grid;
            gap: 15px;
        }}
        
        .component-item {{
            background: #2a2a2a;
            border: 1px solid #404040;
            border-radius: 8px;
            padding: 20px;
            transition: all 0.3s ease;
        }}
        
        .component-item:hover {{
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
            transform: translateY(-2px);
            border-color: #4a90d9;
        }}
        
        .component-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .component-name {{
            font-size: 1.2em;
            font-weight: 600;
            color: #e0e0e0;
        }}
        
        .ecosystem-badge {{
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}
        
        .ecosystem-badge.npm {{
            background: linear-gradient(135deg, #cb3837, #a02d2d);
            color: white;
        }}
        
        .ecosystem-badge.pypi {{
            background: linear-gradient(135deg, #3776ab, #2d5f8a);
            color: white;
        }}
        
        .ecosystem-badge.unknown {{
            background: linear-gradient(135deg, #6c757d, #5a6268);
            color: white;
        }}
        
        .component-details {{
            color: #b0b0b0;
            line-height: 1.6;
        }}
        
        .component-version {{
            font-weight: 600;
            color: #d0d0d0;
        }}
        
        .component-file {{
            font-style: italic;
            color: #888;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 60px 20px;
            color: #888;
        }}
        
        .empty-state .icon {{
            font-size: 4em;
            margin-bottom: 20px;
            filter: grayscale(1) brightness(0.7);
        }}
        
        .empty-state .message {{
            font-size: 1.2em;
            margin-bottom: 10px;
            color: #b0b0b0;
        }}
        
        .empty-state .note {{
            font-size: 0.95em;
            opacity: 0.7;
            color: #777;
        }}
        
        .footer {{
            background: linear-gradient(135deg, #0f1419 0%, #1a1a2e 100%);
            color: #b0b0b0;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
            border-top: 1px solid #404040;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
            <img src="" alt="Basilisk Logo">
            </div>
            <h1>🛡️ Basilisk - Vulnerable and Outdated Components Report</h1>
            <div class="subtitle">Relatório para: {project_name}</div>
            
            <div class="scan-info">
                <div class="scan-info-grid">
                    <div class="scan-info-item">
                        <div class="label">📅 Data do Scan</div>
                        <div class="value">{scan_metadata['scan_timestamp']}</div>
                    </div>
                    <div class="scan-info-item">
                        <div class="label">📂 Pasta de Escopo</div>
                        <div class="value">{scan_metadata['target_path']}</div>
                    </div>
                    <div class="scan-info-item">
                        <div class="label">🔧 Ferramenta</div>
                        <div class="value">{scan_metadata['tool']} v{scan_metadata['version']}</div>
                    </div>
                    <div class="scan-info-item">
                        <div class="label">📊 Total de Componentes</div>
                        <div class="value">{project_info['dependency_count']}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="summary">
            <h2>📋 Sumário das Vulnerabilidades</h2>
            <div class="summary-cards">
                <div class="summary-card">
                    <div class="number">{project_info['dependency_count']}</div>
                    <div class="label">Total de Componentes</div>
                </div>
                <div class="summary-card vulnerable">
                    <div class="number">{len(vulnerable_components)}</div>
                    <div class="label">Componentes Vulneráveis</div>
                </div>
                <div class="summary-card outdated">
                    <div class="number">{len(outdated_components)}</div>
                    <div class="label">Componentes Desatualizados</div>
                </div>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="openTab('all-components')">
                    📦 Todos os Componentes ({project_info['dependency_count']})
                </button>
                <button class="tab-button" onclick="openTab('vulnerable-components')">
                    🚨 Componentes Vulneráveis ({len(vulnerable_components)})
                </button>
                <button class="tab-button" onclick="openTab('outdated-components')">
                    ⚠️ Componentes Desatualizados ({len(outdated_components)})
                </button>
            </div>
            
            <div id="all-components" class="tab-content active">
                <h3>📦 Todos os Componentes Encontrados</h3>
                <div class="component-list">'''
        
        # Adicionar todos os componentes
        for dep in dependencies:
            ecosystem = dep.get('ecosystem', 'unknown')
            html_content += f'''
                    <div class="component-item">
                        <div class="component-header">
                            <div class="component-name">{dep.get('name', 'N/A')}</div>
                            <div class="ecosystem-badge {ecosystem}">{ecosystem}</div>
                        </div>
                        <div class="component-details">
                            <div class="component-version">📌 Versão: {dep.get('version', 'N/A')}</div>
                            <div class="component-file">📄 Declarado em: {dep.get('declared_in', 'N/A')}</div>
                        </div>
                    </div>'''
        
        html_content += '''
                </div>
            </div>
            
            <div id="vulnerable-components" class="tab-content">
                <h3>🚨 Componentes com Vulnerabilidades Conhecidas</h3>
                <div class="empty-state">
                    <div class="icon">🛡️</div>
                    <div class="message">Análise de vulnerabilidades em desenvolvimento</div>
                    <div class="note">Esta funcionalidade será implementada na próxima versão com integração à API de vulnerabilidades.</div>
                </div>
            </div>
            
            <div id="outdated-components" class="tab-content">
                <h3>⚠️ Componentes Desatualizados</h3>
                <div class="empty-state">
                    <div class="icon">🔄</div>
                    <div class="message">Análise de versões desatualizadas em desenvolvimento</div>
                    <div class="note">Esta funcionalidade será implementada na próxima versão com verificação automática de versões.</div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Relatório gerado por {scan_metadata['tool']} v{scan_metadata['version']} • {scan_metadata['scan_timestamp']}</p>
        </div>
    </div>
    
    <script>
        function openTab(tabName) {{
            // Esconder todos os conteúdos
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            // Remover classe active de todos os botões
            const buttons = document.querySelectorAll('.tab-button');
            buttons.forEach(button => button.classList.remove('active'));
            
            // Mostrar conteúdo selecionado
            document.getElementById(tabName).classList.add('active');
            
            // Ativar botão correspondente
            event.target.classList.add('active');
        }}
    </script>
</body>
</html>'''
        
        return html_content

    def save_report_to_file(self, report_data: Dict, output_path: str) -> None:
        """
        Salva o relatório em arquivo HTML.
        
        Args:
            report_data: Dados do relatório
            output_path: Caminho do arquivo de saída
            
        Raises:
            PermissionError: Se não houver permissão para escrever no arquivo
            OSError: Se houver erro de I/O ao salvar o arquivo
        """
        output_file = pathlib.Path(output_path)
        
        # Avisa se o arquivo já existe
        if output_file.exists():
            self.console.print(f"[yellow]⚠️  O arquivo '{output_path}' já existe e será sobrescrito.[/yellow]")
        
        try:
            html_content = self.generate_html_report(report_data)
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(html_content)
        except PermissionError:
            raise PermissionError(f"Sem permissão para escrever no arquivo: {output_path}")
        except OSError as e:
            raise OSError(f"Erro ao salvar o relatório: {e}")
    
    def display_scan_results(self, dependencies: List[Dict], ecosystems: Dict, output_file: str) -> None:
        """
        Exibe os resultados da varredura no console.
        
        Args:
            dependencies: Lista de dependências encontradas
            ecosystems: Estatísticas por ecossistema
            output_file: Arquivo onde o relatório foi salvo
        """
        self.console.print("[bold green]✅ Varredura concluída com sucesso![/bold green]")
        self.console.print(f"[cyan]📊 Estatísticas:[/cyan]")
        self.console.print(f"   • [bold]{len(dependencies)}[/bold] dependências encontradas")
        
        for eco, count in ecosystems.items():
            emoji = ECOSYSTEM_EMOJIS.get(eco, "❓")
            self.console.print(f"   • {emoji} [bold]{count}[/bold] dependência(s) do ecossistema [italic]{eco}[/italic]")
        
        self.console.print(f"\n[bold blue]📁 Relatório HTML interativo salvo em:[/bold blue] [underline]{output_file}[/underline]")
        self.console.print("[dim]💡 Dica: Abra o arquivo HTML no seu navegador para visualizar o relatório completo[/dim]")
    
    def display_scan_header(self, target_path: pathlib.Path, output_file: str, url_mode: bool = False, url: str = None) -> None:
        """
        Exibe o cabeçalho da varredura.
        
        Args:
            target_path: Caminho do projeto sendo analisado
            output_file: Arquivo onde o relatório será salvo
            url_mode: Se está usando modo URL
            url: URL original (se aplicável)
        """
        if url_mode and url:
            self.console.print(f"[dim]🎯 Usando modo URL: {url}[/dim]")
        else:
            self.console.print(f"[dim]🎯 Usando diretório do projeto: {target_path}[/dim]")
        
        self.console.print(f"[cyan]🔍 [BasiliskScan][/cyan] Analisando projeto em: [bold green]{target_path}[/bold green]")
        self.console.print(f"[dim]📋 Relatório será salvo em: {output_file}[/dim]\n")


class SummaryReporter:
    """Gerador de relatórios resumidos."""
    
    @staticmethod
    def generate_dependency_summary(dependencies: List[Dict]) -> Dict:
        """
        Gera um resumo das dependências por arquivo e ecossistema.
        
        Args:
            dependencies: Lista de dependências
            
        Returns:
            Dicionário com resumo organizado
        """
        summary = {
            "total_dependencies": len(dependencies),
            "by_ecosystem": {},
            "by_file": {},
            "files_analyzed": set()
        }
        
        for dep in dependencies:
            # Por ecossistema
            eco = dep.get("ecosystem", "unknown")
            summary["by_ecosystem"][eco] = summary["by_ecosystem"].get(eco, 0) + 1
            
            # Por arquivo
            file_path = dep.get("declared_in", "unknown")
            summary["by_file"][file_path] = summary["by_file"].get(file_path, 0) + 1
            summary["files_analyzed"].add(file_path)
        
        # Converte set para list para serialização JSON
        summary["files_analyzed"] = list(summary["files_analyzed"])
        
        return summary