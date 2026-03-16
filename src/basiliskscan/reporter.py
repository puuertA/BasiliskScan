# src/basiliskscan/reporter.py
"""Módulo responsável pela geração de relatórios e apresentação de resultados."""

import pathlib
import time
import webbrowser
import json
import html
from datetime import datetime
from typing import Callable, Dict, List, Optional
from rich.console import Console
from deep_translator import GoogleTranslator

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
        self.scan_start_time = None
        self.scan_duration = 0
        self.vulnerability_types = self._load_vulnerability_types()

    def _load_vulnerability_types(self) -> List[Dict[str, object]]:
        """Carrega tipos de vulnerabilidade a partir de JSON com fallback seguro."""
        default_types = [
            {
                "name": "XSS",
                "description": "Cross-Site Scripting: permite injeção de código JavaScript malicioso em páginas web",
                "keywords": ["xss", "cross-site scripting", "cross site scripting"]
            },
            {
                "name": "RCE",
                "description": "Remote Code Execution: permite execução de código arbitrário no servidor",
                "keywords": ["rce", "remote code execution", "code execution"]
            },
            {
                "name": "DoS",
                "description": "Denial of Service: causa indisponibilidade do serviço através de consumo excessivo de recursos",
                "keywords": ["dos", "denial of service", "denial-of-service"]
            },
            {
                "name": "SQL Injection",
                "description": "Injeção SQL: permite manipulação de consultas ao banco de dados",
                "keywords": ["sql injection", "sqli"]
            },
            {
                "name": "CSRF",
                "description": "Cross-Site Request Forgery: força usuários autenticados a executar ações indesejadas",
                "keywords": ["csrf", "cross-site request forgery"]
            },
            {
                "name": "Path Traversal",
                "description": "Travessia de Diretório: permite acesso a arquivos fora do diretório autorizado",
                "keywords": ["path traversal", "directory traversal"]
            },
            {
                "name": "Prototype Pollution",
                "description": "Poluição de Protótipo: manipula protótipos de objetos JavaScript",
                "keywords": ["prototype pollution"]
            },
            {
                "name": "Command Injection",
                "description": "Injeção de Comando: permite execução de comandos do sistema operacional",
                "keywords": ["command injection"]
            },
            {
                "name": "Information Disclosure",
                "description": "Vazamento de Informação: expõe dados sensíveis indevidamente",
                "keywords": ["information disclosure", "information leak"]
            },
            {
                "name": "Auth Bypass",
                "description": "Bypass de Autenticação: contorna mecanismos de autenticação ou autorização",
                "keywords": ["authentication", "authorization", "auth bypass"]
            },
            {
                "name": "Security Issue",
                "description": "Problema de Segurança: vulnerabilidade de segurança geral",
                "keywords": []
            }
        ]

        try:
            json_path = pathlib.Path(__file__).parent / "data" / "vulnerability_types.json"
            with open(json_path, "r", encoding="utf-8") as fh:
                content = json.load(fh)

            types = content.get("types", []) if isinstance(content, dict) else []
            if types:
                return types
        except Exception:
            pass

        return default_types
    
    def start_timer(self):
        """Inicia o timer de execução da análise."""
        self.scan_start_time = time.time()
    
    def stop_timer(self):
        """Para o timer e calcula a duração."""
        if self.scan_start_time:
            self.scan_duration = time.time() - self.scan_start_time
    
    def generate_report_data(
        self, 
        target_path: pathlib.Path, 
        dependencies: List[Dict], 
        ecosystems: Dict, 
        output_file: str,
        vulnerabilities: Optional[Dict[str, List[Dict]]] = None
    ) -> Dict:
        """
        Gera os dados estruturados do relatório.
        
        Args:
            target_path: Caminho do projeto analisado
            dependencies: Lista de dependências encontradas
            ecosystems: Estatísticas por ecossistema
            output_file: Arquivo de saída
            vulnerabilities: Dicionário mapeando componentes para suas vulnerabilidades
            
        Returns:
            Dicionário com dados estruturados do relatório
        """
        self.stop_timer()
        
        return {
            "scan_metadata": {
                "tool": APP_NAME,
                "version": APP_VERSION,
                "scan_date": datetime.now().isoformat(),
                "scan_timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                "target_path": str(target_path),
                "output_file": output_file,
                "duration_seconds": round(self.scan_duration, 2)
            },
            "project_info": {
                "path": str(target_path),
                "dependency_count": len(dependencies),
                "ecosystems_found": ecosystems
            },
            "dependencies": dependencies,
            "vulnerabilities": vulnerabilities or {}
        }
    
    def _create_reports_directory(self) -> pathlib.Path:
        """
        Cria o diretório 'reports' se não existir.
        
        Returns:
            Caminho para o diretório reports
        """
        reports_dir = pathlib.Path.cwd() / "reports"
        reports_dir.mkdir(exist_ok=True)
        return reports_dir
    
    def _get_vuln_type(self, description: str) -> tuple:
        """Extrai o tipo de vulnerabilidade da descrição e retorna (tipo, explicação)."""
        description_lower = description.lower()

        for vuln_type in self.vulnerability_types:
            keywords = vuln_type.get("keywords", [])
            if any(term in description_lower for term in keywords):
                return vuln_type.get("name", "Security Issue"), vuln_type.get("description", "Problema de Segurança: vulnerabilidade de segurança geral")

        for vuln_type in self.vulnerability_types:
            if vuln_type.get("name") == "Security Issue":
                return vuln_type.get("name", "Security Issue"), vuln_type.get("description", "Problema de Segurança: vulnerabilidade de segurança geral")

        return "Security Issue", "Problema de Segurança: vulnerabilidade de segurança geral"

    def _build_vuln_type_legend(self, vulnerable_components: List[Dict]) -> Dict[str, Dict[str, object]]:
        """Monta legenda de tipos de vulnerabilidade para exibição com tooltip na aba."""
        legend: Dict[str, Dict[str, object]] = {}

        for comp in vulnerable_components:
            for vuln in comp.get("vulnerabilities", []):
                description = vuln.get("description", "")
                vuln_type, explanation = self._get_vuln_type(description)

                if vuln_type not in legend:
                    legend[vuln_type] = {
                        "description": explanation,
                        "count": 0
                    }
                legend[vuln_type]["count"] += 1

        return dict(sorted(legend.items(), key=lambda item: item[1]["count"], reverse=True))
    
    def _get_severity_icon(self, severity: str) -> str:
        """Retorna o ícone para cada severidade."""
        icons = {
            'CRITICAL': '<i class="bi bi-exclamation-octagon-fill"></i>',
            'HIGH': '<i class="bi bi-exclamation-triangle-fill"></i>',
            'MEDIUM': '<i class="bi bi-exclamation-circle-fill"></i>',
            'LOW': '<i class="bi bi-info-circle-fill"></i>',
            'UNKNOWN': '<i class="bi bi-question-circle-fill"></i>'
        }
        return icons.get(severity, '<i class="bi bi-question-circle-fill"></i>')

    def _get_severity_description(self, severity: str) -> str:
        """Retorna descrição explicativa para níveis de severidade."""
        descriptions = {
            'CRITICAL': 'Crítica: risco extremo com alta probabilidade de impacto grave. Requer correção imediata.',
            'HIGH': 'Alta: risco elevado de exploração e impacto relevante. Deve ser tratada com prioridade alta.',
            'MEDIUM': 'Média: risco moderado, normalmente depende de contexto adicional para exploração completa.',
            'LOW': 'Baixa: risco reduzido e impacto limitado, mas recomenda-se correção no ciclo de manutenção.',
            'UNKNOWN': 'Desconhecida: sem severidade definida pela fonte da vulnerabilidade.'
        }
        return descriptions.get(severity, descriptions['UNKNOWN'])
    
    def _markdown_to_html(self, text: str) -> str:
        """
        Converte texto Markdown básico em HTML.
        
        Args:
            text: Texto com formatação Markdown
            
        Returns:
            HTML formatado
        """
        import re
        
        # Escapar HTML perigoso primeiro
        text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        
        # Headers (### -> h3, ## -> h2, # -> h1)
        text = re.sub(r'^### (.+)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)
        text = re.sub(r'^## (.+)$', r'<h2>\1</h2>', text, flags=re.MULTILINE)
        text = re.sub(r'^# (.+)$', r'<h1>\1</h1>', text, flags=re.MULTILINE)
        
        # Blocos de código (```language ... ```)
        text = re.sub(
            r'```(\w+)?\n(.*?)```',
            r'<pre><code class="language-\1">\2</code></pre>',
            text,
            flags=re.DOTALL
        )
        
        # Código inline (`code`)
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        
        # Links [text](url)
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" target="_blank">\1</a>', text)
        
        # Bold (**text** ou __text__)
        text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
        text = re.sub(r'__([^_]+)__', r'<strong>\1</strong>', text)
        
        # Italic (*text* ou _text_)
        text = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', text)
        text = re.sub(r'_([^_]+)_', r'<em>\1</em>', text)
        
        # Quebras de linha
        text = text.replace('\n', '<br>')
        
        return text
    
    def _translate_text(self, text: str) -> str:
        """
        Traduz texto do inglês para português usando Google Translate.
        Divide textos grandes em chunks para evitar limites da API.
        
        Args:
            text: Texto em inglês para traduzir
            
        Returns:
            Texto traduzido em português ou texto original em caso de erro
        """
        try:
            # Limitar tamanho e dividir em chunks se necessário
            max_chunk_size = 4500  # Deixar margem de segurança
            
            if len(text) <= max_chunk_size:
                translator = GoogleTranslator(source='en', target='pt')
                translated = translator.translate(text)
                return translated if translated else text
            
            # Dividir texto em chunks menores
            # Tentar dividir por parágrafos primeiro
            paragraphs = text.split('\n\n')
            translated_parts = []
            current_chunk = ""
            
            translator = GoogleTranslator(source='en', target='pt')
            
            for para in paragraphs:
                # Se o parágrafo sozinho é muito grande, dividir por sentenças
                if len(para) > max_chunk_size:
                    sentences = para.split('. ')
                    for sentence in sentences:
                        if len(current_chunk) + len(sentence) < max_chunk_size:
                            current_chunk += sentence + '. '
                        else:
                            if current_chunk:
                                translated_parts.append(translator.translate(current_chunk))
                            current_chunk = sentence + '. '
                else:
                    # Se adicionar este parágrafo exceder o limite, traduzir o chunk atual
                    if len(current_chunk) + len(para) > max_chunk_size:
                        if current_chunk:
                            translated_parts.append(translator.translate(current_chunk))
                        current_chunk = para + '\n\n'
                    else:
                        current_chunk += para + '\n\n'
            
            # Traduzir o último chunk
            if current_chunk:
                translated_parts.append(translator.translate(current_chunk))
            
            return ''.join(translated_parts)
            
        except Exception as e:
            # Em caso de erro, retorna o texto original
            self.console.print(f"[yellow]⚠️ Erro na tradução: {str(e)[:100]}[/yellow]")
            return text
    
    def _extract_cve_id(self, vuln_id: str) -> Optional[str]:
        """Extrai o ID do CVE se presente."""
        if vuln_id.startswith('CVE-'):
            return vuln_id
        return None
    
    def _get_nvd_link(self, cve_id: str) -> str:
        """Gera link para o NVD."""
        if cve_id and cve_id.startswith('CVE-'):
            return f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        return ""
    
    def _get_oss_index_link(self, component_name: str) -> str:
        """Gera link para o OSS Index."""
        # Formato simplificado - pode ser melhorado com ecosystem-specific
        return f"https://ossindex.sonatype.org/component/pkg:npm/{component_name}"

    def _find_dependency_vulnerabilities(self, dep_name: str, vulnerabilities_data: Dict[str, List[Dict]]) -> List[Dict]:
        """Localiza vulnerabilidades por nome com fallback case-insensitive."""
        dep_vulns = vulnerabilities_data.get(dep_name, [])

        if dep_vulns:
            return dep_vulns

        for vuln_key, vuln_list in vulnerabilities_data.items():
            if vuln_key.lower() == dep_name.lower():
                return vuln_list

        return []

    def _get_recommended_version(self, dep: Dict, dep_vulns: List[Dict]) -> Optional[str]:
        """Retorna uma versão corrigida recomendada quando disponível."""
        current_version = (dep.get("version_spec") or "").strip()
        latest_version = (dep.get("latest_version") or "").strip()

        if latest_version and latest_version != current_version:
            return latest_version

        for vuln in dep_vulns:
            fixed_version = (vuln.get("fixed_version") or "").strip()
            if fixed_version and fixed_version != current_version:
                return fixed_version

        return None

    def _build_dependency_status(self, dep: Dict, dep_vulns: List[Dict]) -> Dict[str, object]:
        """Calcula o status visual de uma dependência no relatório."""
        recommended_version = self._get_recommended_version(dep, dep_vulns)

        has_update = recommended_version is not None
        is_vulnerable = bool(dep_vulns)
        badges: List[Dict[str, str]] = []

        if is_vulnerable:
            badges.append({
                "kind": "medium",
                "label": "Vulnerável",
                "icon": "bi bi-shield-exclamation",
            })
        else:
            badges.append({
                "kind": "low",
                "label": "Seguro",
                "icon": "bi bi-shield-check",
            })

        if has_update:
            badges.append({
                "kind": "update",
                "label": "Atualização disponível",
                "icon": "bi bi-arrow-up-right-circle-fill",
            })

        return {
            "is_vulnerable": is_vulnerable,
            "has_update": has_update,
            "recommended_version": recommended_version,
            "badges": badges,
        }

    def _format_dependency_version(self, dep: Dict, status: Dict[str, object]) -> str:
        """Formata a versão com indicação visual de upgrade quando houver."""
        current_version = html.escape(dep.get("version_spec") or "N/A")
        recommended_version = status.get("recommended_version")

        if not recommended_version:
            return current_version

        return (
            '<div class="version-flow">'
            f'<span class="version-current">{current_version}</span>'
            '<span class="version-arrow"><i class="bi bi-arrow-right"></i></span>'
            f'<span class="version-target">{html.escape(recommended_version)}</span>'
            '</div>'
        )

    def _render_status_badges(self, status: Dict[str, object]) -> str:
        """Renderiza uma ou mais badges de status para a tabela."""
        badges = status.get("badges", [])
        badges_html = "".join(
            f'<span class="severity-badge {badge["kind"]}"><i class="{badge["icon"]}"></i> {badge["label"]}</span>'
            for badge in badges
        )
        return f'<div class="status-badges">{badges_html}</div>'

    def generate_html_report(self, report_data: Dict) -> str:
        """
        Gera o HTML do relatório com estrutura melhorada.
        
        Args:
            report_data: Dados do relatório
            
        Returns:
            String com o HTML completo do relatório
        """
        scan_metadata = report_data["scan_metadata"]
        project_info = report_data["project_info"]
        dependencies = report_data["dependencies"]
        vulnerabilities_data = report_data.get("vulnerabilities", {})
        
        # Identificar componentes vulneráveis e ordenar por severidade
        vulnerable_components = []
        dependency_statuses = {}
        for dep in dependencies:
            dep_name = dep.get('name', '')
            dep_vulns = self._find_dependency_vulnerabilities(dep_name, vulnerabilities_data)
            dependency_statuses[dep_name.lower()] = self._build_dependency_status(dep, dep_vulns)
            
            if dep_vulns:
                # Calcular severidade máxima
                severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
                max_severity = max([severity_order.get(v.get('severity', 'UNKNOWN'), 0) for v in dep_vulns])
                
                vulnerable_components.append({
                    **dep,
                    'vulnerabilities': sorted(dep_vulns, key=lambda v: severity_order.get(v.get('severity', 'UNKNOWN'), 0), reverse=True),
                    'max_severity_score': max_severity
                })
        
        # Ordenar componentes por severidade
        vulnerable_components.sort(key=lambda x: x['max_severity_score'], reverse=True)
        
        # Calcular estatísticas de vulnerabilidades
        total_vulnerabilities = sum(len(vulns) for vulns in vulnerabilities_data.values())
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for vulns in vulnerabilities_data.values():
            for vuln in vulns:
                severity = vuln.get('severity', 'UNKNOWN')
                if severity == 'CRITICAL':
                    critical_count += 1
                elif severity == 'HIGH':
                    high_count += 1
                elif severity == 'MEDIUM':
                    medium_count += 1
                elif severity == 'LOW':
                    low_count += 1

        outdated_components_count = sum(
            1
            for dep in dependencies
            if dependency_statuses.get(dep.get('name', '').lower(), {}).get('has_update')
        )

        critical_severity_description = self._get_severity_description('CRITICAL')
        high_severity_description = self._get_severity_description('HIGH')
        medium_severity_description = self._get_severity_description('MEDIUM')
        low_severity_description = self._get_severity_description('LOW')

        vuln_type_legend = self._build_vuln_type_legend(vulnerable_components)
        
        project_name = pathlib.Path(scan_metadata["target_path"]).name
        duration = scan_metadata.get('duration_seconds', 0)
        
        html_content = f'''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BasiliskScan - Relatório de Segurança - {project_name}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Montserrat', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0f1419 0%, #1a1a2e 50%, #16213e 100%);
            min-height: 100vh;
            padding: 20px;
            color: #e0e0e0;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: #1e1e1e;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            overflow: visible;
            border: 1px solid #333;
        }}
        
        /* Header Styles */
        .header {{
            background: linear-gradient(135deg, #0f1419 0%, #1a1a2e 50%, #16213e 100%);
            color: #e0e0e0;
            padding: 40px;
            text-align: center;
            border-bottom: 3px solid #4a90d9;
        }}
        
        .logo {{
            width: 100px;
            height: 100px;
            margin: 0 auto 20px;
            display: block;
            border-radius: 50%;
            box-shadow: 0 10px 25px rgba(74, 144, 217, 0.3);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 25px;
        }}
        
        /* Scan Info Grid */
        .scan-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 30px;
            background: rgba(255,255,255,0.05);
            padding: 20px;
            border-radius: 10px;
        }}
        
        .scan-info-item {{
            text-align: left;
            padding: 15px;
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            border-left: 3px solid #4a90d9;
        }}
        
        .scan-info-item .label {{
            font-size: 0.85em;
            color: #888;
            margin-bottom: 5px;
        }}
        
        .scan-info-item .value {{
            font-size: 1.1em;
            font-weight: 600;
            color: #e0e0e0;
        }}
        
        /* Navigation Tabs */
        .nav-tabs {{
            display: flex;
            background: #2a2a2a;
            border-bottom: 2px solid #404040;
            overflow-x: auto;
        }}
        
        .nav-tab {{
            flex: 1;
            min-width: 200px;
            padding: 20px;
            background: none;
            border: none;
            font-size: 1em;
            font-weight: 600;
            color: #888;
            cursor: pointer;
            transition: all 0.3s ease;
            border-bottom: 3px solid transparent;
        }}
        
        .nav-tab:hover {{
            background: #333;
            color: #b0b0b0;
        }}
        
        .nav-tab.active {{
            background: #1e1e1e;
            color: #4a90d9;
            border-bottom-color: #4a90d9;
        }}
        
        /* Content Sections */
        .tab-content {{
            display: none;
            padding: 40px;
            background: #1e1e1e;
        }}
        
        .tab-content.active {{
            display: block;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section-title {{
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #e0e0e0;
            border-bottom: 2px solid #404040;
            padding-bottom: 10px;
        }}
        
        .section-subtitle {{
            font-size: 1.3em;
            margin: 30px 0 15px 0;
            color: #b0b0b0;
        }}
        
        /* Stats Cards */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #2a2a2a 0%, #333 100%);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid #404040;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.4);
        }}
        
        .stat-card .icon {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .icon i, .section-title i, .section-subtitle i, .nav-tab i, .scan-info-item .label i, .header h1 i, .vuln-type i, .cvss-score i, .translation-label i, .info-label i, .btn i, .recommendation-card .title i, .severity-badge i {{
            margin-right: 6px;
        }}
        
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 10px;
        }}
        
        .stat-card .label {{
            font-size: 1em;
            color: #888;
        }}
        
        .stat-card.info {{
            border-left: 4px solid #4a90d9;
        }}
        
        .stat-card.info .number {{
            color: #4a90d9;
        }}
        
        .stat-card.success {{
            border-left: 4px solid #2ecc71;
        }}
        
        .stat-card.success .number {{
            color: #2ecc71;
        }}
        
        .stat-card.warning {{
            border-left: 4px solid #f39c12;
        }}
        
        .stat-card.warning .number {{
            color: #f39c12;
        }}
        
        .stat-card.danger {{
            border-left: 4px solid #e74c3c;
        }}
        
        .stat-card.danger .number {{
            color: #e74c3c;
        }}
        
        .stat-card.critical {{
            border-left: 4px solid #c0392b;
            background: linear-gradient(135deg, #2a2a2a 0%, #3d1f1f 100%);
        }}
        
        .stat-card.critical .number {{
            color: #e74c3c;
        }}
        
        /* Vulnerability Cards */
        .vuln-card {{
            background: #2a2a2a;
            border: 1px solid #404040;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
            border-left: 5px solid #4a90d9;
            transition: all 0.3s ease;
        }}
        
        .vuln-card:hover {{
            box-shadow: 0 8px 20px rgba(0,0,0,0.4);
        }}
        
        .vuln-card.critical {{
            border-left-color: #c0392b;
            background: linear-gradient(135deg, #2a2a2a 0%, #3d1f1f 100%);
        }}
        
        .vuln-card.high {{
            border-left-color: #e74c3c;
        }}
        
        .vuln-card.medium {{
            border-left-color: #f39c12;
        }}
        
        .vuln-card.low {{
            border-left-color: #3498db;
        }}
        
        .vuln-card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }}

        .component-toggle {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            border-radius: 8px;
            border: 1px solid #404040;
            background: rgba(255,255,255,0.06);
            color: #e0e0e0;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s ease;
        }}

        .component-toggle:hover {{
            border-color: #4a90d9;
            background: rgba(74, 144, 217, 0.15);
        }}

        .vuln-count {{
            font-size: 0.85em;
            color: #b0b0b0;
            font-weight: 500;
        }}

        .vuln-card-body {{
            max-height: 0;
            overflow: hidden;
            opacity: 0;
            transition: max-height 0.5s ease, opacity 0.3s ease;
        }}

        .vuln-card-body.expanded {{
            max-height: 12000px;
            overflow: visible;
            opacity: 1;
            margin-top: 15px;
        }}
        
        .component-name {{
            font-size: 1.5em;
            font-weight: 700;
            color: #e0e0e0;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .ecosystem-badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.7em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .ecosystem-badge.npm {{
            background: linear-gradient(135deg, #cb3837, #a02d2d);
            color: white;
        }}
        
        .ecosystem-badge.pypi {{
            background: linear-gradient(135deg, #3776ab, #2d5f8a);
            color: white;
        }}
        
        .ecosystem-badge.maven {{
            background: linear-gradient(135deg, #f58025, #c96915);
            color: white;
        }}

        .ecosystem-badge.ant {{
            background: linear-gradient(135deg, #8e44ad, #6c3483);
            color: white;
        }}

        .version-flow {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }}

        .version-current {{
            color: #e0e0e0;
            font-weight: 600;
        }}

        .version-arrow {{
            color: #f1c40f;
            font-weight: 700;
        }}

        .version-target {{
            color: #2ecc71;
            font-weight: 700;
        }}
        
        .component-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
            padding: 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
        }}
        
        .info-item {{
            display: flex;
            flex-direction: column;
        }}
        
        .info-label {{
            font-size: 0.85em;
            color: #888;
            margin-bottom: 5px;
        }}
        
        .info-value {{
            font-size: 1em;
            color: #e0e0e0;
            font-weight: 600;
        }}
        
        .info-value.version {{
            color: #4a90d9;
        }}
        
        .info-value.fixed {{
            color: #2ecc71;
        }}
        
        /* Vulnerability List */
        .vuln-list {{
            margin-top: 20px;
        }}
        
        .vuln-item {{
            background: rgba(0,0,0,0.3);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 3px solid #404040;
        }}
        
        .vuln-item.critical {{
            border-left-color: #c0392b;
        }}
        
        .vuln-item.high {{
            border-left-color: #e74c3c;
        }}
        
        .vuln-item.medium {{
            border-left-color: #f39c12;
        }}
        
        .vuln-item.low {{
            border-left-color: #3498db;
        }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        
        .vuln-id {{
            font-size: 1.2em;
            font-weight: 700;
            color: #e0e0e0;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .severity-badge {{
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 700;
            text-transform: uppercase;
            white-space: nowrap;
            position: relative;
            cursor: help;
        }}

        .severity-badge:hover .tooltip,
        .severity-chip:hover .tooltip {{
            visibility: visible;
            opacity: 1;
        }}

        .severity-chip {{
            display: inline-flex;
            align-items: center;
            gap: 5px;
            position: relative;
            cursor: help;
        }}
        
        .severity-badge.critical {{
            background: #c0392b;
            color: white;
        }}
        
        .severity-badge.high {{
            background: #e74c3c;
            color: white;
        }}
        
        .severity-badge.medium {{
            background: #f39c12;
            color: #2d3436;
        }}
        
        .severity-badge.low {{
            background: #3498db;
            color: white;
        }}

        .severity-badge.update {{
            background: #f1c40f;
            color: #2d3436;
        }}

        .status-badges {{
            display: inline-flex;
            flex-wrap: wrap;
            gap: 6px;
            align-items: center;
        }}
        
        .vuln-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 15px;
            align-items: center;
        }}

        .vuln-type-legend {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 20px;
            padding: 15px;
            background: rgba(0,0,0,0.2);
            border: 1px solid #404040;
            border-radius: 8px;
        }}

        .vuln-type-legend .vuln-type {{
            font-size: 0.85em;
        }}

        .type-count {{
            color: #b0b0b0;
            font-weight: 600;
            margin-left: 3px;
        }}
        
        .vuln-type {{
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            background: rgba(74, 144, 217, 0.2);
            border-radius: 5px;
            font-size: 0.9em;
            color: #4a90d9;
            border: 1px solid #4a90d9;
            cursor: help;
            position: relative;
        }}
        
        .vuln-type:hover .tooltip {{
            visibility: visible;
            opacity: 1;
        }}
        
        .tooltip {{
            visibility: hidden;
            width: 300px;
            max-width: calc(100vw - 40px);
            background-color: #2d3436;
            color: #dfe6e9;
            text-align: left;
            border-radius: 6px;
            padding: 12px;
            position: absolute;
            z-index: 2147483647;
            bottom: 125%;
            left: 50%;
            margin-left: -150px;
            opacity: 0;
            transition: opacity 0.3s;
            box-shadow: 0 4px 12px rgba(0,0,0,0.5);
            border: 1px solid #4a90d9;
            font-size: 0.85em;
            line-height: 1.4;
            white-space: normal;
            overflow-wrap: anywhere;
            word-break: break-word;
            text-transform: none;
        }}
        
        .tooltip::after {{
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            margin-left: -5px;
            border-width: 5px;
            border-style: solid;
            border-color: #2d3436 transparent transparent transparent;
        }}

        .vuln-header .severity-badge .tooltip {{
            left: auto;
            right: 0;
            margin-left: 0;
        }}

        .vuln-header .severity-badge .tooltip::after {{
            left: auto;
            right: 18px;
            margin-left: 0;
        }}
        
        .cvss-score {{
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            background: rgba(255,255,255,0.1);
            border-radius: 5px;
            font-weight: 600;
        }}
        
        .vuln-description {{
            margin: 15px 0;
            line-height: 1.6;
            color: #b0b0b0;
        }}
        
        .description-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
            cursor: pointer;
            user-select: none;
        }}
        
        .description-header:hover {{
            color: #4a90d9;
        }}
        
        .expand-arrow {{
            transition: transform 0.3s ease;
            display: inline-block;
        }}
        
        .expand-arrow.expanded {{
            transform: rotate(90deg);
        }}
        
        .description-content {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.5s ease;
        }}
        
        .description-content.expanded {{
            max-height: 3000px;
        }}
        
        .description-text {{
            padding: 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 5px;
            margin-bottom: 10px;
            border-left: 3px solid #4a90d9;
            line-height: 1.8;
        }}
        
        .description-text h1,
        .description-text h2,
        .description-text h3 {{
            color: #4a90d9;
            margin-top: 15px;
            margin-bottom: 10px;
            font-weight: 600;
        }}
        
        .description-text h1 {{
            font-size: 1.5em;
        }}
        
        .description-text h2 {{
            font-size: 1.3em;
        }}
        
        .description-text h3 {{
            font-size: 1.1em;
        }}
        
        .description-text code {{
            background: rgba(255, 255, 255, 0.1);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #f39c12;
            font-size: 0.9em;
        }}
        
        .description-text pre {{
            background: rgba(0, 0, 0, 0.4);
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .description-text pre code {{
            background: none;
            padding: 0;
            color: #2ecc71;
            font-size: 0.85em;
            line-height: 1.5;
        }}
        
        .description-text a {{
            color: #4a90d9;
            text-decoration: underline;
        }}
        
        .description-text a:hover {{
            color: #5aa3e8;
        }}
        
        .description-text strong {{
            color: #e0e0e0;
            font-weight: 700;
        }}
        
        .description-text em {{
            font-style: italic;
            color: #b0b0b0;
        }}
        
        .description-translation {{
            padding: 15px;
            background: rgba(74, 144, 217, 0.1);
            border-radius: 5px;
            border-left: 3px solid #4a90d9;
            line-height: 1.8;
        }}
        
        .description-translation h1,
        .description-translation h2,
        .description-translation h3 {{
            color: #4a90d9;
            margin-top: 15px;
            margin-bottom: 10px;
            font-weight: 600;
        }}
        
        .description-translation h1 {{
            font-size: 1.5em;
        }}
        
        .description-translation h2 {{
            font-size: 1.3em;
        }}
        
        .description-translation h3 {{
            font-size: 1.1em;
        }}
        
        .description-translation code {{
            background: rgba(255, 255, 255, 0.1);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #f39c12;
            font-size: 0.9em;
        }}
        
        .description-translation pre {{
            background: rgba(0, 0, 0, 0.4);
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .description-translation pre code {{
            background: none;
            padding: 0;
            color: #2ecc71;
            font-size: 0.85em;
            line-height: 1.5;
        }}
        
        .description-translation a {{
            color: #4a90d9;
            text-decoration: underline;
        }}
        
        .description-translation a:hover {{
            color: #5aa3e8;
        }}
        
        .description-translation strong {{
            color: #e0e0e0;
            font-weight: 700;
        }}
        
        .description-translation em {{
            font-style: italic;
            color: #b0b0b0;
        }}
        
        .translation-label {{
            font-weight: 600;
            color: #4a90d9;
            margin-bottom: 5px;
        }}
        
        .vuln-actions {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }}
        
        .btn {{
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 0.9em;
            font-weight: 600;
            text-decoration: none;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
        }}
        
        .btn-primary {{
            background: #4a90d9;
            color: white;
        }}
        
        .btn-primary:hover {{
            background: #357abd;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(74, 144, 217, 0.3);
        }}
        
        .btn-secondary {{
            background: rgba(255,255,255,0.1);
            color: #e0e0e0;
            border: 1px solid #404040;
        }}
        
        .btn-secondary:hover {{
            background: rgba(255,255,255,0.15);
            border-color: #4a90d9;
        }}
        
        /* Dependency Table */
        .table-wrapper {{
            overflow-x: auto;
            margin-top: 20px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #2a2a2a;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        thead {{
            background: #333;
        }}
        
        th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #e0e0e0;
            border-bottom: 2px solid #404040;
        }}
        
        td {{
            padding: 15px;
            border-bottom: 1px solid #333;
            color: #b0b0b0;
        }}
        
        tr:hover {{
            background: rgba(74, 144, 217, 0.1);
        }}
        
        /* Empty State */
        .empty-state {{
            text-align: center;
            padding: 60px 20px;
        }}
        
        .empty-state .icon {{
            font-size: 4em;
            margin-bottom: 20px;
            opacity: 0.5;
        }}
        
        .empty-state .message {{
            font-size: 1.3em;
            color: #b0b0b0;
            margin-bottom: 10px;
        }}
        
        .empty-state .note {{
            color: #888;
        }}
        
        /* Recommendations */
        .recommendation-card {{
            background: linear-gradient(135deg, #2a2a2a 0%, #1f3d1f 100%);
            border: 1px solid #2ecc71;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}
        
        .recommendation-card .title {{
            font-size: 1.1em;
            font-weight: 600;
            color: #2ecc71;
            margin-bottom: 10px;
        }}
        
        .recommendation-card .content {{
            color: #b0b0b0;
            line-height: 1.6;
        }}
        
        /* Footer */
        .footer {{
            background: linear-gradient(135deg, #0f1419 0%, #1a1a2e 100%);
            color: #888;
            text-align: center;
            padding: 25px;
            border-top: 1px solid #404040;
        }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .container {{
                border-radius: 0;
            }}
            
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
            
            .component-info {{
                grid-template-columns: 1fr;
            }}
            
            .vuln-card-header,
            .vuln-header {{
                flex-direction: column;
                align-items: flex-start;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <img src="./resources/logo.png" alt="BasiliskScan Logo" class="logo">
            <h1><i class="bi bi-shield-check"></i> BasiliskScan - Relatório de Segurança</h1>
            <div class="subtitle">Análise de Componentes e Vulnerabilidades</div>
            
            <div class="scan-info">
                <div class="scan-info-item">
                    <div class="label"><i class="bi bi-calendar-event"></i> Data da Análise</div>
                    <div class="value">{scan_metadata['scan_timestamp']}</div>
                </div>
                <div class="scan-info-item">
                    <div class="label"><i class="bi bi-folder2-open"></i> Projeto</div>
                    <div class="value">{project_name}</div>
                </div>
                <div class="scan-info-item">
                    <div class="label"><i class="bi bi-stopwatch"></i> Tempo de Execução</div>
                    <div class="value">{duration}s</div>
                </div>
                <div class="scan-info-item">
                    <div class="label"><i class="bi bi-tools"></i> Ferramenta</div>
                    <div class="value">{scan_metadata['tool']} v{scan_metadata['version']}</div>
                </div>
            </div>
        </div>
        
        <!-- Navigation Tabs -->
        <div class="nav-tabs">
            <button class="nav-tab active" onclick="openTab('overview', event)">
                <i class="bi bi-bar-chart-line"></i> Visão Geral
            </button>
            <button class="nav-tab" onclick="openTab('dependencies', event)">
                <i class="bi bi-box-seam"></i> Dependências ({project_info['dependency_count']})
            </button>
            <button class="nav-tab" onclick="openTab('vulnerabilities', event)">
                <i class="bi bi-shield-exclamation"></i> Vulnerabilidades ({total_vulnerabilities} em {len(vulnerable_components)} componente(s))
            </button>
            <button class="nav-tab" onclick="openTab('recommendations', event)">
                <i class="bi bi-lightbulb"></i> Recomendações
            </button>
        </div>
        
        <!-- Overview Tab -->
        <div id="overview" class="tab-content active">
            <div class="section">
                <h2 class="section-title"><i class="bi bi-bar-chart-line"></i> Visão Geral da Análise</h2>
                
                <div class="stats-grid">
                    <div class="stat-card info">
                        <div class="icon"><i class="bi bi-box-seam"></i></div>
                        <div class="number">{project_info['dependency_count']}</div>
                        <div class="label">Total de Dependências</div>
                    </div>

                    <div class="stat-card warning">
                        <div class="icon"><i class="bi bi-arrow-up-circle"></i></div>
                        <div class="number">{outdated_components_count}</div>
                        <div class="label">Componentes Desatualizados</div>
                    </div>
                    
                    <div class="stat-card danger">
                        <div class="icon"><i class="bi bi-shield-exclamation"></i></div>
                        <div class="number">{len(vulnerable_components)}</div>
                        <div class="label">Componentes Vulneráveis</div>
                    </div>
                    
                    <div class="stat-card warning">
                        <div class="icon"><i class="bi bi-exclamation-triangle"></i></div>
                        <div class="number">{total_vulnerabilities}</div>
                        <div class="label">Total de Vulnerabilidades</div>
                    </div>
                    
                    <div class="stat-card info">
                        <div class="icon"><i class="bi bi-stopwatch"></i></div>
                        <div class="number">{duration}s</div>
                        <div class="label">Tempo de Execução</div>
                    </div>
                </div>
                
                <h3 class="section-subtitle"><i class="bi bi-bullseye"></i> Distribuição por Severidade</h3>
                <div class="stats-grid">
                    <div class="stat-card critical">
                        <div class="icon"><i class="bi bi-exclamation-octagon-fill"></i></div>
                        <div class="number">{critical_count}</div>
                        <div class="label">
                            <span class="severity-chip">
                                Críticas
                                <span class="tooltip">{critical_severity_description}</span>
                            </span>
                        </div>
                    </div>
                    
                    <div class="stat-card danger">
                        <div class="icon"><i class="bi bi-exclamation-triangle-fill"></i></div>
                        <div class="number">{high_count}</div>
                        <div class="label">
                            <span class="severity-chip">
                                Altas
                                <span class="tooltip">{high_severity_description}</span>
                            </span>
                        </div>
                    </div>
                    
                    <div class="stat-card warning">
                        <div class="icon"><i class="bi bi-exclamation-circle-fill"></i></div>
                        <div class="number">{medium_count}</div>
                        <div class="label">
                            <span class="severity-chip">
                                Médias
                                <span class="tooltip">{medium_severity_description}</span>
                            </span>
                        </div>
                    </div>
                    
                    <div class="stat-card info">
                        <div class="icon"><i class="bi bi-info-circle-fill"></i></div>
                        <div class="number">{low_count}</div>
                        <div class="label">
                            <span class="severity-chip">
                                Baixas
                                <span class="tooltip">{low_severity_description}</span>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Dependencies Tab -->
        <div id="dependencies" class="tab-content">
            <div class="section">
                <h2 class="section-title"><i class="bi bi-box-seam"></i> Dependências Identificadas</h2>
                
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Nome</th>
                                <th>Versão</th>
                                <th>Ecossistema</th>
                                <th>Arquivo</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>'''
        
        for dep in dependencies:
            dep_name = dep.get('name', 'N/A')
            dep_vulns = self._find_dependency_vulnerabilities(dep_name, vulnerabilities_data)
            status = dependency_statuses.get(dep_name.lower()) or self._build_dependency_status(dep, dep_vulns)
            version_html = self._format_dependency_version(dep, status)
            status_badge = self._render_status_badges(status)

            ecosystem = dep.get('ecosystem', 'unknown')
            html_content += f'''
                            <tr>
                                <td><strong>{dep_name}</strong></td>
                                <td>{version_html}</td>
                                <td><span class="ecosystem-badge {ecosystem}">{ecosystem}</span></td>
                                <td>{dep.get('declared_in', 'N/A')}</td>
                                <td>{status_badge}</td>
                            </tr>'''
        
        html_content += '''
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Vulnerabilities Tab -->
        <div id="vulnerabilities" class="tab-content">
            <div class="section">
                <h2 class="section-title"><i class="bi bi-shield-exclamation"></i> Vulnerabilidades Detectadas</h2>'''

        if vuln_type_legend:
            html_content += '''
                <div class="vuln-type-legend">'''
            for vuln_type, legend_info in vuln_type_legend.items():
                type_description = legend_info.get("description", "Sem descrição")
                type_count = legend_info.get("count", 0)
                html_content += f'''
                    <span class="vuln-type">
                        <i class="bi bi-tag"></i> {vuln_type}
                        <span class="type-count">({type_count})</span>
                        <span class="tooltip">{type_description}</span>
                    </span>'''

            html_content += '''
                </div>'''
        
        if vulnerable_components:
            for comp_idx, comp in enumerate(vulnerable_components):
                ecosystem = comp.get('ecosystem', 'unknown')
                comp_name = comp.get('name', 'N/A')
                comp_version = comp.get('version_spec', 'N/A')
                vulns = comp.get('vulnerabilities', [])
                component_expand_id = f"component-{comp_idx}"
                
                # Determinar severidade máxima
                max_severity = 'low'
                for vuln in vulns:
                    severity = vuln.get('severity', 'UNKNOWN').lower()
                    if severity == 'critical':
                        max_severity = 'critical'
                        break
                    elif severity == 'high' and max_severity != 'critical':
                        max_severity = 'high'
                    elif severity == 'medium' and max_severity not in ['critical', 'high']:
                        max_severity = 'medium'
                
                html_content += f'''
                <div class="vuln-card {max_severity}">
                    <div class="vuln-card-header">
                        <div class="component-name">
                            <span>{comp_name}</span>
                            <span class="ecosystem-badge {ecosystem}">{ecosystem}</span>
                        </div>
                        <button class="component-toggle" onclick="toggleComponent('{component_expand_id}')">
                            <span class="expand-arrow" id="arrow-{component_expand_id}">▶</span>
                            <span class="vuln-count">{len(vulns)} vulnerabilidade(s)</span>
                        </button>
                    </div>
                    <div class="vuln-card-body" id="{component_expand_id}">
                    <div class="component-info">
                        <div class="info-item">
                            <div class="info-label"><i class="bi bi-pin-angle"></i> Versão Instalada</div>
                            <div class="info-value version">{comp_version}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label"><i class="bi bi-shield-exclamation"></i> Vulnerabilidades</div>
                            <div class="info-value">{len(vulns)} encontrada(s)</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label"><i class="bi bi-file-earmark-text"></i> Declarado em</div>
                            <div class="info-value">{comp.get('declared_in', 'N/A')}</div>
                        </div>
                    </div>
                    
                    <div class="vuln-list">'''
                
                for idx, vuln in enumerate(vulns):
                    vuln_id = vuln.get('id', 'UNKNOWN')
                    severity = vuln.get('severity', 'UNKNOWN').lower()
                    severity_icon = self._get_severity_icon(severity.upper())
                    severity_description = self._get_severity_description(severity.upper())
                    score = vuln.get('score', 0)
                    description = vuln.get('description', 'Sem descrição disponível')
                    
                    # Converter Markdown para HTML
                    description_html = self._markdown_to_html(description)
                    
                    # Traduzir descrição
                    description_pt = self._translate_text(description)
                    description_pt_html = self._markdown_to_html(description_pt)
                    
                    # Extrair tipo de vulnerabilidade e explicação
                    vuln_type, vuln_explanation = self._get_vuln_type(description)
                    
                    # Links externos
                    cve_id = self._extract_cve_id(vuln_id)
                    nvd_link = self._get_nvd_link(cve_id) if cve_id else ""
                    
                    # Versão corrigida
                    fixed_version = vuln.get('fixed_version', 'Consulte o advisory')
                    
                    # ID único para expansão
                    expand_id = f"desc-{comp_name}-{idx}"
                    
                    html_content += f'''
                        <div class="vuln-item {severity}">
                            <div class="vuln-header">
                                <div class="vuln-id">{vuln_id}</div>
                                <span class="severity-badge {severity}">{severity_icon} {severity.upper()}<span class="tooltip">{severity_description}</span></span>
                            </div>
                            
                            <div class="vuln-meta">
                                <span class="vuln-type">
                                    <i class="bi bi-tag"></i> {vuln_type}
                                    <span class="tooltip">{vuln_explanation}</span>
                                </span>
                                <span class="cvss-score"><i class="bi bi-speedometer2"></i> CVSS: {score}</span>
                            </div>
                            
                            <div class="vuln-description">
                                <div class="description-header" onclick="toggleDescription('{expand_id}')">
                                    <span class="expand-arrow" id="arrow-{expand_id}">▶</span>
                                    <strong>Descrição Completa</strong>
                                </div>
                                <div class="description-content" id="{expand_id}">
                                    <div class="description-text">
                                        <strong>Original (Inglês):</strong><br><br>
                                        {description_html}
                                    </div>
                                    <div class="description-translation">
                                        <div class="translation-label"><i class="bi bi-translate"></i> Tradução (Português):</div>
                                        <div>{description_pt_html}</div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="component-info">
                                <div class="info-item">
                                    <div class="info-label"><i class="bi bi-check-circle"></i> Versão Corrigida</div>
                                    <div class="info-value fixed">{fixed_version}</div>
                                </div>
                            </div>
                            
                            <div class="vuln-actions">'''
                    
                    if nvd_link:
                        html_content += f'''
                                <a href="{nvd_link}" target="_blank" class="btn btn-primary">
                                    <i class="bi bi-link-45deg"></i> Ver no NVD
                                </a>'''
                    
                    html_content += f'''
                                <a href="{self._get_oss_index_link(comp_name)}" target="_blank" class="btn btn-secondary">
                                    <i class="bi bi-journal-text"></i> OSS Index
                                </a>
                            </div>
                        </div>'''
                
                html_content += '''
                    </div>
                </div>
                </div>'''
        else:
            html_content += '''
                <div class="empty-state">
                    <div class="icon"><i class="bi bi-shield-check"></i></div>
                    <div class="message">Nenhuma vulnerabilidade detectada</div>
                    <div class="note">Todos os componentes analisados estão seguros ou não possuem vulnerabilidades conhecidas publicamente.</div>
                </div>'''
        
        html_content += '''
            </div>
        </div>
        
        <!-- Recommendations Tab -->
        <div id="recommendations" class="tab-content">
            <div class="section">
                <h2 class="section-title"><i class="bi bi-lightbulb"></i> Recomendações de Mitigação</h2>'''
        
        if vulnerable_components:
            # Agrupar recomendações por severidade
            critical_vulns = [c for c in vulnerable_components if c.get('max_severity_score', 0) == 4]
            high_vulns = [c for c in vulnerable_components if c.get('max_severity_score', 0) == 3]
            
            if critical_vulns:
                html_content += '''
                <h3 class="section-subtitle"><i class="bi bi-exclamation-octagon-fill"></i> Ações Urgentes (Críticas)</h3>'''
                for comp in critical_vulns:
                    comp_name = comp.get('name', 'N/A')
                    vulns = comp.get('vulnerabilities', [])
                    critical_vulns_list = [v for v in vulns if v.get('severity') == 'CRITICAL']
                    
                    for vuln in critical_vulns_list:
                        fixed_version = vuln.get('fixed_version', 'última versão disponível')
                        html_content += f'''
                <div class="recommendation-card">
                    <div class="title"><i class="bi bi-shield-exclamation"></i> Atualizar {comp_name} imediatamente</div>
                    <div class="content">
                        <p><strong>Vulnerabilidade:</strong> {vuln.get('id', 'N/A')} (CVSS: {vuln.get('score', 0)})</p>
                        <p><strong>Ação:</strong> Atualizar para a versão {fixed_version}</p>
                        <p><strong>Motivo:</strong> Vulnerabilidade crítica que pode comprometer a segurança do sistema.</p>
                    </div>
                </div>'''
            
            if high_vulns:
                html_content += '''
                <h3 class="section-subtitle"><i class="bi bi-exclamation-triangle-fill"></i> Prioridade Alta</h3>'''
                for comp in high_vulns:
                    comp_name = comp.get('name', 'N/A')
                    vulns = comp.get('vulnerabilities', [])
                    high_vulns_list = [v for v in vulns if v.get('severity') == 'HIGH']
                    
                    for vuln in high_vulns_list:
                        fixed_version = vuln.get('fixed_version', 'última versão disponível')
                        html_content += f'''
                <div class="recommendation-card">
                    <div class="title"><i class="bi bi-exclamation-triangle"></i> Atualizar {comp_name} em breve</div>
                    <div class="content">
                        <p><strong>Vulnerabilidade:</strong> {vuln.get('id', 'N/A')} (CVSS: {vuln.get('score', 0)})</p>
                        <p><strong>Ação:</strong> Atualizar para a versão {fixed_version}</p>
                        <p><strong>Motivo:</strong> Vulnerabilidade de alta severidade que requer atenção.</p>
                    </div>
                </div>'''
            
            html_content += '''
                <h3 class="section-subtitle"><i class="bi bi-card-checklist"></i> Recomendações Gerais</h3>
                <div class="recommendation-card">
                    <div class="title"><i class="bi bi-arrow-repeat"></i> Mantenha suas dependências atualizadas</div>
                    <div class="content">
                        Execute análises periódicas para identificar novas vulnerabilidades e mantenha todas as dependências em suas versões mais recentes e seguras.
                    </div>
                </div>
                
                <div class="recommendation-card">
                    <div class="title"><i class="bi bi-shield-lock"></i> Implemente políticas de segurança</div>
                    <div class="content">
                        Estabeleça processos de revisão de segurança antes de adicionar novas dependências ao projeto e configure alertas automáticos para vulnerabilidades.
                    </div>
                </div>
                
                <div class="recommendation-card">
                    <div class="title"><i class="bi bi-journal-text"></i> Monitore fontes oficiais</div>
                    <div class="content">
                        Acompanhe o NVD, OSS Index e advisories dos mantenedores das bibliotecas utilizadas para se manter informado sobre novas vulnerabilidades.
                    </div>
                </div>'''
        else:
            html_content += '''
                <div class="empty-state">
                    <div class="icon"><i class="bi bi-check-circle"></i></div>
                    <div class="message">Seu projeto está seguro!</div>
                    <div class="note">Continue monitorando regularmente suas dependências para manter a segurança.</div>
                </div>'''
        
        html_content += f'''
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Relatório gerado por <strong>{scan_metadata['tool']} v{scan_metadata['version']}</strong></p>
            <p>{scan_metadata['scan_timestamp']}</p>
        </div>
    </div>
    
    <script>
        function openTab(tabName, event) {{
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            const tabs = document.querySelectorAll('.nav-tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            document.getElementById(tabName).classList.add('active');
            
            if (event && event.target) {{
                event.target.classList.add('active');
            }}
        }}

        function toggleComponent(id) {{
            const content = document.getElementById(id);
            const arrow = document.getElementById('arrow-' + id);

            if (content.classList.contains('expanded')) {{
                content.classList.remove('expanded');
                arrow.classList.remove('expanded');
            }} else {{
                content.classList.add('expanded');
                arrow.classList.add('expanded');
            }}
        }}
        
        function toggleDescription(id) {{
            const content = document.getElementById(id);
            const arrow = document.getElementById('arrow-' + id);
            
            if (content.classList.contains('expanded')) {{
                content.classList.remove('expanded');
                arrow.classList.remove('expanded');
            }} else {{
                content.classList.add('expanded');
                arrow.classList.add('expanded');
            }}
        }}
    </script>
        }}
    </script>
</body>
</html>'''
        
        return html_content

    def save_report_to_file(
        self,
        report_data: Dict,
        output_path: str,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> str:
        """
        Salva o relatório em arquivo HTML na pasta reports.
        
        Args:
            report_data: Dados do relatório
            output_path: Nome do arquivo de saída
            
        Returns:
            Caminho completo do arquivo salvo
            
        Raises:
            PermissionError: Se não houver permissão para escrever no arquivo
            OSError: Se houver erro de I/O ao salvar o arquivo
        """
        import shutil
        
        # Cria diretório reports no diretório de trabalho atual
        reports_dir = self._create_reports_directory()
        
        # Garante que o arquivo será salvo na pasta reports
        output_file_name = pathlib.Path(output_path).name
        output_file = reports_dir / output_file_name
        
        self.console.print(f"[dim]💾 Salvando relatório em: {output_file}[/dim]")
        
        if output_file.exists():
            self.console.print(f"[yellow]⚠️  O arquivo '{output_file}' já existe e será sobrescrito.[/yellow]")
        
        try:
            # Cria diretório resources dentro da pasta reports se não existir
            resources_output_dir = reports_dir / "resources"
            resources_output_dir.mkdir(exist_ok=True)
            if progress_callback:
                progress_callback("resources")
            
            # Caminho para o logo original
            current_dir = pathlib.Path(__file__).parent.parent.parent
            logo_source = current_dir / "resources" / "logo.png"
            logo_destination = resources_output_dir / "logo.png"
            
            # Copia o logo se existir
            if logo_source.exists():
                shutil.copy2(logo_source, logo_destination)
            else:
                self.console.print(f"[yellow]⚠️  Logo não encontrado em: {logo_source}[/yellow]")
            
            # Salva o HTML
            html_content = self.generate_html_report(report_data)
            if progress_callback:
                progress_callback("html")
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(html_content)
            if progress_callback:
                progress_callback("written")
            
            return str(output_file)
                
        except PermissionError:
            raise PermissionError(f"Sem permissão para escrever no arquivo: {output_file}")
        except OSError as e:
            raise OSError(f"Erro ao salvar o relatório: {e}")
    
    def display_scan_results(self, dependencies: List[Dict], ecosystems: Dict, output_file: str, vulnerabilities: Optional[Dict[str, List[Dict]]] = None) -> None:
        """
        Exibe os resultados da varredura no console.
        
        Args:
            dependencies: Lista de dependências encontradas
            ecosystems: Estatísticas por ecossistema
            output_file: Arquivo onde o relatório foi salvo
            vulnerabilities: Dicionário com vulnerabilidades encontradas
        """
        self.console.print("[bold green]✅ Varredura concluída com sucesso![/bold green]")
        self.console.print(f"[cyan]📊 Estatísticas:[/cyan]")
        self.console.print(f"   • [bold]{len(dependencies)}[/bold] dependências encontradas")
        
        for eco, count in ecosystems.items():
            emoji = ECOSYSTEM_EMOJIS.get(eco, "❓")
            self.console.print(f"   • {emoji} [bold]{count}[/bold] dependência(s) do ecossistema [italic]{eco}[/italic]")
        
        # Exibir estatísticas de vulnerabilidades
        if vulnerabilities:
            total_vulns = sum(len(v) for v in vulnerabilities.values())
            vulns_components = sum(1 for v in vulnerabilities.values() if v)
            
            if total_vulns > 0:
                self.console.print(f"\n[yellow]🔒 Vulnerabilidades:[/yellow]")
                self.console.print(f"   • [bold]{total_vulns}[/bold] vulnerabilidade(s) encontrada(s)")
                self.console.print(f"   • [bold]{vulns_components}[/bold] componente(s) afetado(s)")
                
                # Contar por severidade
                severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                for vulns in vulnerabilities.values():
                    for vuln in vulns:
                        severity = vuln.get('severity', 'UNKNOWN')
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                
                if severity_counts['CRITICAL'] > 0:
                    self.console.print(f"   • [bold red]{severity_counts['CRITICAL']}[/bold red] crítica(s)")
                if severity_counts['HIGH'] > 0:
                    self.console.print(f"   • [bold orange1]{severity_counts['HIGH']}[/bold orange1] alta(s)")
                if severity_counts['MEDIUM'] > 0:
                    self.console.print(f"   • [bold yellow]{severity_counts['MEDIUM']}[/bold yellow] média(s)")
                if severity_counts['LOW'] > 0:
                    self.console.print(f"   • [bold blue]{severity_counts['LOW']}[/bold blue] baixa(s)")
        
        self.console.print(f"\n[bold blue]📁 Relatório HTML salvo em:[/bold blue] [underline]{output_file}[/underline]")
        try:
            report_uri = pathlib.Path(output_file).resolve().as_uri()
            opened = webbrowser.open(report_uri)

            if opened:
                self.console.print("[green]🌐 Relatório aberto automaticamente no navegador.[/green]")
            else:
                self.console.print("[yellow]⚠️ Não foi possível abrir automaticamente. Abra o arquivo manualmente no navegador.[/yellow]")
        except Exception as e:
            self.console.print(f"[yellow]⚠️ Não foi possível abrir o navegador automaticamente: {e}[/yellow]")
    
    def display_scan_header(self, target_path: pathlib.Path, output_file: str, url_mode: bool = False, url: str = None) -> None:
        """
        Exibe o cabeçalho da varredura.
        
        Args:
            target_path: Caminho do projeto sendo analisado
            output_file: Nome do arquivo onde o relatório será salvo
            url_mode: Se está usando modo URL
            url: URL original (se aplicável)
        """
        # Inicia o timer quando começa a análise
        self.start_timer()
        
        reports_dir = self._create_reports_directory()
        output_file_name = pathlib.Path(output_file).name
        final_output_path = reports_dir / output_file_name
        
        if url_mode and url:
            self.console.print(f"[dim]🎯 Usando modo URL: {url}[/dim]")
        else:
            self.console.print(f"[dim]🎯 Usando diretório do projeto: {target_path}[/dim]")
        
        self.console.print(f"[cyan]🔍 [BasiliskScan][/cyan] Analisando projeto em: [bold green]{target_path}[/bold green]")
        self.console.print(f"[dim]📋 Relatório será salvo em: {final_output_path}[/dim]\n")


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
