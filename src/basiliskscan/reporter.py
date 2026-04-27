# src/basiliskscan/reporter.py
"""Módulo responsável pela geração de relatórios e apresentação de resultados."""

import pathlib
import time
import webbrowser
import json
import html
import os
import re
from datetime import datetime
from typing import Callable, Dict, List, Optional
from packaging.version import InvalidVersion, Version
from rich.console import Console
from deep_translator import GoogleTranslator

from .config import APP_NAME, APP_VERSION, ECOSYSTEM_EMOJIS


class ReportGenerator:
    """Gerador de relatórios de análise de dependências."""

    _INVALID_FIXED_VERSION_TOKENS = {
        "none",
        "null",
        "n/a",
        "na",
        "unknown",
        "not available",
        "-",
    }

    _ECOSYSTEM_ALIASES: Dict[str, str] = {
        "node": "npm",
        "node.js": "npm",
        "nodejs": "npm",
        "javascript": "npm",
        "typescript": "npm",
        "python": "pypi",
        "pip": "pypi",
        "pipenv": "pypi",
        "poetry": "pypi",
        "php": "composer",
        "packagist": "composer",
        "rubygems": "gem",
        "ruby": "gem",
        "golang": "go",
        "go-module": "go",
        "gomod": "go",
        "go modules": "go",
    }

    _ECOSYSTEM_BADGE_LABELS: Dict[str, str] = {
        "npm": "NPM",
        "ionic": "IONIC",
        "pypi": "PYTHON",
        "composer": "PHP",
        "maven": "MAVEN",
        "gradle": "GRADLE",
        "ant": "ANT",
        "nuget": "NUGET",
        "gem": "RUBY",
        "cargo": "RUST",
        "go": "GO",
        "unknown": "UNKNOWN",
    }
    
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
        self._translation_cache: Dict[str, str] = {}
        # Termos técnicos que não devem ser traduzidos para evitar perda de sentido.
        self._translation_protected_patterns: List[str] = [
            r"\bJavaScript\b",
            r"\bJavascript\b",
            r"\bTypeScript\b",
            r"\bRust\b",
            r"\brust\b",
            r"\bNode\.js\b",
            r"\bnode\.js\b",
            r"\bNode\b",
            r"\bnode\b",
            r"\bReact\b",
            r"\bNext\.js\b",
            r"\bVue\.js\b",
            r"\bAngular\b",
            r"\bnpm\b",
            r"\bpnpm\b",
            r"\byarn\b",
            r"\bpackage\b",
            r"\bpackages\b",
            r"\blockfile\b",
            r"\bcrate\b",
            r"\bGo\b",
            r"\bJWT\b",
            r"\bjwt\b",
            r"\bjsonwebtoken\b",
            r"\bFailedToParse\b",
            r"\bNotPresent\b",
            r"\bactivate_nbf\b",
            r"\brequire_spec_claims\b",
            r"\bnbf\b",
            r"\bexp\b",
            r"\b[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]*\b",
            r"\b[A-Z][a-z]+[A-Z][A-Za-z0-9]*\b",
            r"\bCVE-\d{4}-\d{4,7}\b",
        ]
        disable_translation = os.getenv("BASILISKSCAN_DISABLE_TRANSLATION", "").strip().lower()
        self.disable_translation = disable_translation in {"1", "true", "yes", "on"}
        self._translator: Optional[GoogleTranslator] = None
        self._sorted_translation_protected_patterns = sorted(
            self._translation_protected_patterns,
            key=len,
            reverse=True,
        )
        self._cached_vuln_lookup_data_id: Optional[int] = None
        self._cached_vuln_lookup: Dict[str, List[Dict]] = {}

    def _get_translator(self) -> GoogleTranslator:
        """Retorna instância reutilizável do tradutor para evitar overhead por chamada."""
        if self._translator is None:
            self._translator = GoogleTranslator(source='en', target='pt')
        return self._translator

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

    def _load_report_css(self) -> str:
        """Carrega o CSS do relatório com fallback para estilo mínimo."""
        css_path = pathlib.Path(__file__).parent / "data" / "report.css"
        try:
            return css_path.read_text(encoding="utf-8")
        except Exception:
            return """
        * {
            box-sizing: border-box;
        }
        body {
            font-family: 'Montserrat', sans-serif;
            margin: 0;
            background: #0f1419;
            color: #e0e0e0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 16px;
        }
        """
    
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
        vulnerabilities: Optional[Dict[str, List[Dict]]] = None,
        all_dependencies: Optional[List[Dict]] = None,
        report_options: Optional[Dict[str, object]] = None,
        duration_seconds: Optional[float] = None,
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
        if duration_seconds is None:
            self.stop_timer()
            total_duration = round(self.scan_duration, 2)
        else:
            total_duration = round(max(float(duration_seconds), 0.0), 2)
            self.scan_duration = total_duration
        
        return {
            "scan_metadata": {
                "tool": APP_NAME,
                "version": APP_VERSION,
                "scan_date": datetime.now().isoformat(),
                "scan_timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                "target_path": str(target_path),
                "output_file": output_file,
                "duration_seconds": total_duration
            },
            "project_info": {
                "path": str(target_path),
                "dependency_count": len(dependencies),
                "ecosystems_found": ecosystems
            },
            "dependencies": dependencies,
            "vulnerabilities": vulnerabilities or {},
            "report_options": report_options or {},
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

    @staticmethod
    def _format_duration_label(duration_seconds: float) -> str:
        """Formata duração em `mm:ss` ou `hh:mm:ss` para exibição no relatório."""
        safe_seconds = max(float(duration_seconds or 0.0), 0.0)
        rounded_seconds = int(round(safe_seconds))

        hours, remainder = divmod(rounded_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        return f"{minutes:02d}:{seconds:02d}"
    
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
        if self.disable_translation:
            return text

        cache_key = text.strip()
        if not cache_key:
            return text

        cached = self._translation_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            protected_map: Dict[str, str] = {}
            protected_text = self._protect_translation_terms(text, protected_map)

            # Limitar tamanho e dividir em chunks se necessário
            max_chunk_size = 4500  # Deixar margem de segurança
            
            translator = self._get_translator()

            if len(protected_text) <= max_chunk_size:
                translated = translator.translate(protected_text)
                translated = translated if translated else protected_text
                final_text = self._restore_translation_terms(translated, protected_map)
                self._translation_cache[cache_key] = final_text
                return final_text
            
            # Dividir texto em chunks menores
            # Tentar dividir por parágrafos primeiro
            paragraphs = protected_text.split('\n\n')
            translated_parts = []
            current_chunk = ""
            
            for para in paragraphs:
                # Se o parágrafo sozinho é muito grande, dividir por sentenças
                if len(para) > max_chunk_size:
                    sentences = para.split('. ')
                    for sentence in sentences:
                        if len(current_chunk) + len(sentence) < max_chunk_size:
                            current_chunk += sentence + '. '
                        else:
                            if current_chunk:
                                translated_parts.append(translator.translate(current_chunk) or current_chunk)
                            current_chunk = sentence + '. '
                else:
                    # Se adicionar este parágrafo exceder o limite, traduzir o chunk atual
                    if len(current_chunk) + len(para) > max_chunk_size:
                        if current_chunk:
                            translated_parts.append(translator.translate(current_chunk) or current_chunk)
                        current_chunk = para + '\n\n'
                    else:
                        current_chunk += para + '\n\n'
            
            # Traduzir o último chunk
            if current_chunk:
                translated_parts.append(translator.translate(current_chunk) or current_chunk)
            
            joined_translation = ''.join(translated_parts)
            final_text = self._restore_translation_terms(joined_translation, protected_map)
            self._translation_cache[cache_key] = final_text
            return final_text
            
        except Exception as e:
            # Em caso de erro, retorna o texto original
            self.console.print(f"[yellow]⚠️ Erro na tradução: {str(e)[:100]}[/yellow]")
            self._translation_cache[cache_key] = text
            return text

    def _protect_translation_terms(self, text: str, protected_map: Dict[str, str]) -> str:
        """Substitui termos técnicos por placeholders estáveis antes da tradução."""
        protected_text = text

        # Padrões maiores primeiro para evitar substituições parciais (Node.js antes de Node).
        for pattern in self._sorted_translation_protected_patterns:
            protected_text = re.sub(
                pattern,
                lambda match: self._register_translation_placeholder(match.group(0), protected_map),
                protected_text,
            )

        return protected_text

    def _register_translation_placeholder(self, original: str, protected_map: Dict[str, str]) -> str:
        """Registra um placeholder único preservando o termo técnico original."""
        placeholder = f"[[BASILISK_KEEP_{len(protected_map)}]]"
        protected_map[placeholder] = original
        return placeholder

    def _restore_translation_terms(self, text: str, protected_map: Dict[str, str]) -> str:
        """Restaura placeholders para os termos técnicos originais após a tradução."""
        restored = text
        for placeholder, original in protected_map.items():
            restored = restored.replace(placeholder, original)
        return restored
    
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

    def _sanitize_fixed_version_text(self, value: object) -> Optional[str]:
        """Normaliza `fixed_version` textual removendo placeholders inválidos."""
        if value is None:
            return None

        normalized = str(value).strip().strip('"').strip("'")
        if not normalized:
            return None

        if normalized.lower() in self._INVALID_FIXED_VERSION_TOKENS:
            return None

        return normalized

    def _resolve_fixed_version(self, vuln: Dict) -> Optional[str]:
        """Resolve versão corrigida a partir do campo explícito ou inferência textual."""
        explicit_fixed = self._sanitize_fixed_version_text(vuln.get("fixed_version"))
        if explicit_fixed:
            return explicit_fixed

        candidate_versions: List[str] = []

        description = str(vuln.get("description", "") or "").strip()
        candidate_versions.extend(self._extract_fixed_versions_from_text(description))

        raw_data = vuln.get("raw_data") or {}
        if isinstance(raw_data, dict):
            summary = str(raw_data.get("summary", "") or "").strip()
            details = str(raw_data.get("details", "") or "").strip()
            candidate_versions.extend(self._extract_fixed_versions_from_text(summary))
            candidate_versions.extend(self._extract_fixed_versions_from_text(details))

            cve = raw_data.get("cve") or {}
            if isinstance(cve, dict):
                for item in cve.get("descriptions", []) or []:
                    if not isinstance(item, dict):
                        continue
                    candidate_versions.extend(
                        self._extract_fixed_versions_from_text(str(item.get("value", "") or ""))
                    )

        if not candidate_versions:
            return None

        return self._pick_highest_version(candidate_versions)

    def _extract_fixed_versions_from_text(self, text: str) -> List[str]:
        """Extrai possíveis versões corrigidas a partir de texto de advisory."""
        if not text:
            return []

        patterns = [
            r"(?:upgrade|update)\s+to\s+(?:[\w.-]+@)?\s*(?:>=|=>|=|v)?\s*(\d+(?:\.\d+){1,3}(?:[-+._]?[0-9A-Za-z]+)?)",
            r"(?:fixed|patched|resolved|mitigated)\s+(?:in|by)\s+(?:version\s+)?(?:[\w.-]+@)?\s*(?:>=|=>|=|v)?\s*(\d+(?:\.\d+){1,3}(?:[-+._]?[0-9A-Za-z]+)?)",
            r"(?:before|prior\s+to)\s+(\d+(?:\.\d+){1,3}(?:[-+._]?[0-9A-Za-z]+)?)",
        ]

        candidates: List[str] = []
        for pattern in patterns:
            for match in re.findall(pattern, text, flags=re.IGNORECASE):
                cleaned = self._sanitize_fixed_version_text(match)
                if cleaned:
                    candidates.append(cleaned)

        return candidates

    def _pick_highest_version(self, versions: List[str]) -> Optional[str]:
        """Escolhe a maior versão válida entre candidatas textuais."""
        parsed_candidates: List[tuple[Version, str]] = []
        for item in versions:
            parsed = self._parse_version(item)
            if parsed is not None:
                parsed_candidates.append((parsed, item))

        if not parsed_candidates:
            return None

        parsed_candidates.sort(key=lambda entry: entry[0])
        return parsed_candidates[-1][1]

    def _find_dependency_vulnerabilities(self, dep: Dict, vulnerabilities_data: Dict[str, List[Dict]]) -> List[Dict]:
        """Localiza vulnerabilidades por nome e filtra aplicabilidade por versão/ecossistema."""
        dep_name = str(dep.get("name", "") or "").strip()
        if not dep_name:
            return []

        dep_vulns = vulnerabilities_data.get(dep_name, [])

        if not dep_vulns:
            lookup = self._get_case_insensitive_vuln_lookup(vulnerabilities_data)
            dep_vulns = lookup.get(dep_name.lower(), [])

        return [
            vuln
            for vuln in dep_vulns
            if self._is_vulnerability_applicable(dep, vuln)
        ]

    def _get_case_insensitive_vuln_lookup(self, vulnerabilities_data: Dict[str, List[Dict]]) -> Dict[str, List[Dict]]:
        """Cria cache de lookup case-insensitive para evitar varreduras repetidas."""
        data_id = id(vulnerabilities_data)
        if self._cached_vuln_lookup_data_id == data_id:
            return self._cached_vuln_lookup

        lookup: Dict[str, List[Dict]] = {}
        for vuln_key, vuln_list in vulnerabilities_data.items():
            normalized_key = str(vuln_key).lower()
            if normalized_key not in lookup:
                lookup[normalized_key] = vuln_list

        self._cached_vuln_lookup_data_id = data_id
        self._cached_vuln_lookup = lookup
        return lookup

    def _is_vulnerability_applicable(self, dep: Dict, vuln: Dict) -> bool:
        """Determina se uma vulnerabilidade é aplicável ao componente/versão analisado."""
        dep_version = self._extract_dependency_version(dep)

        if dep_version:
            fixed_version = self._parse_version(self._resolve_fixed_version(vuln))
            if fixed_version and dep_version >= fixed_version:
                return False

        affected_products = vuln.get("affected_products") or []
        if not isinstance(affected_products, list) or not affected_products:
            return True

        dep_name = str(dep.get("name", "") or "").strip().lower()
        dep_ecosystem = self._normalize_ecosystem_badge_token(dep.get("ecosystem"))

        has_package_scoped_entries = False
        matched_package_entries = False

        for affected in affected_products:
            if not isinstance(affected, dict):
                continue

            affected_name = str(affected.get("name", "") or "").strip().lower()
            affected_ecosystem = self._normalize_ecosystem_badge_token(affected.get("ecosystem"))

            is_package_scoped = bool(affected_name or affected_ecosystem)
            if is_package_scoped:
                has_package_scoped_entries = True

                if affected_name and affected_name != dep_name:
                    continue

                if affected_ecosystem and affected_ecosystem != dep_ecosystem:
                    continue

                matched_package_entries = True

            if dep_version is None:
                return True

            if self._is_version_affected(dep_version, affected):
                return True

        if has_package_scoped_entries:
            return matched_package_entries and dep_version is None

        return True

    def _is_version_affected(self, dep_version: Version, affected: Dict) -> bool:
        """Verifica se a versão da dependência está nas faixas/versões afetadas."""
        versions = affected.get("versions") or []
        for item in versions:
            parsed = self._parse_version(item)
            if parsed and parsed == dep_version:
                return True

        ranges = affected.get("ranges") or []
        for range_info in ranges:
            events = range_info.get("events") or []
            if self._is_version_in_osv_events(dep_version, events):
                return True

        version_start = self._parse_version(affected.get("version_start"))
        version_end = self._parse_version(affected.get("version_end"))
        if version_start and dep_version < version_start:
            return False
        if version_end and dep_version > version_end:
            return False
        if version_start or version_end:
            return True

        if not versions and not ranges:
            return True

        return False

    def _is_version_in_osv_events(self, dep_version: Version, events: List[Dict]) -> bool:
        """Avalia se a versão está dentro de uma sequência de eventos OSV."""
        affected = False
        has_window = False

        for event in events:
            if not isinstance(event, dict):
                continue

            introduced = self._parse_version(event.get("introduced"))
            if "introduced" in event:
                has_window = True
                introduced_raw = str(event.get("introduced") or "").strip()
                affected = introduced_raw == "0" or (introduced is not None and dep_version >= introduced)

            fixed = self._parse_version(event.get("fixed"))
            if fixed:
                has_window = True
                if dep_version >= fixed:
                    affected = False
                elif affected:
                    return True

            last_affected = self._parse_version(event.get("last_affected"))
            if last_affected:
                has_window = True
                if affected and dep_version <= last_affected:
                    return True
                if dep_version > last_affected:
                    affected = False

            limit = self._parse_version(event.get("limit"))
            if limit:
                has_window = True
                if dep_version >= limit:
                    affected = False

        if has_window:
            return affected

        return False

    def _extract_dependency_version(self, dep: Dict) -> Optional[Version]:
        """Extrai versão comparável da dependência, lidando com formatos comuns de spec."""
        raw_value = str(dep.get("version_spec", "") or "").strip()
        if not raw_value:
            return None

        parts = [part.strip() for part in raw_value.split("/") if part.strip()]
        if not parts:
            parts = [raw_value]

        for part in parts:
            parsed = self._parse_version(part)
            if parsed:
                return parsed

        return None

    def _parse_version(self, value: object) -> Optional[Version]:
        """Converte texto de versão para `Version`, quando possível."""
        if value is None:
            return None

        text = str(value).strip().strip('"').strip("'")
        if not text:
            return None

        text = re.sub(r"^[~^<>=\s]+", "", text)
        if not text:
            return None

        text = text.split(" ")[0].split("||")[0].split(",")[0].strip()
        if not text:
            return None

        try:
            return Version(text)
        except InvalidVersion:
            return None

    def _component_group_scope(self, dependency: Dict) -> str:
        """Define escopo lógico de agrupamento para evitar duplicações no relatório."""
        declared_in = str(dependency.get("declared_in", "") or "")
        ecosystem = str(dependency.get("ecosystem", "") or "").lower()

        if not declared_in:
            return ""

        file_path = pathlib.Path(declared_in)
        file_name = file_path.name.lower()

        if ecosystem in {"npm", "ionic"} and file_name in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
            return str(file_path.parent)

        if ecosystem == "gradle" and file_name in {"build.gradle", "build.gradle.kts", "gradle.lockfile"}:
            return str(file_path.parent)

        if ecosystem == "maven" and file_name == "pom.xml":
            return str(file_path.parent)

        return declared_in

    def _normalize_ecosystem_badge_token(self, ecosystem: object) -> str:
        """Normaliza token de ecossistema para chave estável de badge."""
        raw = str(ecosystem or "unknown").strip().lower()
        if not raw:
            return "unknown"

        canonical = self._ECOSYSTEM_ALIASES.get(raw, raw)
        return canonical

    def _get_ecosystem_badge_info(self, ecosystem: object) -> Dict[str, str]:
        """Retorna metadados (classe/label) da badge de ecossistema."""
        canonical = self._normalize_ecosystem_badge_token(ecosystem)
        badge_class = re.sub(r"[^a-z0-9_-]+", "-", canonical).strip("-") or "unknown"
        label = self._ECOSYSTEM_BADGE_LABELS.get(canonical, canonical.upper())

        return {
            "class_name": badge_class,
            "label": label,
        }

    def _build_vulnerable_components(self, dependencies: List[Dict], vulnerabilities_data: Dict[str, List[Dict]]) -> List[Dict]:
        """Agrupa componentes vulneráveis removendo duplicações de origem equivalente."""
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
        grouped_components: Dict[tuple, Dict] = {}

        for dep in dependencies:
            dep_name = str(dep.get("name", "") or "")
            dep_vulns = self._find_dependency_vulnerabilities(dep, vulnerabilities_data)
            if not dep_vulns:
                continue

            ecosystem = str(dep.get("ecosystem", "unknown") or "unknown").lower()
            scope = self._component_group_scope(dep)
            group_key = (dep_name.lower(), ecosystem, scope)

            if group_key not in grouped_components:
                grouped_components[group_key] = {
                    **dep,
                    "vulnerabilities": [],
                    "max_severity_score": 0,
                    "declared_in_files": set(),
                }

            grouped_entry = grouped_components[group_key]
            declared_in = str(dep.get("declared_in", "") or "")
            if declared_in:
                grouped_entry["declared_in_files"].add(declared_in)

            existing_ids = {
                vuln.get("id", "")
                for vuln in grouped_entry["vulnerabilities"]
                if vuln.get("id")
            }

            for vulnerability in dep_vulns:
                vulnerability_id = vulnerability.get("id", "")
                if vulnerability_id and vulnerability_id in existing_ids:
                    continue
                grouped_entry["vulnerabilities"].append(vulnerability)
                if vulnerability_id:
                    existing_ids.add(vulnerability_id)

            grouped_entry["vulnerabilities"].sort(
                key=lambda vulnerability: severity_order.get(vulnerability.get("severity", "UNKNOWN"), 0),
                reverse=True,
            )
            grouped_entry["max_severity_score"] = max(
                [severity_order.get(vulnerability.get("severity", "UNKNOWN"), 0) for vulnerability in grouped_entry["vulnerabilities"]],
                default=0,
            )

        vulnerable_components = list(grouped_components.values())
        for component in vulnerable_components:
            files = sorted(component.get("declared_in_files", set()))
            component["declared_in"] = "<br>".join(files) if files else component.get("declared_in", "N/A")

        vulnerable_components.sort(key=lambda component: component["max_severity_score"], reverse=True)
        return vulnerable_components

    def _dependency_status_key(self, dependency: Dict) -> tuple:
        """Gera chave estável para lookup de status por componente e escopo."""
        return (
            str(dependency.get("name", "") or "").lower(),
            str(dependency.get("ecosystem", "unknown") or "unknown").lower(),
            self._component_group_scope(dependency),
        )

    def _build_grouped_dependencies(self, dependencies: List[Dict]) -> List[Dict]:
        """Agrupa dependências por componente+ecossistema+escopo para reduzir ruído da aba."""
        grouped: Dict[tuple, Dict] = {}

        for dep in dependencies:
            key = self._dependency_status_key(dep)

            if key not in grouped:
                grouped[key] = {
                    **dep,
                    "declared_in_files": set(),
                    "version_specs": set(),
                    "latest_versions": set(),
                    "has_direct": False,
                    "has_transitive": False,
                    "instance_count": 0,
                }

            entry = grouped[key]
            entry["instance_count"] += 1

            declared_in = str(dep.get("declared_in", "") or "")
            if declared_in:
                entry["declared_in_files"].add(declared_in)

            version_spec = str(dep.get("version_spec", "") or "").strip()
            if version_spec:
                entry["version_specs"].add(version_spec)

            latest_version = str(dep.get("latest_version", "") or "").strip()
            if latest_version:
                entry["latest_versions"].add(latest_version)
                if not entry.get("latest_version"):
                    entry["latest_version"] = latest_version

            dependency_type = str(dep.get("dependency_type", "") or "").strip().lower()
            is_transitive = dep.get("is_transitive") is True or dependency_type == "transitive"
            if is_transitive:
                entry["has_transitive"] = True
            else:
                entry["has_direct"] = True

            if dependency_type == "direct":
                entry["version_spec"] = dep.get("version_spec", entry.get("version_spec", ""))

        grouped_dependencies = list(grouped.values())
        for dep in grouped_dependencies:
            files = sorted(dep.get("declared_in_files", set()))
            dep["declared_in"] = "<br>".join(files) if files else dep.get("declared_in", "N/A")

            versions = sorted(dep.get("version_specs", set()))
            if len(versions) > 1:
                dep["version_spec"] = " / ".join(versions)
            elif len(versions) == 1:
                dep["version_spec"] = versions[0]

            latest_versions = sorted(dep.get("latest_versions", set()))
            if latest_versions:
                dep["latest_version"] = latest_versions[-1]

            has_direct = dep.get("has_direct", False)
            has_transitive = dep.get("has_transitive", False)
            if has_direct and has_transitive:
                dep["relationship"] = "mixed"
            elif has_transitive:
                dep["relationship"] = "transitive"
            else:
                dep["relationship"] = "direct"

        grouped_dependencies.sort(
            key=lambda dep: (
                self._normalize_ecosystem_badge_token(dep.get("ecosystem", "unknown")),
                str(dep.get("name", "") or "").lower(),
            )
        )
        return grouped_dependencies

    def _get_recommended_version(self, dep: Dict, dep_vulns: List[Dict]) -> Optional[str]:
        """Retorna uma versão corrigida recomendada quando disponível."""
        current_version = (dep.get("version_spec") or "").strip()
        latest_version = (dep.get("latest_version") or "").strip()

        if latest_version and latest_version != current_version:
            return latest_version

        for vuln in dep_vulns:
            fixed_version = self._resolve_fixed_version(vuln) or ""
            if fixed_version and fixed_version != current_version:
                return fixed_version

        return None

    def _build_dependency_statuses(
        self,
        dependencies: List[Dict],
        vulnerabilities_data: Dict[str, List[Dict]],
    ) -> Dict[tuple, Dict[str, object]]:
        """Gera lookup de status usando a coleção já exibida no relatório."""
        statuses: Dict[tuple, Dict[str, object]] = {}

        for dep in dependencies:
            dep_vulns = self._find_dependency_vulnerabilities(dep, vulnerabilities_data)
            statuses[self._dependency_status_key(dep)] = self._build_dependency_status(dep, dep_vulns)

        return statuses

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
                "tooltip": "O componente possui vulnerabilidades conhecidas publicamente e exige atenção.",
            })
        else:
            badges.append({
                "kind": "low",
                "label": "Seguro",
                "icon": "bi bi-shield-check",
                "tooltip": "Nenhuma vulnerabilidade conhecida foi encontrada para este componente nas fontes consultadas.",
            })

        if has_update:
            badges.append({
                "kind": "update",
                "label": "Atualização disponível",
                "icon": "bi bi-arrow-up-right-circle-fill",
                "tooltip": "Existe uma versão mais recente ou corrigida recomendada para este componente.",
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
            f'<span class="severity-badge {badge["kind"]}"><i class="{badge["icon"]}"></i> {badge["label"]}<span class="tooltip">{html.escape(badge.get("tooltip", ""))}</span></span>'
            for badge in badges
        )
        return f'<div class="status-badges">{badges_html}</div>'

    def _render_dependency_relationship_badge(self, dependency: Dict) -> str:
        """Renderiza badge de relacionamento direta/transitiva/mista."""
        relationship = str(dependency.get("relationship", "direct") or "direct").lower()
        if relationship == "transitive":
            return (
                '<span class="severity-badge transitive">'
                '<i class="bi bi-diagram-3"></i> Transitiva'
                '<span class="tooltip">Dependência instalada indiretamente por outra biblioteca do projeto.</span>'
                '</span>'
            )
        if relationship == "mixed":
            return (
                '<span class="severity-badge mixed">'
                '<i class="bi bi-intersect"></i> Mista'
                '<span class="tooltip">Componente aparece como dependência direta e também transitiva em outros manifestos/locks.</span>'
                '</span>'
            )
        return (
            '<span class="severity-badge direct">'
            '<i class="bi bi-record-circle"></i> Direta'
            '<span class="tooltip">Dependência declarada explicitamente no manifesto do projeto (ex.: package.json).</span>'
            '</span>'
        )

    def _get_cvss_rating_label(self, score: float, version: str) -> str:
        """Retorna a classificação qualitativa considerando a versão do CVSS."""
        normalized_version = str(version or "").strip().lower()

        if score <= 0:
            return "Nenhum"

        if normalized_version.startswith("2"):
            if score <= 3.9:
                return "Baixo"
            if score <= 6.9:
                return "Médio"
            return "Alto"

        if score <= 3.9:
            return "Baixo"
        if score <= 6.9:
            return "Médio"
        if score <= 8.9:
            return "Alto"
        return "Crítico"

    def _build_cvss_tooltip(self, vulnerability: Dict) -> str:
        """Monta tooltip explicativo do CVSS com faixas por versão."""
        cvss = vulnerability.get("cvss") or {}
        version = str(cvss.get("version") or "N/A")
        score = float(vulnerability.get("score") or cvss.get("score") or 0.0)
        rating = self._get_cvss_rating_label(score, version)
        normalized_version = version.strip().lower()

        if normalized_version.startswith("2"):
            active_column = "v2"
        elif normalized_version.startswith("3"):
            active_column = "v3"
        elif normalized_version.startswith("4"):
            active_column = "v4"
        else:
            active_column = "v4"

        def bucket_for(score_value: float, column: str) -> str:
            if score_value <= 0:
                return "none"
            if column == "v2":
                if score_value <= 3.9:
                    return "low"
                if score_value <= 6.9:
                    return "medium"
                return "high"

            if score_value <= 3.9:
                return "low"
            if score_value <= 6.9:
                return "medium"
            if score_value <= 8.9:
                return "high"
            return "critical"

        active_bucket = bucket_for(score, active_column)
        rows = [
            ("none", "Nenhum*", "0,0", "0,0", "0,0"),
            ("low", "Baixo", "0,0-3,9", "0,1-3,9", "0,1-3,9"),
            ("medium", "Médio", "4,0-6,9", "4,0-6,9", "4,0-6,9"),
            ("high", "Alto", "7,0-10,0", "7,0-8,9", "7,0-8,9"),
            ("critical", "Crítico", "—", "9,0-10,0", "9,0-10,0"),
        ]

        body_rows = []
        for bucket_key, label, v2_range, v3_range, v4_range in rows:
            def cell(value: str, column: str) -> str:
                is_active = bucket_key == active_bucket and column == active_column
                css_class = f'cvss-cell-active cvss-cell-active-{bucket_key}' if is_active else ''
                return f'<td class="{css_class}">{value}</td>'

            body_rows.append(
                "<tr>"
                f"<td>{label}</td>"
                f"{cell(v2_range, 'v2')}"
                f"{cell(v3_range, 'v3')}"
                f"{cell(v4_range, 'v4')}"
                "</tr>"
            )

        body_html = "".join(body_rows)

        return (
            '<div class="cvss-tooltip-content">'
            '<div class="cvss-tooltip-title">O que é CVSS?</div>'
            '<div class="cvss-tooltip-text">CVSS (Common Vulnerability Scoring System) é um padrão usado para medir a gravidade técnica de uma vulnerabilidade em uma escala de 0.0 a 10.0.</div>'
            f'<div class="cvss-tooltip-current">Métrica deste item: CVSS v{html.escape(version)} · score {score:.1f} · gravidade {html.escape(rating)}</div>'
            '<table class="cvss-tooltip-table">'
            '<thead><tr><th>Classificação</th><th>CVSS v2.0</th><th>CVSS v3.x</th><th>CVSS v4.0</th></tr></thead>'
            f'<tbody>{body_html}</tbody>'
            '</table>'
            '<div class="cvss-tooltip-footnote">* Em CVSS, score 0.0 indica ausência de impacto mensurável.</div>'
            '</div>'
        )

    def _build_component_status_chart_data(self, total_components: int, vulnerable_components: int, outdated_components: int) -> str:
        """Gera dados para o gráfico de status dos componentes."""
        import json

        return json.dumps({
            'labels': ['Total de Componentes', 'Componentes Vulneráveis', 'Componentes Desatualizados'],
            'data': [
                int(total_components or 0),
                int(vulnerable_components or 0),
                int(outdated_components or 0),
            ],
            'background_colors': ['rgba(74, 144, 217, 0.35)', 'rgba(231, 76, 60, 0.35)', 'rgba(243, 156, 18, 0.35)'],
            'border_colors': ['#4a90d9', '#e74c3c', '#f39c12']
        })

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
        report_options = report_data.get("report_options", {})
        transitive_hidden_count = int(report_options.get("transitive_hidden_count", 0) or 0)
        grouped_dependencies = self._build_grouped_dependencies(dependencies)
        displayed_dependencies_count = len(grouped_dependencies)
        
        # Identificar componentes vulneráveis e ordenar por severidade
        dependency_statuses = self._build_dependency_statuses(grouped_dependencies, vulnerabilities_data)

        vulnerable_components = self._build_vulnerable_components(dependencies, vulnerabilities_data)
        
        # Calcular estatísticas de vulnerabilidades (apenas aplicáveis)
        total_vulnerabilities = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        unknown_count = 0

        for component in vulnerable_components:
            for vuln in component.get("vulnerabilities", []):
                total_vulnerabilities += 1
                severity = vuln.get('severity', 'UNKNOWN')
                if severity == 'CRITICAL':
                    critical_count += 1
                elif severity == 'HIGH':
                    high_count += 1
                elif severity == 'MEDIUM':
                    medium_count += 1
                elif severity == 'LOW':
                    low_count += 1
                else:
                    unknown_count += 1

        outdated_components_count = sum(
            1
            for dep in grouped_dependencies
            if dependency_statuses.get(self._dependency_status_key(dep), {}).get('has_update')
        )

        critical_severity_description = self._get_severity_description('CRITICAL')
        high_severity_description = self._get_severity_description('HIGH')
        medium_severity_description = self._get_severity_description('MEDIUM')
        low_severity_description = self._get_severity_description('LOW')
        unknown_severity_description = self._get_severity_description('UNKNOWN')

        vuln_type_legend = self._build_vuln_type_legend(vulnerable_components)
        
        project_name = pathlib.Path(scan_metadata["target_path"]).name
        duration = scan_metadata.get('duration_seconds', 0)
        duration_label = self._format_duration_label(duration)
        
        # Gerar dados para o gráfico de status dos componentes
        component_status_chart_data = self._build_component_status_chart_data(
            displayed_dependencies_count,
            len(vulnerable_components),
            outdated_components_count,
        )
        severity_distribution_chart_data = json.dumps(
            {
                "labels": ["Críticas", "Altas", "Médias", "Baixas", "Sem severidade"],
                "data": [critical_count, high_count, medium_count, low_count, unknown_count],
                "background_colors": [
                    "rgba(231, 76, 60, 0.55)",
                    "rgba(230, 126, 34, 0.55)",
                    "rgba(243, 156, 18, 0.55)",
                    "rgba(74, 144, 217, 0.55)",
                    "rgba(127, 140, 141, 0.55)",
                ],
                "border_colors": ["#e74c3c", "#e67e22", "#f39c12", "#4a90d9", "#7f8c8d"],
            },
            ensure_ascii=False,
        )
        report_css = self._load_report_css()
        
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
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
{report_css}
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
                    <div class="value">{duration_label}</div>
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
            <button class="nav-tab" onclick="openTab('components', event)">
                <i class="bi bi-box-seam"></i> Componentes ({len(grouped_dependencies)})
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
                        <div class="number">{displayed_dependencies_count}</div>
                        <div class="label">Total de Componentes</div>
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
                        <div class="number">{duration_label}</div>
                        <div class="label">Tempo de Execução</div>
                    </div>
                </div>

                <div class="overview-charts-grid">
                    <div class="chart-panel">
                        <h3 class="section-subtitle"><i class="bi bi-bar-chart"></i> Status dos Componentes</h3>
                        <div class="chart-toolbar">
                            <div id="component-chart-controls" class="chart-type-switch" role="group" aria-label="Tipo de visualização do gráfico">
                                <button type="button" class="chart-type-btn active" data-chart-type="bar">Barras</button>
                                <button type="button" class="chart-type-btn" data-chart-type="doughnut">Donut</button>
                                <button type="button" class="chart-type-btn" data-chart-type="line">Linhas</button>
                            </div>
                        </div>
                        <div class="chart-container status-chart">
                            <canvas id="componentStatusChart"></canvas>
                        </div>
                        <div class="chart-legend-note">Comparativo entre total identificado, componentes com vulnerabilidades e componentes com atualização recomendada.</div>
                    </div>

                    <div class="chart-panel">
                        <h3 class="section-subtitle"><i class="bi bi-pie-chart"></i> Distribuição por Severidade</h3>
                        <div class="chart-toolbar">
                            <div id="severity-chart-controls" class="chart-type-switch" role="group" aria-label="Tipo de visualização do gráfico de severidade">
                                <button type="button" class="chart-type-btn active" data-chart-type="bar">Barras</button>
                                <button type="button" class="chart-type-btn" data-chart-type="doughnut">Donut</button>
                                <button type="button" class="chart-type-btn" data-chart-type="line">Linhas</button>
                            </div>
                        </div>
                        <div class="chart-container status-chart">
                            <canvas id="severityDistributionChart"></canvas>
                        </div>
                        <div class="chart-legend-note">Quantidade de vulnerabilidades por severidade: críticas, altas, médias, baixas e sem severidade definida.</div>
                    </div>
                </div>
                <script>
                    const statusCtx = document.getElementById('componentStatusChart').getContext('2d');
                    const componentStatusData = {component_status_chart_data};
                    const severityCtx = document.getElementById('severityDistributionChart').getContext('2d');
                    const severityDistributionData = {severity_distribution_chart_data};

                    const chartTypeButtons = document.querySelectorAll('#component-chart-controls .chart-type-btn');
                    const severityChartTypeButtons = document.querySelectorAll('#severity-chart-controls .chart-type-btn');
                    let componentStatusChart = null;
                    let severityDistributionChart = null;

                    function getStatusChartConfig(chartType) {{
                        if (chartType === 'line') {{
                            return {{
                                labels: ['Base', 'Quantidade'],
                                datasets: componentStatusData.labels.map(function(label, index) {{
                                    const value = Number(componentStatusData.data[index] ?? 0);
                                    const color = componentStatusData.border_colors[index];

                                    return {{
                                        label: label,
                                        data: [0, value],
                                        borderColor: color,
                                        backgroundColor: color,
                                        borderWidth: 2,
                                        tension: 0.25,
                                        fill: false,
                                        pointRadius: 4,
                                        pointHoverRadius: 6
                                    }};
                                }})
                            }};
                        }}

                        return {{
                            labels: componentStatusData.labels,
                            datasets: [{{
                                data: componentStatusData.data,
                                backgroundColor: componentStatusData.background_colors,
                                borderColor: componentStatusData.border_colors,
                                borderWidth: 2
                            }}]
                        }};
                    }}

                    function getStatusChartOptions(chartType) {{
                        const isDonut = chartType === 'doughnut';
                        const isLine = chartType === 'line';

                        return {{
                            responsive: true,
                            maintainAspectRatio: false,
                            cutout: isDonut ? '60%' : undefined,
                            scales: isDonut ? {{}} : {{
                                x: {{
                                    ticks: {{
                                        color: '#d0d0d0',
                                        font: {{
                                            family: "'Montserrat', sans-serif",
                                            size: 12,
                                            weight: '600'
                                        }}
                                    }},
                                    grid: {{
                                        color: 'rgba(255,255,255,0.06)'
                                    }}
                                }},
                                y: {{
                                    beginAtZero: true,
                                    ticks: {{
                                        precision: 0,
                                        color: '#d0d0d0',
                                        font: {{
                                            family: "'Montserrat', sans-serif",
                                            size: 12
                                        }}
                                    }},
                                    grid: {{
                                        color: 'rgba(255,255,255,0.08)'
                                    }}
                                }}
                            }},
                            plugins: {{
                                legend: {{
                                    display: isDonut || isLine,
                                    position: 'bottom',
                                    labels: {{
                                        color: '#d0d0d0',
                                        font: {{
                                            family: "'Montserrat', sans-serif",
                                            size: 12,
                                            weight: '600'
                                        }}
                                    }}
                                }},
                                tooltip: {{
                                    backgroundColor: 'rgba(0,0,0,0.8)',
                                    titleColor: '#ffffff',
                                    bodyColor: '#e0e0e0',
                                    borderColor: '#4a90d9',
                                    borderWidth: 1,
                                    padding: 12,
                                    titleFont: {{
                                        size: 13,
                                        weight: 'bold'
                                    }},
                                    bodyFont: {{
                                        size: 12
                                    }},
                                    callbacks: {{
                                        label: function(context) {{
                                            const label = context.label || '';
                                            const value = Number(context.raw ?? 0);
                                            return label + ': ' + value;
                                        }}
                                    }}
                                }}
                            }}
                        }};
                    }}

                    function renderComponentStatusChart(chartType) {{
                        if (componentStatusChart) {{
                            componentStatusChart.destroy();
                        }}

                        componentStatusChart = new Chart(statusCtx, {{
                            type: chartType,
                            data: getStatusChartConfig(chartType),
                            options: getStatusChartOptions(chartType)
                        }});
                    }}

                    function getSeverityDistributionChartOptions(chartType) {{
                        const isDonut = chartType === 'doughnut';
                        const isLine = chartType === 'line';

                        return {{
                            responsive: true,
                            maintainAspectRatio: false,
                            cutout: isDonut ? '58%' : undefined,
                            scales: isDonut ? {{}} : {{
                                x: {{
                                    ticks: {{
                                        color: '#d0d0d0',
                                        font: {{
                                            family: "'Montserrat', sans-serif",
                                            size: 12,
                                            weight: '600'
                                        }}
                                    }},
                                    grid: {{
                                        color: 'rgba(255,255,255,0.06)'
                                    }}
                                }},
                                y: {{
                                    beginAtZero: true,
                                    ticks: {{
                                        precision: 0,
                                        color: '#d0d0d0',
                                        font: {{
                                            family: "'Montserrat', sans-serif",
                                            size: 12
                                        }}
                                    }},
                                    grid: {{
                                        color: 'rgba(255,255,255,0.08)'
                                    }}
                                }}
                            }},
                            plugins: {{
                                legend: {{
                                    display: isDonut || isLine,
                                    position: 'bottom',
                                    labels: {{
                                        color: '#d0d0d0',
                                        font: {{
                                            family: "'Montserrat', sans-serif",
                                            size: 12,
                                            weight: '600'
                                        }}
                                    }}
                                }},
                                tooltip: {{
                                    backgroundColor: 'rgba(0,0,0,0.8)',
                                    titleColor: '#ffffff',
                                    bodyColor: '#e0e0e0',
                                    borderColor: '#4a90d9',
                                    borderWidth: 1,
                                    padding: 12,
                                    titleFont: {{
                                        size: 13,
                                        weight: 'bold'
                                    }},
                                    bodyFont: {{
                                        size: 12
                                    }},
                                    callbacks: {{
                                        label: function(context) {{
                                            const label = context.label || context.dataset.label || '';
                                            const value = Number(context.raw ?? 0);
                                            return label + ': ' + value;
                                        }}
                                    }}
                                }}
                            }}
                        }};
                    }}

                    function renderSeverityDistributionChart(chartType) {{
                        if (severityDistributionChart) {{
                            severityDistributionChart.destroy();
                        }}

                        const isLine = chartType === 'line';

                        severityDistributionChart = new Chart(severityCtx, {{
                            type: chartType,
                            data: {{
                                labels: severityDistributionData.labels,
                                datasets: [{{
                                    label: 'Vulnerabilidades',
                                    data: severityDistributionData.data,
                                    backgroundColor: severityDistributionData.background_colors,
                                    borderColor: severityDistributionData.border_colors,
                                    borderWidth: 2,
                                    tension: isLine ? 0.25 : 0,
                                    fill: false,
                                    pointRadius: isLine ? 4 : 0,
                                    pointHoverRadius: isLine ? 6 : 0
                                }}]
                            }},
                            options: getSeverityDistributionChartOptions(chartType)
                        }});
                    }}

                    function setActiveChartTypeButton(chartType) {{
                        chartTypeButtons.forEach(function(button) {{
                            button.classList.toggle('active', button.dataset.chartType === chartType);
                        }});
                    }}

                    function setActiveSeverityChartTypeButton(chartType) {{
                        severityChartTypeButtons.forEach(function(button) {{
                            button.classList.toggle('active', button.dataset.chartType === chartType);
                        }});
                    }}

                    chartTypeButtons.forEach(function(button) {{
                        button.addEventListener('click', function() {{
                            const selectedType = button.dataset.chartType;
                            setActiveChartTypeButton(selectedType);
                            renderComponentStatusChart(selectedType);
                        }});
                    }});

                    severityChartTypeButtons.forEach(function(button) {{
                        button.addEventListener('click', function() {{
                            const selectedType = button.dataset.chartType;
                            setActiveSeverityChartTypeButton(selectedType);
                            renderSeverityDistributionChart(selectedType);
                        }});
                    }});

                    setActiveChartTypeButton('bar');
                    renderComponentStatusChart('bar');
                    setActiveSeverityChartTypeButton('bar');
                    renderSeverityDistributionChart('bar');
                </script>
                
                <h3 class="section-subtitle"><i class="bi bi-bullseye"></i> Detalhamento por Severidade</h3>
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

                    <div class="stat-card neutral">
                        <div class="icon"><i class="bi bi-question-circle-fill"></i></div>
                        <div class="number">{unknown_count}</div>
                        <div class="label">
                            <span class="severity-chip">
                                Sem severidade
                                <span class="tooltip">{unknown_severity_description}</span>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Components Tab -->
        <div id="components" class="tab-content">
            <div class="section">
                <h2 class="section-title"><i class="bi bi-box-seam"></i> Componentes Identificados</h2>
                '''

        if transitive_hidden_count > 0:
            html_content += f'''
                <div class="dependency-note">
                    <i class="bi bi-info-circle"></i>
                    {transitive_hidden_count} componente(s) transitivo(s) foi(foram) ocultado(s) neste relatório.
                    Use <code>--include-transitive</code> para incluir também os transitivos.
                </div>'''

        html_content += '''
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
        
        for dep in grouped_dependencies:
            dep_name = dep.get('name', 'N/A')
            dep_vulns = self._find_dependency_vulnerabilities(dep, vulnerabilities_data)
            status = dependency_statuses.get(self._dependency_status_key(dep)) or self._build_dependency_status(dep, dep_vulns)
            version_html = self._format_dependency_version(dep, status)
            status_badge = self._render_status_badges(status)
            relationship_badge = self._render_dependency_relationship_badge(dep)

            ecosystem_badge = self._get_ecosystem_badge_info(dep.get('ecosystem', 'unknown'))
            html_content += f'''
                            <tr>
                                <td><strong>{dep_name}</strong></td>
                                <td>{version_html}</td>
                                <td><span class="ecosystem-badge {ecosystem_badge["class_name"]}">{ecosystem_badge["label"]}</span></td>
                                <td>{dep.get('declared_in', 'N/A')}</td>
                                <td>{status_badge}<div class="status-badges">{relationship_badge}</div></td>
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
            html_content += f'''
                <div class="vuln-type-legend" id="vuln-type-filters">
                    <button type="button" class="vuln-type vuln-type-filter active" data-vuln-type-filter="all">
                        <i class="bi bi-funnel"></i> Todas
                        <span class="type-count">({total_vulnerabilities})</span>
                    </button>'''
            for vuln_type, legend_info in vuln_type_legend.items():
                type_description = legend_info.get("description", "Sem descrição")
                type_count = legend_info.get("count", 0)
                vuln_type_slug = re.sub(r"[^a-z0-9]+", "-", vuln_type.lower()).strip("-") or "security-issue"
                html_content += f'''
                    <button type="button" class="vuln-type vuln-type-filter" data-vuln-type-filter="{vuln_type_slug}">
                        <i class="bi bi-tag"></i> {vuln_type}
                        <span class="type-count">({type_count})</span>
                        <span class="tooltip">{type_description}</span>
                    </button>'''

            html_content += '''
                </div>'''

        if vulnerable_components:
            html_content += f'''
                <div class="vuln-controls" id="vuln-controls">
                    <div class="vuln-control">
                        <label for="vuln-sort-select">Ordenar componentes</label>
                        <select id="vuln-sort-select">
                            <option value="severity-desc">Severidade (maior primeiro)</option>
                            <option value="severity-asc">Severidade (menor primeiro)</option>
                            <option value="count-desc">Quantidade de vulnerabilidades (maior primeiro)</option>
                            <option value="count-asc">Quantidade de vulnerabilidades (menor primeiro)</option>
                            <option value="name-asc">Nome do componente (A-Z)</option>
                            <option value="name-desc">Nome do componente (Z-A)</option>
                        </select>
                    </div>
                    <div class="vuln-control">
                        <label for="vuln-severity-filter">Filtrar severidade</label>
                        <select id="vuln-severity-filter">
                            <option value="all">Todas as severidades ({total_vulnerabilities})</option>
                            <option value="critical">Crítica ({critical_count})</option>
                            <option value="high">Alta ({high_count})</option>
                            <option value="medium">Média ({medium_count})</option>
                            <option value="low">Baixa ({low_count})</option>
                            <option value="unknown">Sem severidade ({unknown_count})</option>
                        </select>
                    </div>
                    <div class="vuln-control">
                        <label for="vuln-search-input">Buscar por CVE/componente/texto</label>
                        <input id="vuln-search-input" type="search" placeholder="Ex: CVE-2022, log4j, injection" />
                    </div>
                </div>
                <div class="vuln-results-summary" id="vuln-results-summary">
                    Exibindo
                    <span class="value" id="vuln-visible-count">{total_vulnerabilities}</span>
                    de
                    <span class="value" id="vuln-total-count">{total_vulnerabilities}</span>
                    vulnerabilidade(s) em
                    <span class="value" id="vuln-visible-components">{len(vulnerable_components)}</span>
                    componente(s).
                    Ordenação:
                    <span class="value" id="vuln-current-sort">Severidade (maior primeiro)</span>
                </div>
                <div id="vuln-cards-container">'''
        
        if vulnerable_components:
            for comp_idx, comp in enumerate(vulnerable_components):
                ecosystem_badge = self._get_ecosystem_badge_info(comp.get('ecosystem', 'unknown'))
                comp_name = comp.get('name', 'N/A')
                comp_version = comp.get('version_spec', 'N/A')
                vulns = comp.get('vulnerabilities', [])
                component_expand_id = f"component-{comp_idx}"
                max_severity_score = int(comp.get('max_severity_score', 0) or 0)
                
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
                <div class="vuln-card {max_severity}" data-component-name="{html.escape(str(comp_name).lower())}" data-max-severity-score="{max_severity_score}" data-vuln-count="{len(vulns)}">
                    <div class="vuln-card-header">
                        <div class="component-name">
                            <span>{comp_name}</span>
                            <span class="ecosystem-badge {ecosystem_badge["class_name"]}">{ecosystem_badge["label"]}</span>
                        </div>
                        <button class="component-toggle" onclick="toggleComponent('{component_expand_id}')">
                            <span class="expand-arrow" id="arrow-{component_expand_id}">▶</span>
                            <span class="vuln-count">{len(vulns)} vulnerabilidade(s)</span>
                        </button>
                    </div>
                    <div class="vuln-card-body" id="{component_expand_id}">
                    <div class="component-section-label"><i class="bi bi-box-seam"></i> Componente analisado</div>
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
                            <div class="info-value path">{comp.get('declared_in', 'N/A')}</div>
                        </div>
                    </div>

                    <div class="vuln-section-label"><i class="bi bi-diagram-3"></i> Vulnerabilidades deste componente ({len(vulns)})</div>
                    <div class="vuln-list">'''
                
                for idx, vuln in enumerate(vulns):
                    vuln_id = vuln.get('id', 'UNKNOWN')
                    severity = vuln.get('severity', 'UNKNOWN').lower()
                    severity_icon = self._get_severity_icon(severity.upper())
                    severity_description = self._get_severity_description(severity.upper())
                    score = vuln.get('score', 0)
                    description = vuln.get('description', 'Sem descrição disponível')
                    cvss_tooltip = self._build_cvss_tooltip(vuln)
                    
                    # Converter Markdown para HTML
                    description_html = self._markdown_to_html(description)
                    
                    # Traduzir descrição
                    description_pt = self._translate_text(description)
                    description_pt_html = self._markdown_to_html(description_pt)
                    
                    # Extrair tipo de vulnerabilidade e explicação
                    vuln_type, vuln_explanation = self._get_vuln_type(description)
                    vuln_type_slug = re.sub(r"[^a-z0-9]+", "-", vuln_type.lower()).strip("-") or "security-issue"
                    
                    # Links externos
                    cve_id = self._extract_cve_id(vuln_id)
                    nvd_link = self._get_nvd_link(cve_id) if cve_id else ""
                    
                    # Versão corrigida
                    fixed_version = self._resolve_fixed_version(vuln) or 'Consulte o advisory'
                    
                    # ID único para expansão
                    expand_id = f"desc-{comp_name}-{idx}"
                    
                    html_content += f'''
                        <div class="vuln-item {severity}" data-vuln-type="{vuln_type_slug}" data-severity="{severity}">
                            <div class="vuln-header">
                                <div class="vuln-id">{vuln_id}</div>
                                <span class="severity-badge {severity}">{severity_icon} {severity.upper()}<span class="tooltip">{severity_description}</span></span>
                            </div>
                            
                            <div class="vuln-meta">
                                <span class="vuln-type">
                                    <i class="bi bi-tag"></i> {vuln_type}
                                    <span class="tooltip">{vuln_explanation}</span>
                                </span>
                                <span class="cvss-score"><i class="bi bi-speedometer2"></i> CVSS: {score}<span class="tooltip tooltip-cvss">{cvss_tooltip}</span></span>
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
            html_content += '''
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
                        fixed_version = self._resolve_fixed_version(vuln) or 'última versão disponível'
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
                        fixed_version = self._resolve_fixed_version(vuln) or 'última versão disponível'
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
                    <div class="title"><i class="bi bi-arrow-repeat"></i> Mantenha seus componentes atualizados</div>
                    <div class="content">
                        Execute análises periódicas para identificar novas vulnerabilidades e mantenha todos os componentes em suas versões mais recentes e seguras.
                    </div>
                </div>
                
                <div class="recommendation-card">
                    <div class="title"><i class="bi bi-shield-lock"></i> Implemente políticas de segurança</div>
                    <div class="content">
                        Estabeleça processos de revisão de segurança antes de adicionar novos componentes ao projeto e configure alertas automáticos para vulnerabilidades.
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
                    <div class="note">Continue monitorando regularmente seus componentes para manter a segurança.</div>
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

        const vulnState = {{
            typeFilter: 'all',
            severityFilter: 'all',
            searchText: '',
            sortOrder: 'severity-desc'
        }};

        function getSeveritySortValue(card) {{
            return Number(card.dataset.maxSeverityScore || 0);
        }}

        function getVulnCountSortValue(card) {{
            return Number(card.dataset.vulnCount || 0);
        }}

        function getVulnerabilityCards(container) {{
            if (!container) {{
                return [];
            }}
            return Array.from(container.children).filter(function(child) {{
                return child.classList && child.classList.contains('vuln-card');
            }});
        }}

        function getSortOrderLabel(sortOrder) {{
            const labels = {{
                'severity-desc': 'Severidade (maior primeiro)',
                'severity-asc': 'Severidade (menor primeiro)',
                'count-desc': 'Quantidade de vulnerabilidades (maior primeiro)',
                'count-asc': 'Quantidade de vulnerabilidades (menor primeiro)',
                'name-asc': 'Nome do componente (A-Z)',
                'name-desc': 'Nome do componente (Z-A)'
            }};
            return labels[sortOrder] || labels['severity-desc'];
        }}

        function updateCurrentSortLabel() {{
            const sortLabelEl = document.getElementById('vuln-current-sort');
            if (sortLabelEl) {{
                sortLabelEl.textContent = getSortOrderLabel(vulnState.sortOrder);
            }}
        }}

        function compareVulnCards(left, right, order) {{
            const leftName = (left.dataset.componentName || '').toLowerCase();
            const rightName = (right.dataset.componentName || '').toLowerCase();

            if (order === 'severity-asc') {{
                return getSeveritySortValue(left) - getSeveritySortValue(right) || leftName.localeCompare(rightName);
            }}
            if (order === 'count-desc') {{
                return getVulnCountSortValue(right) - getVulnCountSortValue(left) || leftName.localeCompare(rightName);
            }}
            if (order === 'count-asc') {{
                return getVulnCountSortValue(left) - getVulnCountSortValue(right) || leftName.localeCompare(rightName);
            }}
            if (order === 'name-asc') {{
                return leftName.localeCompare(rightName);
            }}
            if (order === 'name-desc') {{
                return rightName.localeCompare(leftName);
            }}

            return getSeveritySortValue(right) - getSeveritySortValue(left) || leftName.localeCompare(rightName);
        }}

        function sortVulnerabilityCards() {{
            const container = document.getElementById('vuln-cards-container');
            if (!container) {{
                return;
            }}

            const cards = getVulnerabilityCards(container);
            if (cards.length < 2) {{
                updateCurrentSortLabel();
                return;
            }}

            cards.sort(function(a, b) {{
                return compareVulnCards(a, b, vulnState.sortOrder);
            }});

            const fragment = document.createDocumentFragment();
            cards.forEach(function(card) {{
                fragment.appendChild(card);
            }});
            container.appendChild(fragment);
            updateCurrentSortLabel();
        }}

        function updateVulnSummary(visibleVulns, visibleComponents) {{
            const visibleCountEl = document.getElementById('vuln-visible-count');
            const visibleComponentsEl = document.getElementById('vuln-visible-components');
            if (visibleCountEl) {{
                visibleCountEl.textContent = String(visibleVulns);
            }}
            if (visibleComponentsEl) {{
                visibleComponentsEl.textContent = String(visibleComponents);
            }}
        }}

        function applyVulnerabilityFilters() {{
            const vulnItems = document.querySelectorAll('#vulnerabilities .vuln-item[data-vuln-type]');
            const search = (vulnState.searchText || '').toLowerCase();

            vulnItems.forEach(function(item) {{
                const matchesType = vulnState.typeFilter === 'all' || item.dataset.vulnType === vulnState.typeFilter;
                const matchesSeverity = vulnState.severityFilter === 'all' || item.dataset.severity === vulnState.severityFilter;
                const searchableText = item.textContent.toLowerCase();
                const matchesSearch = !search || searchableText.includes(search);
                const shouldShow = matchesType && matchesSeverity && matchesSearch;
                item.classList.toggle('vuln-item-hidden', !shouldShow);
            }});

            const vulnCards = document.querySelectorAll('#vulnerabilities .vuln-card');
            let visibleVulns = 0;
            let visibleComponents = 0;

            vulnCards.forEach(function(card) {{
                const visibleItems = card.querySelectorAll('.vuln-item:not(.vuln-item-hidden)');
                const hasVisibleItems = visibleItems.length > 0;
                card.classList.toggle('vuln-card-hidden', !hasVisibleItems);

                const countLabel = card.querySelector('.vuln-count');
                if (countLabel) {{
                    const countText = hasVisibleItems ? visibleItems.length : 0;
                    countLabel.textContent = `${{countText}} vulnerabilidade(s)`;
                }}

                if (hasVisibleItems) {{
                    visibleComponents += 1;
                    visibleVulns += visibleItems.length;
                }}
            }});

            updateVulnSummary(visibleVulns, visibleComponents);
        }}

        function initVulnTypeFilters() {{
            const filterButtons = document.querySelectorAll('#vuln-type-filters .vuln-type-filter');
            filterButtons.forEach(function(button) {{
                button.addEventListener('click', function() {{
                    const filterType = button.dataset.vulnTypeFilter || 'all';
                    vulnState.typeFilter = filterType;

                    filterButtons.forEach(function(btn) {{
                        btn.classList.toggle('active', btn === button);
                    }});

                    applyVulnerabilityFilters();
                }});
            }});

            const severityFilterSelect = document.getElementById('vuln-severity-filter');
            if (severityFilterSelect) {{
                severityFilterSelect.addEventListener('change', function() {{
                    vulnState.severityFilter = severityFilterSelect.value || 'all';
                    applyVulnerabilityFilters();
                }});
            }}

            const searchInput = document.getElementById('vuln-search-input');
            if (searchInput) {{
                searchInput.addEventListener('input', function() {{
                    vulnState.searchText = searchInput.value || '';
                    applyVulnerabilityFilters();
                }});
            }}

            const sortSelect = document.getElementById('vuln-sort-select');
            if (sortSelect) {{
                sortSelect.value = vulnState.sortOrder;
                sortSelect.addEventListener('change', function() {{
                    vulnState.sortOrder = sortSelect.value || 'severity-desc';
                    sortVulnerabilityCards();
                    applyVulnerabilityFilters();
                }});
            }}

            sortVulnerabilityCards();
            applyVulnerabilityFilters();
        }}

        initVulnTypeFilters();
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
        
        if not progress_callback:
            self.console.print(f"[dim]💾 Salvando relatório em: {output_file}[/dim]")
        
        if output_file.exists():
            if not progress_callback:
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
                if not progress_callback:
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

    def update_saved_report_duration(self, output_path: str, duration_seconds: float) -> None:
        """Atualiza o tempo de execução no HTML já salvo em disco."""
        report_file = pathlib.Path(output_path)
        if not report_file.exists():
            return

        formatted_duration = self._format_duration_label(duration_seconds)
        content = report_file.read_text(encoding="utf-8")

        updated_content = re.sub(
            r'(<div class="label"><i class="bi bi-stopwatch"></i> Tempo de Execução</div>\s*<div class="value">)([^<]*)(</div>)',
            rf'\g<1>{formatted_duration}\g<3>',
            content,
            count=1,
        )
        updated_content = re.sub(
            r'(<div class="number">)([^<]*)(</div>\s*<div class="label">Tempo de Execução</div>)',
            rf'\g<1>{formatted_duration}\g<3>',
            updated_content,
            count=1,
        )

        if updated_content != content:
            report_file.write_text(updated_content, encoding="utf-8")
    
    def display_scan_results(self, dependencies: List[Dict], ecosystems: Dict, output_file: str, vulnerabilities: Optional[Dict[str, List[Dict]]] = None) -> None:
        """
        Exibe os resultados da varredura no console.
        
        Args:
            dependencies: Lista de dependências encontradas
            ecosystems: Estatísticas por ecossistema
            output_file: Arquivo onde o relatório foi salvo
            vulnerabilities: Dicionário com vulnerabilidades encontradas
        """
        grouped_dependencies = self._build_grouped_dependencies(dependencies)
        grouped_ecosystems: Dict[str, int] = {}
        for dependency in grouped_dependencies:
            ecosystem = self._normalize_ecosystem_badge_token(dependency.get("ecosystem", "unknown"))
            grouped_ecosystems[ecosystem] = grouped_ecosystems.get(ecosystem, 0) + 1

        self.console.print("[bold green]✅ Varredura concluída com sucesso![/bold green]")
        self.console.print(f"[cyan]📊 Estatísticas:[/cyan]")
        self.console.print(f"   • [bold]{len(grouped_dependencies)}[/bold] dependências encontradas")

        if len(grouped_dependencies) != len(dependencies):
            self.console.print(
                f"   • [dim]{len(dependencies)} ocorrência(s) bruta(s) no parse; consolidado por componente para refletir a aba Dependências[/dim]"
            )
        
        for eco, count in grouped_ecosystems.items():
            emoji = ECOSYSTEM_EMOJIS.get(eco, "❓")
            ecosystem_badge = self._get_ecosystem_badge_info(eco)
            ecosystem_label = ecosystem_badge["label"]
            self.console.print(f"   • {emoji} [bold]{count}[/bold] dependência(s) do ecossistema [italic]{ecosystem_label}[/italic]")
        
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
