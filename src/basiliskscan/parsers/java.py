"""Parser para dependências Java (Maven e Gradle)."""

import pathlib
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from .base import BaseParser
from .purl import build_purl


class JavaParser(BaseParser):
    """Parser para arquivos pom.xml (Maven) e build.gradle (Gradle)."""

    GRADLE_CONFIGURATIONS = {
        "annotationProcessor",
        "api",
        "compile",
        "compileOnly",
        "implementation",
        "kapt",
        "providedCompile",
        "providedRuntime",
        "runtimeOnly",
        "testAnnotationProcessor",
        "testCompile",
        "testCompileOnly",
        "testImplementation",
        "testRuntimeOnly",
    }

    GRADLE_STRING_DEPENDENCY_RE = re.compile(
        r"^\s*(?P<scope>[A-Za-z_][\w.-]*)\s*(?:\(\s*)?[\"'](?P<group>[^:\"']+):(?P<artifact>[^:\"']+)(?::(?P<version>[^\"']+))?[\"']",
    )

    GRADLE_MAP_DEPENDENCY_RE = re.compile(
        r"^\s*(?P<scope>[A-Za-z_][\w.-]*)\s*(?:\(\s*)?(?=.*\bgroup\s*[:=]\s*[\"'](?P<group>[^\"']+)[\"'])(?=.*\bname\s*[:=]\s*[\"'](?P<artifact>[^\"']+)[\"'])(?:(?=.*\bversion\s*[:=]\s*[\"'](?P<version>[^\"']+)[\"']))?.*",
    )

    ANT_PROPERTY_TOKEN_RE = re.compile(r"\$\{([^}]+)\}")
    ANT_JAR_PATH_RE = re.compile(
        r"(?:location|file|path|classpath|classpathref|destfile)\s*=\s*[\"'](?P<value>[^\"']+?\.jar)[\"']",
        re.IGNORECASE,
    )
    
    def get_supported_files(self) -> List[str]:
        """Retorna lista de arquivos suportados."""
        return ["pom.xml", "build.gradle", "build.gradle.kts", "build.xml", "gradle.lockfile"]
    
    def parse(self, path: pathlib.Path) -> List[Dict]:
        """
        Extrai dependências de arquivos Java.
        
        Args:
            path: Caminho para o arquivo de dependências
            
        Returns:
            Lista de dicionários com informações das dependências
        """
        if path.name == "pom.xml":
            return self._parse_maven(path)
        elif path.name in ["build.gradle", "build.gradle.kts"]:
            return self._parse_gradle(path)
        elif path.name == "build.xml":
            return self._parse_ant(path)
        elif path.name == "gradle.lockfile":
            return self._parse_gradle_lockfile(path)
        else:
            raise ValueError(f"Arquivo não suportado: {path.name}")
    
    def _parse_maven(self, path: pathlib.Path) -> List[Dict]:
        """
        Extrai dependências de um arquivo pom.xml (Maven).
        
        Args:
            path: Caminho para o arquivo pom.xml
            
        Returns:
            Lista de dicionários com informações das dependências
        """
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except ET.ParseError as e:
            raise ET.ParseError(f"Erro ao fazer parse do XML em {path}: {e}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Arquivo pom.xml não encontrado: {path}")
        
        deps = []

        for dependency in root.iter():
            if self._local_name(dependency.tag) != "dependency":
                continue

            group_id = self._find_child_text(dependency, "groupId")
            artifact_id = self._find_child_text(dependency, "artifactId")
            version_spec = self._find_child_text(dependency, "version")
            scope = self._find_child_text(dependency, "scope") or "compile"

            if group_id and artifact_id:
                deps.append({
                    "ecosystem": "maven",
                    "name": f"{group_id}:{artifact_id}",
                    "version_spec": version_spec,
                    "declared_in": str(path),
                    "scope": scope,
                    "dependency_type": "direct",
                    "is_transitive": False,
                    "purl": build_purl("maven", f"{group_id}:{artifact_id}", version_spec),
                })
        
        return deps

    def _local_name(self, tag: str) -> str:
        """Extrai o nome local de uma tag XML, com ou sem namespace."""
        return tag.split("}", 1)[1] if "}" in tag else tag

    def _find_child_text(self, element: ET.Element, child_name: str) -> Optional[str]:
        """Busca texto de um filho direto, ignorando namespaces XML."""
        for child in list(element):
            if self._local_name(child.tag) == child_name and child.text:
                return child.text.strip()
        return None
    
    def _parse_gradle(self, path: pathlib.Path) -> List[Dict]:
        """
        Extrai dependências de um arquivo build.gradle ou build.gradle.kts.
        
        Args:
            path: Caminho para o arquivo Gradle
            
        Returns:
            Lista de dicionários com informações das dependências
        """
        try:
            content = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise FileNotFoundError(f"Arquivo Gradle não encontrado: {path}")
        except UnicodeDecodeError as e:
            raise UnicodeDecodeError(
                e.encoding,
                e.object,
                e.start,
                e.end,
                f"Erro de encoding ao ler {path}: {e.reason}"
            )
        
        deps = []
        brace_depth = 0
        dependencies_depth = None
        waiting_for_dependencies_brace = False

        for line_num, raw_line in enumerate(content.splitlines(), 1):
            line = self._strip_gradle_comments(raw_line).strip()

            if not line:
                brace_depth += raw_line.count("{") - raw_line.count("}")
                continue

            if dependencies_depth is None:
                if re.match(r"^\s*dependencies\b", line):
                    if "{" in line:
                        dependencies_depth = brace_depth + 1
                    else:
                        waiting_for_dependencies_brace = True
                elif waiting_for_dependencies_brace and "{" in line:
                    dependencies_depth = brace_depth + 1
                    waiting_for_dependencies_brace = False
            else:
                dependency = self._parse_gradle_dependency_line(line, path, line_num)
                if dependency is not None:
                    deps.append(dependency)

            brace_depth += raw_line.count("{") - raw_line.count("}")

            if dependencies_depth is not None and brace_depth < dependencies_depth:
                dependencies_depth = None

        return deps

    def _strip_gradle_comments(self, line: str) -> str:
        """Remove comentários simples de linha preservando strings."""
        result = []
        quote_char = None
        escaped = False

        for index, char in enumerate(line):
            if escaped:
                result.append(char)
                escaped = False
                continue

            if char == "\\":
                result.append(char)
                escaped = True
                continue

            if quote_char:
                result.append(char)
                if char == quote_char:
                    quote_char = None
                continue

            if char in {"'", '"'}:
                result.append(char)
                quote_char = char
                continue

            if char == "/" and index + 1 < len(line) and line[index + 1] == "/":
                break

            result.append(char)

        return "".join(result)

    def _parse_gradle_dependency_line(self, line: str, path: pathlib.Path, line_num: int) -> Optional[Dict]:
        """Converte uma linha de dependência Gradle em dicionário estruturado."""
        match = self.GRADLE_STRING_DEPENDENCY_RE.match(line)
        if match is None:
            match = self.GRADLE_MAP_DEPENDENCY_RE.match(line)

        if match is None:
            return None

        scope = match.group("scope")
        if scope not in self.GRADLE_CONFIGURATIONS:
            return None

        group_id = match.group("group")
        artifact_id = match.group("artifact")
        version_spec = match.groupdict().get("version")

        if not group_id or not artifact_id:
            return None

        return {
            "ecosystem": "gradle",
            "name": f"{group_id}:{artifact_id}",
            "version_spec": version_spec,
            "declared_in": str(path),
            "line_number": line_num,
            "scope": scope,
            "dependency_type": "direct",
            "is_transitive": False,
            "purl": build_purl("gradle", f"{group_id}:{artifact_id}", version_spec),
        }

    def _parse_gradle_lockfile(self, path: pathlib.Path) -> List[Dict]:
        """Extrai dependências bloqueadas de `gradle.lockfile` (normalmente inclui transitivas)."""
        try:
            content = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise FileNotFoundError(f"Arquivo gradle.lockfile não encontrado: {path}")
        except UnicodeDecodeError as e:
            raise UnicodeDecodeError(
                e.encoding,
                e.object,
                e.start,
                e.end,
                f"Erro de encoding ao ler {path}: {e.reason}",
            )

        deps: List[Dict] = []
        seen = set()

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            dependency_part, _, scope_part = line.partition("=")
            coordinates = dependency_part.strip()
            segments = coordinates.split(":")
            if len(segments) < 3:
                continue

            group_id = segments[0].strip()
            artifact_id = segments[1].strip()
            version_spec = ":".join(segments[2:]).strip()

            if not group_id or not artifact_id or not version_spec:
                continue

            scope = scope_part.split(",", 1)[0].strip() if scope_part else "locked"
            key = (group_id, artifact_id, version_spec, scope)
            if key in seen:
                continue
            seen.add(key)

            name = f"{group_id}:{artifact_id}"
            deps.append({
                "ecosystem": "gradle",
                "name": name,
                "version_spec": version_spec,
                "declared_in": str(path),
                "scope": scope,
                "section": "lockfile",
                "dependency_type": "transitive",
                "is_transitive": True,
                "purl": build_purl("gradle", name, version_spec),
            })

        return deps

    def _parse_ant(self, path: pathlib.Path) -> List[Dict]:
        """Extrai dependências declaradas em projetos Ant/NetBeans."""
        properties_path = path.parent / "nbproject" / "project.properties"
        deps = []
        seen_keys = set()

        if properties_path.exists():
            properties = self._read_properties_file(properties_path)

            for key, value in properties.items():
                if not key.startswith("file.reference."):
                    continue

                normalized_value = value.replace("\\", "/")
                if not normalized_value.lower().endswith(".jar"):
                    continue

                dependency = self._build_ant_dependency(path, key, value)
                if dependency is not None:
                    deps.append(dependency)
                    seen_keys.add((dependency["name"], dependency.get("version_spec"), dependency["dependency_type"]))

            classpath_properties = {
                key: value
                for key, value in properties.items()
                if key.endswith(".classpath")
            }

            for classpath_property, classpath_value in classpath_properties.items():
                for token in self.ANT_PROPERTY_TOKEN_RE.findall(classpath_value):
                    dependency = self._build_ant_classpath_dependency(path, token, classpath_property)
                    if dependency is None:
                        continue

                    unique_key = (
                        dependency["name"],
                        dependency.get("version_spec"),
                        dependency["dependency_type"],
                    )
                    if unique_key in seen_keys:
                        continue

                    seen_keys.add(unique_key)
                    deps.append(dependency)

        if not deps:
            deps.extend(self._discover_ant_local_jar_dependencies(path, seen_keys))

        return deps

    def _discover_ant_local_jar_dependencies(self, build_file: pathlib.Path, seen_keys: set[tuple[str, Optional[str], str]]) -> List[Dict]:
        """Tenta descobrir JARs locais em projetos Ant sem metadata NetBeans."""
        project_root = build_file.parent
        discovered: List[Dict] = []

        for jar_path in self._find_ant_jar_candidates(build_file, project_root):
            dependency = self._build_ant_dependency(build_file, f"file.reference.{jar_path.stem}", str(jar_path))
            if dependency is None:
                continue

            unique_key = (
                dependency["name"],
                dependency.get("version_spec"),
                dependency["dependency_type"],
            )
            if unique_key in seen_keys:
                continue

            seen_keys.add(unique_key)
            discovered.append(dependency)

        return discovered

    def _find_ant_jar_candidates(self, build_file: pathlib.Path, project_root: pathlib.Path) -> List[pathlib.Path]:
        """Encontra JARs prováveis de dependências em um projeto Ant."""
        candidates: List[pathlib.Path] = []
        seen: set[pathlib.Path] = set()

        try:
            build_text = build_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            build_text = ""

        for match in self.ANT_JAR_PATH_RE.finditer(build_text):
            raw_value = match.group("value").replace("\\", "/").strip()
            if not raw_value:
                continue

            jar_path = (project_root / raw_value).resolve()
            if jar_path.exists() and jar_path.suffix.lower() == ".jar" and jar_path not in seen:
                seen.add(jar_path)
                candidates.append(jar_path)

        library_dir_names = {"lib", "libs", "library", "libraries", "external", "externals", "vendor", "vendors", "thirdparty", "dependencies"}

        for directory in project_root.rglob("*"):
            if not directory.is_dir():
                continue

            if directory.name.lower() not in library_dir_names:
                continue

            for jar_path in directory.rglob("*.jar"):
                if jar_path in seen:
                    continue
                if any(part.lower() in {"build", "target", "out", "dist"} for part in jar_path.parts):
                    continue
                seen.add(jar_path)
                candidates.append(jar_path)

        return candidates

    def _read_properties_file(self, path: pathlib.Path) -> Dict[str, str]:
        """Lê arquivo `.properties` preservando continuações de linha."""
        content = path.read_text(encoding="utf-8", errors="ignore")
        logical_lines: List[str] = []
        current_line = ""

        for raw_line in content.splitlines():
            stripped_right = raw_line.rstrip()
            if stripped_right.endswith("\\") and not stripped_right.endswith("\\\\"):
                current_line += stripped_right[:-1]
                continue

            current_line += stripped_right
            logical_lines.append(current_line)
            current_line = ""

        if current_line:
            logical_lines.append(current_line)

        properties: Dict[str, str] = {}
        for line in logical_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("!"):
                continue

            separator_index = -1
            for candidate in ("=", ":"):
                index = line.find(candidate)
                if index != -1 and (separator_index == -1 or index < separator_index):
                    separator_index = index

            if separator_index == -1:
                key = stripped
                value = ""
            else:
                key = line[:separator_index].strip()
                value = line[separator_index + 1 :].strip()

            properties[key] = value

        return properties

    def _build_ant_dependency(self, build_file: pathlib.Path, property_name: str, property_value: str) -> Optional[Dict]:
        """Transforma referência de JAR do NetBeans em dependência estruturada."""
        jar_path = pathlib.Path(property_value.replace("\\", "/"))
        jar_name = jar_path.name
        stem = jar_name[:-4] if jar_name.lower().endswith(".jar") else jar_name

        artifact, version_spec = self._split_ant_name_and_version(stem)

        return {
            "ecosystem": "ant",
            "name": artifact,
            "version_spec": version_spec,
            "declared_in": str(build_file),
            "scope": "compile",
            "file_reference": property_name,
            "source_path": str((build_file.parent / jar_path).resolve()),
            "dependency_type": "direct",
            "is_transitive": False,
            "purl": build_purl("ant", artifact, version_spec),
        }

    def _build_ant_classpath_dependency(
        self,
        build_file: pathlib.Path,
        token: str,
        classpath_property: str,
    ) -> Optional[Dict]:
        """Converte token de classpath em dependência, marcando libs.* como transitiva."""
        if token.startswith("file.reference."):
            return None

        if not (token.startswith("libs.") and token.endswith(".classpath")):
            return None

        library_name = token[len("libs.") : -len(".classpath")]
        if not library_name:
            return None

        normalized_library_name = library_name.replace("_", "-")
        artifact, version_spec = self._split_ant_name_and_version(normalized_library_name)
        dependency_type = "transitive"
        is_transitive = True

        return {
            "ecosystem": "ant",
            "name": artifact,
            "version_spec": version_spec,
            "declared_in": str(build_file),
            "scope": "compile",
            "source_property": classpath_property,
            "file_reference": token,
            "dependency_type": dependency_type,
            "is_transitive": is_transitive,
            "purl": build_purl("ant", artifact, version_spec),
        }

    def _split_ant_name_and_version(self, value: str) -> tuple[str, Optional[str]]:
        """Extrai artefato e versão de identificadores comuns de dependências Ant."""
        normalized = value.strip()
        match = re.match(r"^(?P<artifact>.+?)[-_](?P<version>\d[\w.+-]*)$", normalized)
        if match:
            return match.group("artifact"), match.group("version")

        return normalized, None