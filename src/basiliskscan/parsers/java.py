"""Parser para dependências Java (Maven e Gradle)."""

import pathlib
import xml.etree.ElementTree as ET
from typing import Dict, List

from .base import BaseParser


class JavaParser(BaseParser):
    """Parser para arquivos pom.xml (Maven) e build.gradle (Gradle)."""
    
    def get_supported_files(self) -> List[str]:
        """Retorna lista de arquivos suportados."""
        return ["pom.xml", "build.gradle", "build.gradle.kts"]
    
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
        
        # Define o namespace do Maven
        ns = {"mvn": "http://maven.apache.org/POM/4.0.0"}
        
        deps = []
        
        # Extrai dependências
        for dependency in root.findall(".//mvn:dependency", ns):
            group_id = dependency.find("mvn:groupId", ns)
            artifact_id = dependency.find("mvn:artifactId", ns)
            version = dependency.find("mvn:version", ns)
            scope = dependency.find("mvn:scope", ns)
            
            if group_id is not None and artifact_id is not None:
                name = f"{group_id.text}:{artifact_id.text}"
                version_spec = version.text if version is not None else None
                
                deps.append({
                    "ecosystem": "maven",
                    "name": name,
                    "version_spec": version_spec,
                    "declared_in": str(path),
                    "scope": scope.text if scope is not None else "compile"
                })
        
        return deps
    
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
        in_dependencies_block = False
        
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            
            # Detecta bloco de dependências
            if "dependencies" in line and "{" in line:
                in_dependencies_block = True
                continue
            
            if in_dependencies_block:
                # Fim do bloco de dependências
                if line == "}":
                    in_dependencies_block = False
                    continue
                
                # Parse de dependências no formato: implementation 'group:name:version'
                # Suporta: implementation, api, compile, testImplementation, etc.
                if any(keyword in line for keyword in [
                    "implementation", "api", "compile", 
                    "testImplementation", "testCompile",
                    "runtimeOnly", "compileOnly"
                ]):
                    # Remove comentários
                    if "//" in line:
                        line = line.split("//")[0].strip()
                    
                    # Extrai a string da dependência
                    if "'" in line or '"' in line:
                        quote = "'" if "'" in line else '"'
                        parts = line.split(quote)
                        if len(parts) >= 2:
                            dep_string = parts[1]
                            
                            # Parse do formato group:artifact:version
                            dep_parts = dep_string.split(":")
                            if len(dep_parts) >= 2:
                                name = f"{dep_parts[0]}:{dep_parts[1]}"
                                version_spec = dep_parts[2] if len(dep_parts) >= 3 else None
                                
                                # Extrai o scope/configuration
                                scope = line.split("(")[0].strip() if "(" in line else "implementation"
                                
                                deps.append({
                                    "ecosystem": "gradle",
                                    "name": name,
                                    "version_spec": version_spec,
                                    "declared_in": str(path),
                                    "line_number": line_num,
                                    "scope": scope
                                })
        
        return deps