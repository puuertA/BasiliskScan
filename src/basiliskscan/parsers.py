# src/basiliskscan/parsers.py
"""Parsers para diferentes tipos de arquivos de dependências."""

import json
import pathlib
from typing import Dict, List

from .config import NPM_DEPENDENCY_SECTIONS


class DependencyParser:
    """Classe base para parsers de dependências."""
    
    @staticmethod
    def parse_package_json(path: pathlib.Path) -> List[Dict]:
        """
        Extrai dependências de um arquivo package.json.
        
        Args:
            path: Caminho para o arquivo package.json
            
        Returns:
            Lista de dicionários com informações das dependências
            
        Raises:
            json.JSONDecodeError: Se o arquivo não for um JSON válido
            FileNotFoundError: Se o arquivo não existir
        """
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(f"Erro ao fazer parse do JSON em {path}: {e}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Arquivo package.json não encontrado: {path}")
        
        deps = []
        for section in NPM_DEPENDENCY_SECTIONS:
            items = data.get(section, {}) or {}
            for name, version_spec in items.items():
                deps.append({
                    "ecosystem": "npm",
                    "name": name,
                    "version_spec": version_spec,
                    "declared_in": str(path),
                    "section": section
                })
        
        return deps
    
    @staticmethod 
    def parse_requirements_txt(path: pathlib.Path) -> List[Dict]:
        """
        Extrai dependências de um arquivo requirements.txt.
        
        Args:
            path: Caminho para o arquivo requirements.txt
            
        Returns:
            Lista de dicionários com informações das dependências
            
        Raises:
            FileNotFoundError: Se o arquivo não existir
        """
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise FileNotFoundError(f"Arquivo requirements.txt não encontrado: {path}")
        except UnicodeDecodeError as e:
            raise UnicodeDecodeError(f"Erro de encoding ao ler {path}: {e}")
        
        deps = []
        for line_num, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            
            # Ignora linhas vazias e comentários
            if not line or line.startswith("#"):
                continue
                
            # Ignora options como -r, -e, -f, etc.
            if line.startswith("-"):
                continue
            
            # Parse de dependências com versão fixa (==)
            if "==" in line:
                name, version = line.split("==", 1)
                deps.append({
                    "ecosystem": "pypi",
                    "name": name.strip(),
                    "version_spec": version.strip(),
                    "declared_in": str(path),
                    "line_number": line_num
                })
            # Parse de dependências com outros operadores de versão
            elif any(op in line for op in [">=", "<=", ">", "<", "~=", "!="]):
                # Extrai o nome da dependência (parte antes do operador)
                for op in [">=", "<=", "~=", "!=", ">", "<"]:
                    if op in line:
                        name, version = line.split(op, 1)
                        deps.append({
                            "ecosystem": "pypi",
                            "name": name.strip(),
                            "version_spec": f"{op}{version.strip()}",
                            "declared_in": str(path),
                            "line_number": line_num
                        })
                        break
            else:
                # Dependência sem versão especificada
                deps.append({
                    "ecosystem": "pypi",
                    "name": line.strip(),
                    "version_spec": None,
                    "declared_in": str(path),
                    "line_number": line_num
                })
        
        return deps


def get_parser_for_file(filename: str) -> callable:
    """
    Retorna o parser apropriado para o tipo de arquivo.
    
    Args:
        filename: Nome do arquivo
        
    Returns:
        Função parser apropriada
        
    Raises:
        ValueError: Se o tipo de arquivo não for suportado
    """
    parsers = {
        "package.json": DependencyParser.parse_package_json,
        "requirements.txt": DependencyParser.parse_requirements_txt
    }
    
    if filename not in parsers:
        raise ValueError(f"Tipo de arquivo não suportado: {filename}")
    
    return parsers[filename]