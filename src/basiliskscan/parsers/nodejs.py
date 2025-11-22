"""Parser para dependências Node.js (npm/yarn) - inclui Ionic."""

import json
import pathlib
from typing import Dict, List

from .base import BaseParser


# Seções de dependências do package.json
NPM_DEPENDENCY_SECTIONS = [
    "dependencies",
    "devDependencies", 
    "peerDependencies",
    "optionalDependencies"
]


class NodeJSParser(BaseParser):
    """Parser para arquivos package.json (Node.js, Ionic, React, etc.)."""
    
    def get_supported_files(self) -> List[str]:
        """Retorna lista de arquivos suportados."""
        return ["package.json"]
    
    def parse(self, path: pathlib.Path) -> List[Dict]:
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
            raise json.JSONDecodeError(
                f"Erro ao fazer parse do JSON em {path}: {e}",
                e.doc,
                e.pos
            )
        except FileNotFoundError:
            raise FileNotFoundError(f"Arquivo package.json não encontrado: {path}")
        
        deps = []
        
        # Detecta se é um projeto Ionic
        is_ionic = self._is_ionic_project(data)
        ecosystem = "ionic" if is_ionic else "npm"
        
        for section in NPM_DEPENDENCY_SECTIONS:
            items = data.get(section, {}) or {}
            for name, version_spec in items.items():
                deps.append({
                    "ecosystem": ecosystem,
                    "name": name,
                    "version_spec": version_spec,
                    "declared_in": str(path),
                    "section": section
                })
        
        return deps
    
    def _is_ionic_project(self, package_data: Dict) -> bool:
        """
        Verifica se o projeto é baseado em Ionic.
        
        Args:
            package_data: Dados do package.json
            
        Returns:
            True se for projeto Ionic, False caso contrário
        """
        # Verifica dependências do Ionic
        all_deps = {}
        for section in NPM_DEPENDENCY_SECTIONS:
            all_deps.update(package_data.get(section, {}))
        
        ionic_indicators = [
            "@ionic/angular",
            "@ionic/react", 
            "@ionic/vue",
            "ionic-angular",
            "@ionic/core"
        ]
        
        return any(indicator in all_deps for indicator in ionic_indicators)