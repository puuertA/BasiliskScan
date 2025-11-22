"""Parser base para dependências."""

import pathlib
from abc import ABC, abstractmethod
from typing import Dict, List


class BaseParser(ABC):
    """Classe abstrata base para parsers de dependências."""
    
    @abstractmethod
    def parse(self, path: pathlib.Path) -> List[Dict]:
        """
        Extrai dependências de um arquivo.
        
        Args:
            path: Caminho para o arquivo de dependências
            
        Returns:
            Lista de dicionários com informações das dependências
        """
        pass
    
    @abstractmethod
    def get_supported_files(self) -> List[str]:
        """
        Retorna lista de arquivos suportados pelo parser.
        
        Returns:
            Lista de nomes de arquivos suportados
        """
        pass