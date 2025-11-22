"""Parsers para diferentes tipos de arquivos de dependências."""

import pathlib
from typing import Dict, List

from .base import BaseParser
from .nodejs import NodeJSParser
from .java import JavaParser


# Instâncias dos parsers
_PARSERS = [
    NodeJSParser(),
    JavaParser()
]

# Mapeia arquivos para parsers
_FILE_TO_PARSER = {}
for parser in _PARSERS:
    for filename in parser.get_supported_files():
        _FILE_TO_PARSER[filename] = parser


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
    parser = _FILE_TO_PARSER.get(filename)
    
    if parser is None:
        supported = list(_FILE_TO_PARSER.keys())
        raise ValueError(
            f"Tipo de arquivo não suportado: {filename}. "
            f"Arquivos suportados: {', '.join(supported)}"
        )
    
    return parser.parse


def get_all_supported_files() -> List[str]:
    """
    Retorna lista de todos os arquivos suportados.
    
    Returns:
        Lista com nomes de todos os arquivos suportados
    """
    return list(_FILE_TO_PARSER.keys())


__all__ = [
    "BaseParser",
    "NodeJSParser",
    "JavaParser",
    "get_parser_for_file",
    "get_all_supported_files"
]