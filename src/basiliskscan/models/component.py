"""
Modelo de componente de software.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class Component:
    """
    Modelo interno de componente representando uma dependência de software.
    
    Atributos:
        nome: Nome do componente
        versao: Versão do componente
        ecossistema: Ecossistema do pacote (ex: 'npm', 'maven', 'pypi')
        purl: Identificador Package URL (PURL)
        cpe: Identificador Common Platform Enumeration
        caminho: Caminho do componente no projeto
    """
    nome: str
    versao: str
    ecossistema: str
    caminho: str
    purl: Optional[str] = None
    cpe: Optional[str] = None
    
    def __post_init__(self):
        """Valida os dados do componente após inicialização."""
        if not self.nome:
            raise ValueError("O nome do componente não pode estar vazio")
        if not self.versao:
            raise ValueError("A versão do componente não pode estar vazia")
        if not self.ecossistema:
            raise ValueError("O ecossistema do componente não pode estar vazio")
        if not self.caminho:
            raise ValueError("O caminho do componente não pode estar vazio")
    
    def para_dicionario(self) -> dict:
        """
        Converte o componente para representação em dicionário.
        
        Retorna:
            Dicionário com os dados do componente
        """
        return {
            "nome": self.nome,
            "versao": self.versao,
            "ecossistema": self.ecossistema,
            "purl": self.purl,
            "cpe": self.cpe,
            "caminho": self.caminho
        }
    
    def __str__(self) -> str:
        """Representação em string do componente."""
        return f"{self.nome}@{self.versao} ({self.ecossistema})"
    
    def __repr__(self) -> str:
        """Representação detalhada do componente."""
        return (
            f"Component(nome='{self.nome}', versao='{self.versao}', "
            f"ecossistema='{self.ecossistema}', caminho='{self.caminho}', "
            f"purl={self.purl!r}, cpe={self.cpe!r})"
        )
