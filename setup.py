"""Setup com hook para popular banco seed antes do build."""

import sys
from pathlib import Path
from setuptools import setup

# Executa script de seed se não existir ou estiver vazio
def ensure_seed_db():
    """Popula banco seed se estiver vazio ou inexistente."""
    seed_path = Path(__file__).resolve().parent / "resources" / "offline" / "offline_vulnerabilities.db"
    
    # Verificar tamanho mínimo (DB populado deve ter > 100KB)
    if seed_path.exists() and seed_path.stat().st_size > 100000:
        print(f"✓ Seed DB já existe e tem tamanho adequado: {seed_path.stat().st_size / 1024:.1f}KB")
        return
    
    print("📦 Gerando banco seed com vulnerabilidades de libs populares...")
    
    try:
        # Importar e rodar o script de seed
        sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
        from populate_offline_seed import main
        main()
        print("✓ Seed DB gerado com sucesso!")
    except Exception as e:
        print(f"⚠️  Erro ao gerar seed DB: {e}")
        print("   Continuando sem seed DB (será criado no primeiro uso)")


# Garantir que seed existe antes de build
ensure_seed_db()

# Executar setup padrão
setup()
