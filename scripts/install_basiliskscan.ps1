param(
    [switch]$Editable
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot

Write-Host "Instalando BasiliskScan..."

if ($Editable) {
    py -m pip install -e $repoRoot
} else {
    py -m pip install $repoRoot
}

if ($LASTEXITCODE -ne 0) {
    throw "Falha ao instalar BasiliskScan via pip."
}

Write-Host "Configurando PATH e launcher do bscan..."
& (Join-Path $PSScriptRoot "add_bscan_path.ps1")

Write-Host "Pronto. Feche e reabra o terminal se quiser usar o comando em novas sessões."