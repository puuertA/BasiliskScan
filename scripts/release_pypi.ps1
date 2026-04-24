param(
    [Parameter(Position = 0)]
    [ValidateSet("patch", "minor", "major")]
    [string]$Bump = "patch",

    [Parameter()]
    [switch]$SkipUpload,

    [Parameter()]
    [switch]$SkipBump,

    [Parameter()]
    [string]$PythonCmd = "python"
)

$ErrorActionPreference = "Stop"

function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $false)]
        [string[]]$Arguments = @(),

        [Parameter(Mandatory = $true)]
        [string]$ErrorMessage
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$ErrorMessage (exit code: $LASTEXITCODE)"
    }
}

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $ProjectRoot

if ($SkipBump) {
    Write-Host "[1/4] Version bump skipped (-SkipBump)." -ForegroundColor Yellow
} else {
    Write-Host "[1/4] Bumping version ($Bump)..." -ForegroundColor Cyan
    Invoke-ExternalCommand -Command $PythonCmd -Arguments @("scripts/bump_version.py", $Bump) -ErrorMessage "Falha no bump de versão"
}

Write-Host "[2/4] Cleaning dist/..." -ForegroundColor Cyan
if (Test-Path "dist") {
    Remove-Item -Recurse -Force "dist"
}

Write-Host "[3/4] Building package..." -ForegroundColor Cyan
Invoke-ExternalCommand -Command $PythonCmd -Arguments @("-m", "build") -ErrorMessage "Falha ao gerar os artefatos do pacote"

if ($SkipUpload) {
    Write-Host "[4/4] Upload skipped (-SkipUpload)." -ForegroundColor Yellow
    exit 0
}

Write-Host "[4/4] Uploading to PyPI..." -ForegroundColor Cyan
if (-not $env:TWINE_USERNAME) {
    if ($env:TWINE_PASSWORD) {
        $env:TWINE_USERNAME = "__token__"
    } else {
        throw "TWINE_USERNAME/TWINE_PASSWORD não definidos. Defina as variáveis e tente novamente."
    }
}

if (-not $env:TWINE_PASSWORD) {
    throw "TWINE_PASSWORD não definido. Exemplo: `$env:TWINE_PASSWORD='pypi-...'."
}

if ($env:TWINE_PASSWORD -like "pypi-*") {
    if ($env:TWINE_USERNAME -ne "__token__") {
        Write-Host "Ajustando TWINE_USERNAME para __token__ (detected PyPI token)." -ForegroundColor Yellow
        $env:TWINE_USERNAME = "__token__"
    }
}

try {
    Invoke-ExternalCommand -Command $PythonCmd -Arguments @("-m", "twine", "upload", "--non-interactive", "dist/*") -ErrorMessage "Falha no upload para o PyPI"
} catch {
    Write-Host "Upload falhou. Dica: execute com --verbose para detalhes completos:" -ForegroundColor Yellow
    Write-Host "  $PythonCmd -m twine upload --verbose --non-interactive dist/*" -ForegroundColor Yellow
    throw
}

Write-Host "Release finalizada com sucesso." -ForegroundColor Green
