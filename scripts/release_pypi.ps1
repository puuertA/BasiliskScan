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

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $ProjectRoot

if ($SkipBump) {
    Write-Host "[1/4] Version bump skipped (-SkipBump)." -ForegroundColor Yellow
} else {
    Write-Host "[1/4] Bumping version ($Bump)..." -ForegroundColor Cyan
    & $PythonCmd "scripts/bump_version.py" $Bump
}

Write-Host "[2/4] Cleaning dist/..." -ForegroundColor Cyan
if (Test-Path "dist") {
    Remove-Item -Recurse -Force "dist"
}

Write-Host "[3/4] Building package..." -ForegroundColor Cyan
& $PythonCmd -m build

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

& $PythonCmd -m twine upload --non-interactive dist/*

Write-Host "Release finalizada com sucesso." -ForegroundColor Green
