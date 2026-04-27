$ErrorActionPreference = "Stop"

function Get-PythonUserScriptsPath {
    $userBase = & py -m site --user-base 2>$null
    if (-not $userBase) {
        return $null
    }

    return Join-Path $userBase "Scripts"
}

function Get-PythonDefaultScriptsPath {
    $pythonScripts = & py -c "import os, sys; print(os.path.join(os.path.dirname(sys.executable), 'Scripts'))" 2>$null
    if (-not $pythonScripts) {
        return $null
    }

    return $pythonScripts
}

function Add-ToUserPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathToAdd
    )

    if (-not (Test-Path $PathToAdd)) {
        try {
            New-Item -ItemType Directory -Force -Path $PathToAdd | Out-Null
        } catch {
            throw "Caminho nao existe e nao foi possivel criar: $PathToAdd"
        }
    }

    $currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $currentUserPath) {
        $currentUserPath = ""
    }
    $paths = $currentUserPath -split ";" | Where-Object { $_ -and $_.Trim().Length -gt 0 }

    $userPathAlreadyHadIt = $paths -contains $PathToAdd
    if (-not $userPathAlreadyHadIt) {
        $newUserPath = ($paths + $PathToAdd) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
    }

    $currentProcessPath = [Environment]::GetEnvironmentVariable("Path", "Process")
    if (-not $currentProcessPath) {
        $currentProcessPath = ""
    }

    $processPaths = $currentProcessPath -split ";" | Where-Object { $_ -and $_.Trim().Length -gt 0 }
    if ($processPaths -notcontains $PathToAdd) {
        $newProcessPath = ($processPaths + $PathToAdd) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $newProcessPath, "Process")
        $env:Path = $newProcessPath
    }

    if ($userPathAlreadyHadIt) {
        Write-Host "OK: PATH do usuario ja continha: $PathToAdd"
    } else {
        Write-Host "OK: Adicionado ao PATH do usuario: $PathToAdd"
    }
    Write-Host "OK: Atualizado também no PATH da sessão atual."
}

function Ensure-BscanLauncher {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptsPath
    )

    if (-not (Test-Path $ScriptsPath)) {
        New-Item -ItemType Directory -Force -Path $ScriptsPath | Out-Null
    }

    $launcherPath = Join-Path $ScriptsPath "bscan.cmd"
    $launcherContent = @"
@echo off
py -m basiliskscan %*
"@

    Set-Content -Path $launcherPath -Value $launcherContent -Encoding ASCII
    Write-Host "OK: Launcher criado/atualizado em $launcherPath"
}

$candidatePaths = @()
$userScripts = Get-PythonUserScriptsPath
$defaultScripts = Get-PythonDefaultScriptsPath

if ($userScripts) {
    $candidatePaths += $userScripts
}
if ($defaultScripts -and ($candidatePaths -notcontains $defaultScripts)) {
    $candidatePaths += $defaultScripts
}

if ($candidatePaths.Count -eq 0) {
    throw "Nao foi possivel determinar o caminho do Scripts do Python."
}

foreach ($path in $candidatePaths) {
    try {
        Add-ToUserPath -PathToAdd $path
        Ensure-BscanLauncher -ScriptsPath $path
        break
    } catch {
        $lastError = $_
    }
}

if ($lastError) {
    throw $lastError
}
