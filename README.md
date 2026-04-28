# BasiliskScan 🔍

<div align="center">

<img src="https://github.com/puuertA/BasiliskScan/blob/main/resources/logo.png" alt="BasiliskScan Logo" width="500" height="500">

```
                            ██████╗  █████╗ ███████╗██╗██╗     ██╗███████╗██╗  ██╗
                            ██╔══██╗██╔══██╗██╔════╝██║██║     ██║██╔════╝██║ ██╔╝
                            ██████╔╝███████║███████╗██║██║     ██║███████╗█████╔╝ 
                            ██╔══██╗██╔══██║╚════██║██║██║     ██║╚════██║██╔═██╗ 
                            ██████╔╝██║  ██║███████║██║███████╗██║███████║██║  ██╗
                            ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
```

**Advanced CLI for comprehensive dependency and vulnerability analysis in software projects**

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.5.18-red.svg)](https://github.com/PuertA/basiliskscan)

</div>

> 🇧🇷 Prefer Portuguese? See [`README.pt-BR.md`](README.pt-BR.md).

## Overview

BasiliskScan is a command-line tool that scans projects, identifies dependencies, checks vulnerability sources, and generates rich HTML reports.

## Key Features

- Recursive dependency discovery across supported manifests
- Vulnerability ingestion from OSV, NVD, and Sonatype Guide
- Offline vulnerability database mode
- Rich terminal UI with progress and status feedback
- Interactive HTML report output

## Supported Files

- **Node.js / Ionic**: `package.json`, `package-lock.json`, `npm-shrinkwrap.json`
- **Java**: `pom.xml`, `build.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile`

## Installation

### Requirements

- Python 3.10 or newer
- pip

### Install from PyPI

```bash
pip install basiliskscan
```

### Verify Installation

```bash
bscan --version
bscan --help
```

### Development Installation

```bash
git clone https://github.com/PuertA/basiliskscan.git
cd basiliskscan
pip install -e .
```

### Windows Automatic Setup

If you want the installer to set up `bscan` automatically in PowerShell, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
./scripts/install_basiliskscan.ps1 -Editable
```

This installs the project in editable mode, updates the user PATH, and creates the `bscan` launcher.

## Quick Usage

```bash
# Scan current directory
bscan scan

# Scan a specific project
bscan scan --project ./my-app

# Save report with custom name
bscan scan --project ./my-app --output my-report.html
```

## Offline Vulnerability Database

- Default DB path: `~/.basiliskscan/offline/offline_vulnerabilities.db`
- Optional override: `BASILISKSCAN_OFFLINE_DB_DIR`

The database file is bundled with the package from `src/basiliskscan/data/offline/offline_vulnerabilities.db` and is auto-seeded on first use.

```bash
# Show local DB status
bscan offline-db --status

# Sync expired components
bscan offline-db --sync

# Force full sync
bscan offline-db --sync --force

# Scan using local data only
bscan scan --offline
```

## Optional Configuration

Create a `.env` file in the directory where you run `bscan`:

```env
NVD_API_KEY=your-nvd-api-key
```

## Commands Reference

```bash
bscan scan --help
bscan nvd-key --help
bscan nvd-register-guide
bscan sonatype-guide-key --help
bscan offline-db --help
```

## Project Version Updates

```bash
python scripts/bump_version.py patch
python scripts/bump_version.py minor
python scripts/bump_version.py major
python scripts/bump_version.py set 1.2.3
```

## PyPI Release Script (PowerShell)

Set your PyPI credentials in the current terminal session and run the release script:

```powershell
$env:TWINE_USERNAME="__token__"
$env:TWINE_PASSWORD="pypi-..."
./scripts/release_pypi.ps1 patch
```

Useful options:

```powershell
# build only (no upload)
./scripts/release_pypi.ps1 patch -SkipUpload

# test build/upload steps without changing version
./scripts/release_pypi.ps1 patch -SkipBump -SkipUpload
```

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE).

## Contact

- Issues: <https://github.com/PuertA/basiliskscan/issues>
- Discussions: <https://github.com/PuertA/basiliskscan/discussions>

---

<div align="center">

Built with ❤️ for the developer community.

</div>
