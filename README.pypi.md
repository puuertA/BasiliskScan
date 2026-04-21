# BasiliskScan

Advanced CLI for dependency and vulnerability analysis in software projects.

## Installation

```bash
pip install basiliskscan
```

## Quick Start

```bash
bscan --version
bscan --help
bscan scan
```

If `bscan` is not recognized on Windows, run once:

```bash
python -m basiliskscan --help
```

This command auto-adds your Python Scripts directory to `PATH` (user scope).

## What BasiliskScan does

- Recursively discovers dependencies in supported manifests
- Aggregates vulnerability data from OSV, NVD, and Sonatype Guide
- Supports offline vulnerability database mode
- Generates rich HTML reports

## Supported Files

- **Node.js / Ionic**: `package.json`, `package-lock.json`, `npm-shrinkwrap.json`
- **Java**: `pom.xml`, `build.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile`

## Useful Commands

```bash
# Main scan command
bscan scan --help

# NVD credentials
bscan nvd-key --help

# Sonatype Guide credentials
bscan sonatype-guide-key --help

# Offline database operations
bscan offline-db --help
```

## Optional Environment Configuration

Create a `.env` file in your working directory:

```env
NVD_API_KEY=your-nvd-api-key
```

## Project Links

- Homepage: <https://github.com/puuertA/basiliskscan>
- Repository: <https://github.com/puuertA/basiliskscan>
- Issues: <https://github.com/puuertA/basiliskscan/issues>

For complete documentation (including Portuguese version), visit the GitHub repository.
