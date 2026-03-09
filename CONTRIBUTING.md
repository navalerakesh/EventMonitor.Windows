# Contributing to EventMonitor.Windows

Thank you for your interest in contributing! This document provides guidelines and best practices for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Submitting Changes](#submitting-changes)
- [Releasing to PSGallery](#releasing-to-psgallery)
- [Reporting Issues](#reporting-issues)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## How to Contribute

### Reporting Bugs

1. Search [existing issues](../../issues) to avoid duplicates
2. Open a new issue using the **Bug Report** template
3. Include:
   - PowerShell version (`$PSVersionTable`)
   - Windows version (`[System.Environment]::OSVersion`)
   - Steps to reproduce
   - Expected vs. actual behavior
   - Relevant entries from `EventMonitor/Telemetry/Logs.txt`

### Suggesting Features

1. Open an issue using the **Feature Request** template
2. Describe:
   - The problem or use case
   - Your proposed solution
   - Alternative approaches you've considered

### Submitting Code

1. Fork [navalerakesh/EventMonitor.Windows](https://github.com/navalerakesh/EventMonitor.Windows)
2. Create a feature branch from `main`: `git checkout -b feature/my-feature`
3. Make your changes following the [Coding Standards](#coding-standards)
4. Test your changes (see [Testing](#testing))
5. Commit with a clear message (see [Commit Messages](#commit-messages))
6. Push to your fork and open a Pull Request

---

## Development Setup

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- [PowerShell 7.4+](https://github.com/PowerShell/PowerShell/releases)
- Administrator privileges (for scheduled task testing)
- Azure Application Insights resource (optional — telemetry sinks are pluggable)

### Getting Started

```powershell
# Clone the repo (or your fork)
git clone https://github.com/navalerakesh/EventMonitor.Windows.git
cd EventMonitor.Windows

# Import the module for development
Import-Module .\EventMonitor.Windows.psd1

# Install development dependencies
Install-Module -Name Pester -MinimumVersion 5.0 -Force
Install-Module -Name PSScriptAnalyzer -Force
```

### Testing

```powershell
# Run PSScriptAnalyzer for code quality
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning

# Run Pester tests (safe local runner — no code coverage, has timeout)
.\Run-Tests.ps1

# Or with less output:
.\Run-Tests.ps1 -Verbosity Normal
```

> **Note:** Do not run `Invoke-Pester` with code coverage enabled locally — it can
> cause VS Code to become unresponsive. Code coverage runs automatically in CI.
> Always use `Run-Tests.ps1` for local testing.

---

## Coding Standards

### PowerShell Style

- Use **PascalCase** for function names following the `Verb-Noun` convention
- Use **approved PowerShell verbs** (`Get-Verb` to see the list)
- Use `[CmdletBinding()]` and `[Parameter()]` attributes for all public functions
- Include comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`) for all exported functions
- Use `$ErrorActionPreference = "Stop"` in scripts that need strict error handling
- Prefer `Write-Verbose` / `Write-Warning` over `Write-Host` for non-interactive output

### Security

- **Never** commit secrets, connection strings, or credentials to the repository
- **Never** log secrets or connection strings in plain text
- Use `-Force` with `Remove-Item` cautiously
- Validate all external input parameters

### File Organization

- Root module is `EventMonitor/WindowsEventMonitor.psm1` — it dot-sources all `.ps1` files
- **`Core/`** — Infrastructure: `EventWatcher.ps1`, `WatchdogService.ps1`, `MonitoringConfig.ps1`, `EventJournal.ps1`
- **`EventProcessors/`** — One file per event category (14 processor files + `EventProcessorBase.ps1`)
- `TelemetryClient.ps1` — Pluggable sink dispatcher (not App Insights-specific)
- `EventDispatch.ps1` — Write-EMLog + event enrichment
- `SessionDetection.ps1` — quser, netstat, user enumeration
- `TaskManagement.ps1` — Scheduled task lifecycle + orchestration
- `Start-EventMonitorService.ps1` — Event-driven entry point (primary)
- `Invoke-EventMonitor` — Exported function for diagnostic one-shot scan
- New event categories should get their own `.ps1` file in `EventProcessors/` and be dot-sourced from the root module

### Commit Messages

Use clear, descriptive commit messages:

```
<type>: <short description>

<optional body explaining the change>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

Examples:
- `feat: add Event 4625 failed logon tracking`
- `fix: handle missing OpenSSH log gracefully`
- `docs: add KQL query examples to README`

---

## Pull Request Process

1. Ensure your PR targets the `main` branch
2. Fill in the PR template completely
3. Ensure PSScriptAnalyzer passes with no errors
4. Add or update tests for your changes
5. Update documentation if behavior changes
6. One approval is required before merging
7. Squash commits into a single meaningful commit on merge

---

## Releasing to PSGallery

The release pipeline is fully automated via GitHub Actions. You just need to set up the secret once, then tag-and-push to release.

### One-Time Setup: PSGallery API Key

1. **Get your API key** from [PSGallery](https://www.powershellgallery.com/account/apikeys):
   - Sign in at https://www.powershellgallery.com
   - Go to **Account** → **API Keys** → **Create**
   - Set a descriptive name (e.g. `EventMonitor.Windows-CI`)
   - Scope: **Push new packages and package versions**
   - Glob pattern: `EventMonitor.Windows`
   - Set expiration (max 365 days — set a calendar reminder to rotate)
   - Copy the key immediately (it won't be shown again)

2. **Store the key as a GitHub secret**:
   - Go to your repo → **Settings** → **Secrets and variables** → **Actions**
   - Click **New repository secret**
   - Name: `PSGALLERY_API_KEY`
   - Value: paste the API key
   - Click **Add secret**

3. **Create a GitHub Environment** (recommended for protection rules):
   - Go to **Settings** → **Environments** → **New environment**
   - Name: `PSGallery`
   - Optionally add protection rules (required reviewers, wait timer)
   - The release workflow references this environment for the publish job

### How to Release

```powershell
# 1. Update the version in EventMonitor.Windows.psd1
#    ModuleVersion = '1.1.0'

# 2. Update CHANGELOG.md — move items from [Unreleased] to [1.1.0] - YYYY-MM-DD

# 3. Update ReleaseNotes in the manifest PrivateData.PSData section

# 4. Commit and push
git add -A
git commit -m 'chore: prepare release v1.1.0'
git push origin main

# 5. Tag and push — this triggers the release pipeline
git tag v1.1.0
git push origin v1.1.0
```

The pipeline will automatically:
1. Run PSScriptAnalyzer (lint)
2. Run all Pester tests
3. Validate the manifest, version consistency, and changelog entry
4. Check that the version isn't already published on PSGallery
5. Stage and publish the module to PSGallery
6. Create a GitHub Release with changelog notes

### Manual Release (workflow_dispatch)

You can also trigger a release manually from the **Actions** tab → **Release to PSGallery** → **Run workflow**. Use this if a tag push failed or you need to re-publish.

### API Key Rotation

PSGallery API keys expire. When yours is about to expire:
1. Create a new key on PSGallery
2. Update the `PSGALLERY_API_KEY` secret in GitHub
3. Delete the old key from PSGallery

---

## Questions?

If you have questions about contributing, open a [Discussion](../../discussions) or reach out via an issue.

Thank you for helping make EventMonitor.Windows better!
