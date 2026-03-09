# Contributing

Thank you for your interest in contributing to EventMonitor.Windows!

---

## Getting Started

### Prerequisites

- PowerShell 7.4+
- Windows 10/11 or Server 2016+
- Git
- [Pester 5](https://pester.dev/) (for running tests)

### Clone and Setup

```powershell
git clone https://github.com/navalerakesh/EventMonitor.Windows.git
cd EventMonitor.Windows

# Import the module from source
Import-Module .\EventMonitor.Windows.psd1 -Force

# Install test framework
Install-Module -Name Pester -MinimumVersion 5.0 -Scope CurrentUser
```

### Run Tests

```powershell
Import-Module Pester -MinimumVersion 5.0 -Force
Invoke-Pester -Path './tests' -Output Detailed
```

All 54 tests should pass before submitting a pull request.

---

## How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/navalerakesh/EventMonitor.Windows/issues) first
2. Include: PowerShell version, Windows version, error messages, steps to reproduce
3. Include relevant log entries from `C:\ProgramData\WindowsEventMonitor\Logs\`

### Suggesting Features

Open a [discussion](https://github.com/navalerakesh/EventMonitor.Windows/discussions) or issue describing:
- The use case
- Expected behavior
- Any alternative approaches you've considered

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-change`
3. Make changes, keeping commits focused and descriptive
4. Add tests for new functionality
5. Run `Invoke-Pester` — all tests must pass
6. Push and create a pull request

---

## Code Style

- Follow [PowerShell Best Practices](https://poshcode.gitbook.io/powershell-practice-and-style/)
- Use `Verb-Noun` naming for functions
- Prefer full cmdlet names over aliases
- Add comment-based help for public functions
- Use `[CmdletBinding()]` on all public functions

## Adding a New Event Processor

1. Create `EventMonitor/EventProcessors/YourEvents.ps1`
2. Follow the pattern in existing processors (see `LogonEvents.ps1` as a template)
3. Register with `Register-EventProcessor` in the file
4. Add the event group to `MonitoringConfig.ps1`
5. Add tests
6. Update documentation

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](https://github.com/navalerakesh/EventMonitor.Windows/blob/main/LICENSE).

---

**Back to:** [Home](Home)
