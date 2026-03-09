# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.1   | Yes       |
| < 1.0.1 | No        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in EventMonitor.Windows, please report it responsibly:

1. **GitHub Security Advisory**: Use [GitHub's private vulnerability reporting](../../security/advisories/new) to submit a report directly

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours of your report
- **Status update** within 7 days with an assessment and expected timeline
- **Credit** in the release notes (unless you prefer to remain anonymous)

## Security Considerations

When using EventMonitor.Windows, be aware of the following:

### Connection String & Sink Security

If using Azure Application Insights, the connection string is sensitive. Follow these practices:

- **Do not** commit connection strings to source control
- **Do not** share connection strings in logs or console output
- Use environment variables or secure vaults (e.g., Azure Key Vault) to store connection strings
- Restrict access to `EventMonitor/Telemetry/LogAnalyticsConString.txt` if it exists on disk
- The `.gitignore` in this project excludes `LogAnalyticsConString.txt` and `MonitoringConfig.json` from version control
- Custom telemetry sinks registered via `Register-TelemetrySink` should not log sensitive data

### Scheduled Task Privileges

The scheduled task runs under `NT AUTHORITY\SYSTEM` with highest privileges. This is necessary to read Security event logs but means:

- Only administrators should be able to register/modify the task
- Audit access to the task configuration
- Monitor the task for unexpected modifications

### Event Log Access

Reading Security event logs requires elevated privileges. The module only reads events; it does not modify or delete any event log entries.
