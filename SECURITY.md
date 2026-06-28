# Security Policy

## Supported Versions

Security fixes are accepted for the current `main` branch until the project publishes versioned
releases.

## Reporting a Vulnerability

Please report suspected vulnerabilities by opening a private security advisory on GitHub, or by
contacting the maintainer through the GitHub profile linked from the repository.

Include:

- affected version or commit,
- steps to reproduce,
- expected and observed behavior,
- whether any sensitive data was exposed.

## Security Model

ContextAudit is an offline scanner. It does not make network requests, execute context text, or
call external models. It reads local JSON/JSONL files, applies deterministic checks, and writes
reports to stdout.

Treat context packs and reports as potentially sensitive. Reports include short evidence snippets
around matched text, so avoid uploading reports from private data sources unless your policy
allows it.

Known limits:

- Pattern-based sensitive-data checks can miss secrets or flag benign text.
- Prompt-injection findings identify risky text patterns, not guaranteed model behavior.
- User-provided policy files are parsed as JSON only and are not executed.
