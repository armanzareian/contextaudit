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

### Threat Model

ContextAudit assumes the local machine, installed package, and repository checkout are trusted.
The main untrusted inputs are assembled context packs, retrieval-export files, answer candidates,
and policy files supplied to the CLI or Python API.

- Context text is treated as data. Detectors search it for risky strings, but ContextAudit never
  follows instructions found in context, loads remote content referenced by context, or evaluates
  context as code.
- Policy files are JSON configuration, not scripts. A policy can lower failure thresholds,
  allowlist sources, disable detectors, or add detector regexes, so use reviewed policies in CI.
- Custom detector regexes are compiled case-insensitively. To reduce regex denial-of-service risk,
  custom patterns are capped at 240 characters and reject backreferences and nested repeated
  groups before scanning starts. This is a conservative guardrail, not a formal proof that every
  accepted pattern is cheap on every input.
- Reports can contain sensitive snippets from matched context. Treat text, JSON, Markdown, and
  SARIF reports as derived sensitive data when scanning private corpora.

Treat context packs and reports as potentially sensitive. Reports include short evidence snippets
around matched text, so avoid uploading reports from private data sources unless your policy
allows it.

Known limits:

- Pattern-based sensitive-data checks can miss secrets or flag benign text.
- Instruction-injection findings identify risky text patterns, not guaranteed model behavior.
- User-provided policy files are parsed as JSON only and are not executed.
- Custom detector regex validation is intentionally heuristic; keep patterns small and reviewable.
