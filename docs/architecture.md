# Architecture

ContextAudit is an offline Python CLI and library for auditing assembled RAG and LLM context
packs. It is designed around small, testable modules and deterministic output.

## Data Flow

1. `contextaudit.io` loads a JSONL context pack and optional JSON policy.
2. `contextaudit.models` represents chunks, policies, issues, and scan reports.
3. `contextaudit.scanner` runs deterministic detectors and computes the triage score.
4. `contextaudit.report` renders text or JSON output.
5. `contextaudit.evaluation` runs labeled suites and reports precision, recall, and F1.
6. `contextaudit.cli` wires the library into `scan` and `eval` commands.

The scanner keeps detector output as `Issue` objects until rendering. This makes the CLI and
Python API share the same behavior and keeps report formatting separate from detection logic.

## Policy Model

Policies are loaded once and normalized before scanning. The policy model controls:

- the failure threshold and maximum chunk size,
- disabled detector IDs,
- detector-level severity overrides,
- source allowlists for instruction-like detector checks,
- detector-specific regex pattern packs.

Policy validation rejects unknown detectors, invalid severities, and invalid regex patterns before
the scanner runs. CLI flags can override the failure threshold and chunk-size limit while preserving
the rest of the file policy.

## Detectors

The initial detector set is intentionally narrow:

- `instruction_override`: instruction-like context that tries to override system or developer
  behavior.
- `sensitive_data`: common key/value shapes such as password, secret, token, or API key text.
- `untrusted_instruction`: untrusted chunks containing authority or instruction-like language.
- `duplicate_text`: repeated normalized text that can crowd a context window.
- `oversize_chunk`: chunks larger than the configured character limit.

Detectors return short evidence snippets and never execute context text. The score subtracts a
fixed penalty by severity and is intended for triage, not as a calibrated safety probability.
Each issue receives a deterministic fingerprint based on the detector, chunk ID, source, and
evidence. Severity overrides intentionally do not affect fingerprints, which makes review and
suppression workflows stable when a team changes how strongly a detector should fail builds.

## Error Handling

Malformed user input raises `InputError`, which the CLI maps to exit code `2`. Policy threshold
failures return exit code `1`. Clean scans or evaluation runs return `0`.

Input files are size-capped, JSONL parsing reports line numbers, and adapter errors avoid
printing full chunk text.

## Extension Points

The current extension surface is the Python API:

- create `ContextChunk` values,
- call `scan_context(chunks, policy)`,
- inspect `ScanReport.issues`, `summary`, and `exit_code`.

Future extension work should keep detectors independent, deterministic, and unit-tested with
labeled fixtures. New detectors should document known false positives and avoid external network
or model calls in the default path.
