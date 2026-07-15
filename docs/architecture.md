# Architecture

ContextAudit is an offline Python CLI and library for auditing assembled RAG and LLM context
packs. It is designed around small, testable modules and deterministic output.

## Data Flow

1. `contextaudit.io` loads a context pack, optional adapter format, and optional JSON policy.
2. `contextaudit.models` represents chunks, policies, issues, and scan reports.
3. `contextaudit.scanner` runs deterministic detectors and computes the triage score.
4. `contextaudit.answer_audit` checks answer citations and lexical support against context chunks.
5. `contextaudit.report` renders text, JSON, or SARIF output.
6. `contextaudit.evaluation` runs labeled suites and reports precision, recall, and F1.
7. `contextaudit.cli` wires the library into `scan`, `audit-answer`, and `eval` commands.

The scanner keeps detector output as `Issue` objects until rendering. This makes the CLI and
Python API share the same behavior and keeps report formatting separate from detection logic.

## Report Formats

All report formats are derived from the same `ScanReport`. Text output is optimized for terminal
review, JSON output preserves the full machine-readable issue contract, and SARIF output is shaped
for CI systems that ingest static-analysis results. SARIF rules correspond to detector IDs. SARIF
results preserve the issue source as the artifact URI, the chunk ID as a logical location, the
evidence snippet as the region snippet, and the stable issue fingerprint under
`partialFingerprints.contextaudit`.

## Corpus Adapters

All context inputs normalize to `ContextChunk` values before scanning. Native JSONL is the most
direct path, while adapters cover common retrieval exports:

- Markdown directories with optional simple front matter.
- LangChain-style document JSONL using `page_content` and `metadata`.
- LlamaIndex-style node JSON using node IDs, text, and common metadata source fields.

Adapters preserve user metadata where practical, promote stable chunk IDs and sources, and report
validation failures with the input path, JSON line, or node index. Error messages avoid echoing
full document bodies so malformed sensitive inputs do not get copied into terminal logs.

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
- `missing_citation`: answer citations that do not resolve to supplied chunk IDs.
- `weak_sentence_support`: answer sentences with weak lexical overlap against cited chunks.
- `uncited_risky_context`: answer text overlapping high-risk context that was not cited.

Detectors return short evidence snippets and never execute context text. The score subtracts a
fixed penalty by severity and is intended for triage, not as a calibrated safety probability.
Each issue receives a deterministic fingerprint based on the detector, chunk ID, source, and
evidence. Severity overrides intentionally do not affect fingerprints, which makes review and
suppression workflows stable when a team changes how strongly a detector should fail builds.

Answer citation checks are deterministic lexical heuristics. They do not call models, fetch remote
documents, or prove semantic entailment. They are meant to find obvious citation gaps and claims
that deserve human review.

## Error Handling

Malformed user input raises `InputError`, which the CLI maps to exit code `2`. Policy threshold
failures return exit code `1`. Clean scans, adapter demos, or evaluation runs return `0`.

Input files are size-capped, JSONL parsing reports line numbers, Markdown parsing reports paths,
and LlamaIndex parsing reports node indexes.

## Extension Points

The current extension surface is the Python API:

- create `ContextChunk` values,
- load common context exports through `load_context` or adapter-specific loader functions,
- call `scan_context(chunks, policy)`,
- call `audit_answer(chunks, answer_candidate, policy)`,
- inspect `ScanReport.issues`, `summary`, and `exit_code`.

Future extension work should keep detectors independent, deterministic, and unit-tested with
labeled fixtures. New detectors should document known false positives and avoid external network
or model calls in the default path.
