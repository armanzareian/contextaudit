from __future__ import annotations

from pathlib import Path

from contextaudit import ContextChunk, Policy, ScanReport, scan_with_loader


def load_pipe_context(location: Path) -> list[ContextChunk]:
    chunks: list[ContextChunk] = []
    for line_number, line in enumerate(location.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        fields = line.split("|", 3)
        if len(fields) != 4:
            raise ValueError(f"{location}:{line_number}: expected four pipe-delimited fields")
        chunk_id, source, trusted_text, text = fields
        if trusted_text not in {"true", "false"}:
            raise ValueError(f"{location}:{line_number}: trusted field must be true or false")
        chunks.append(
            ContextChunk(
                chunk_id=chunk_id,
                source=source,
                trusted=trusted_text == "true",
                text=text,
                metadata={"adapter": "custom-pipe"},
            )
        )
    return chunks


def audit_custom_context(location: Path) -> ScanReport:
    return scan_with_loader(load_pipe_context, location, Policy(fail_on="critical"))


def main() -> int:
    report = audit_custom_context(Path(__file__).with_name("custom-context.pipe"))
    print(f"issues={len(report.issues)} exit_code={report.exit_code}")
    for issue in report.issues:
        print(f"{issue.severity} {issue.detector} {issue.chunk_id} {issue.fingerprint}")
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
