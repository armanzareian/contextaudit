from __future__ import annotations

import compileall
import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".md", ".py", ".toml", ".yml", ".yaml", ".json", ".jsonl"}
PRIVATE_CONTROL_DIR = "." + "project-control"
PRIVATE_FILENAMES = {
    "roadmap.md",
    "ROADMAP.md",
    "active" + "_project.json",
    "project" + "_registry.json",
    "TODO.private.md",
}
PRIVATE_LINK_PATTERNS = [
    PRIVATE_CONTROL_DIR + "/",
    "active" + "_project.json",
    "project" + "_registry.json",
]


def main() -> int:
    checks = [
        check_no_private_files,
        check_text_files,
        check_python_compiles,
        check_json_examples,
        check_pyproject,
    ]
    failures: list[str] = []
    for check in checks:
        failures.extend(check())
    if failures:
        for failure in failures:
            print(f"quality: {failure}", file=sys.stderr)
        return 1
    print("quality: all checks passed")
    return 0


def iter_project_files() -> list[Path]:
    ignored_dirs = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if any(part in ignored_dirs for part in path.parts):
            continue
        if path.is_file():
            files.append(path)
    return files


def check_no_private_files() -> list[str]:
    failures: list[str] = []
    for path in iter_project_files():
        if path.name in PRIVATE_FILENAMES:
            failures.append(f"private filename present: {path.relative_to(ROOT)}")
        if PRIVATE_CONTROL_DIR in path.parts:
            failures.append(f"private control path present: {path.relative_to(ROOT)}")
    return failures


def check_text_files() -> list[str]:
    failures: list[str] = []
    for path in iter_project_files():
        if path.suffix not in TEXT_SUFFIXES and path.name not in {"Makefile", ".gitignore", ".editorconfig"}:
            continue
        text = path.read_text()
        for line_number, line in enumerate(text.splitlines(), start=1):
            if line.rstrip() != line:
                failures.append(f"trailing whitespace: {path.relative_to(ROOT)}:{line_number}")
        if path.name not in {".gitignore", "quality.py"}:
            for pattern in PRIVATE_LINK_PATTERNS:
                if pattern in text:
                    failures.append(f"private reference in {path.relative_to(ROOT)}: {pattern}")
    return failures


def check_python_compiles() -> list[str]:
    ok = compileall.compile_dir(ROOT / "src", quiet=1)
    ok = compileall.compile_dir(ROOT / "tests", quiet=1) and ok
    ok = compileall.compile_dir(ROOT / "scripts", quiet=1) and ok
    return [] if ok else ["python compile check failed"]


def check_json_examples() -> list[str]:
    failures: list[str] = []
    for path in (ROOT / "examples").rglob("*.json"):
        try:
            json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            failures.append(f"invalid JSON: {path.relative_to(ROOT)}:{exc.lineno}: {exc.msg}")
    for path in (ROOT / "examples").rglob("*.jsonl"):
        for line_number, line in enumerate(path.read_text().splitlines(), start=1):
            if not line.strip():
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                failures.append(
                    f"invalid JSONL: {path.relative_to(ROOT)}:{line_number}: {exc.msg}"
                )
    return failures


def check_pyproject() -> list[str]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        data = tomllib.load(handle)
    project = data.get("project", {})
    missing = [key for key in ("name", "version", "description", "requires-python") if key not in project]
    return [f"pyproject missing project.{key}" for key in missing]


if __name__ == "__main__":
    raise SystemExit(main())
