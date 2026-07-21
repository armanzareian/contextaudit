from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol, runtime_checkable

from contextaudit.models import ContextChunk, Policy, ScanReport
from contextaudit.scanner import scan_context


class ExtensionError(ValueError):
    """Raised when an extension hook returns an unsupported value."""


@runtime_checkable
class ContextLoader(Protocol):
    def __call__(self, location: Path) -> Iterable[ContextChunk]: ...


@runtime_checkable
class ContextScanner(Protocol):
    def __call__(
        self,
        chunks: list[ContextChunk],
        policy: Policy | None = None,
    ) -> ScanReport: ...


def load_with(loader: ContextLoader, location: Path) -> list[ContextChunk]:
    chunks = list(loader(location))
    if not chunks:
        raise ExtensionError(f"{location}: custom loader returned no context chunks")
    for index, chunk in enumerate(chunks):
        if not isinstance(chunk, ContextChunk):
            raise ExtensionError(
                f"{location}: custom loader item {index} must be a ContextChunk"
            )
    return chunks


def scan_with_loader(
    loader: ContextLoader,
    location: Path,
    policy: Policy | None = None,
    *,
    scanner: ContextScanner = scan_context,
) -> ScanReport:
    return scanner(load_with(loader, location), policy)
