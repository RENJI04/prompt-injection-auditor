"""Shared immutable benchmark data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Scenario:
    canonical: dict[str, Any]
    source_file: str

    @property
    def id(self) -> str:
        return self.canonical["id"]

    @property
    def kind(self) -> str:
        return self.canonical["kind"]

    @property
    def category(self) -> str:
        return self.canonical["category"]


@dataclass(frozen=True)
class RuntimeCase:
    scenario: Scenario
    runtime_id: str
    runtime_view: dict[str, Any]
    mutation_id: str | None = None


@dataclass(frozen=True)
class Suite:
    root: Path
    manifest: dict[str, Any]
    scenarios: tuple[Scenario, ...]
    suite_hash: str
    file_hashes: dict[str, str]


@dataclass(frozen=True)
class ContextBundle:
    mode: str
    text: str
    files: tuple[str, ...]
    file_hashes: dict[str, str]
    assembled_hash: str


@dataclass(frozen=True)
class PromptBundle:
    condition: str
    messages: tuple[dict[str, str], ...]
    context: ContextBundle
    prompt_hash: str


@dataclass
class AdapterResult:
    text: str
    model: str
    provider: str
    latency_seconds: float | None = None
    usage: dict[str, int] | None = None
    attempts: int = 1
    status: str = "COMPLETED"
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ParsedResponse:
    state: str
    value: dict[str, Any] | None
    errors: tuple[str, ...] = ()
