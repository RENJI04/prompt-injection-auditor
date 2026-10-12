"""Reproducible, secret-free benchmark provenance manifests."""

from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import ARTIFACT_SCHEMA_VERSION, RUNNER_VERSION, SCORING_VERSION
from .models import ContextBundle, Suite
from .util import sanitized_argv, sha256_file, sha256_json, utc_now


def git_commit(root: Path) -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def build_manifest(*, run_id: str, repository_root: Path, suite: Suite, condition: str,
                   adapter: Any, contexts: list[ContextBundle], runs: int,
                   filters: dict[str, Any], mutation_ids: list[str], parameters: dict[str, Any],
                   argv: list[str], private_holdout: bool, pricing: dict[str, Any] | None = None,
                   minimal_artifacts: bool = False) -> dict[str, Any]:
    context_records = [{"mode": item.mode, "files": list(item.files), "file_hashes": item.file_hashes, "assembled_hash": item.assembled_hash} for item in contexts]
    benchmark_configuration = {
        "condition": condition,
        "target": {"adapter": adapter.name, "provider": adapter.provider, "model": adapter.model},
        "repeats": runs, "filters": filters, "mutations": mutation_ids,
        "parameters": parameters, "contexts": context_records,
    }
    return {
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION, "runner_version": RUNNER_VERSION,
        "scoring_version": SCORING_VERSION, "run_id": run_id, "status": "RUNNING",
        "started_at": utc_now(), "ended_at": None, "git_commit": git_commit(repository_root),
        "suite": {"name": suite.manifest.get("suite_name"), "version": suite.manifest.get("suite_version"), "content_hash": suite.suite_hash, "file_hashes": suite.file_hashes, "private_holdout": private_holdout},
        "condition": condition, "target": {"adapter": adapter.name, "provider": adapter.provider, "model": adapter.model},
        "judge": {"relationship": "NONE"}, "repeats": runs, "filters": filters,
        "mutation_policy": {"selected": mutation_ids, "default": "none"}, "model_parameters": parameters,
        "contexts": context_records, "python_version": platform.python_version(), "platform": platform.platform(),
        "renguard_source": {"skill_hash": sha256_file(repository_root / "SKILL.md")},
        "benchmark_configuration_hash": sha256_json(benchmark_configuration),
        "pricing_config_hash": sha256_json(pricing) if pricing else None,
        "command_line": sanitized_argv(argv),
        "artifact_mode": "MINIMAL_NO_RAW_RESPONSES" if minimal_artifacts else "REPRODUCIBLE_RAW_RESPONSES",
    }
