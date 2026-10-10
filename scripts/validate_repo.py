#!/usr/bin/env python3
"""Validate RenGuard's taxonomy, risk scoring, evals, and historical benchmark."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import statistics
import sys
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any
from urllib.parse import unquote


ROUNDING_TOLERANCE = 0.000051
CONFIGURATIONS = ("with_skill", "without_skill")
HISTORICAL_SOURCE_COMMIT = "c2e8de497b7550ca3ca4df081efae27ddd28d582"
CURRENT_CORPUS_STATUS = "current_renguard_v2_alpha"
HISTORICAL_METADATA_SHA256 = "6caa15e52fae155c3ca1fcb4efa4a3a47628891cb3660877637e160f9067316e"
OWASP_LLM_2026 = {
    "LLM01:2026": "Prompt Injection",
    "LLM02:2026": "Sensitive Information Disclosure",
    "LLM03:2026": "Excessive Agency",
    "LLM04:2026": "Supply Chain",
    "LLM05:2026": "Data and Model Poisoning",
    "LLM06:2026": "Unbounded Consumption",
    "LLM07:2026": "Misinformation",
    "LLM08:2026": "Hidden Context Exposure",
    "LLM09:2026": "Vector and Embedding Weaknesses",
    "LLM10:2026": "Improper Output Handling",
}
OWASP_AGENTIC_2026 = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}
TECHNIQUE_FAMILY_COUNTS = {
    "PI": 10,
    "HC": 4,
    "PR": 3,
    "TL": 5,
    "ME": 2,
    "AG": 5,
    "RA": 3,
    "SC": 1,
    "EX": 1,
    "OU": 1,
    "RC": 1,
    "MI": 1,
    "MM": 1,
}
REQUIRED_TECHNIQUE_IDS = {
    f"RG-{family}-{number:03d}"
    for family, count in TECHNIQUE_FAMILY_COUNTS.items()
    for number in range(1, count + 1)
}
TECHNIQUE_ID_PATTERN = re.compile(
    r"RG-(?:PI|HC|PR|TL|ME|AG|RA|SC|EX|OU|RC|MI|MM)-[0-9]{3}"
)
HARDENING_ID_PATTERN = re.compile(
    r"RG-HARD-(?:P|AUTHN|AUTHZ|DATA|TOOL|RUN|NET|MEM|AGENT|HITL|MON|REC|RES|OUT)-[0-9]{3}"
)
HARDENING_CONTROL_LAYERS = {
    "PROMPT",
    "APPLICATION",
    "AUTHENTICATION",
    "AUTHORIZATION",
    "DATA",
    "TOOL",
    "MEMORY",
    "RUNTIME",
    "NETWORK",
    "HUMAN APPROVAL",
    "MONITORING",
    "RECOVERY",
}
HARDENING_STRENGTHS = {
    "GUIDANCE",
    "MODEL-ENFORCED",
    "APPLICATION-ENFORCED",
    "PLATFORM-ENFORCED",
    "EXTERNAL / INDEPENDENT ENFORCEMENT",
}
IMPLEMENTATION_STATUSES = {"IMPLEMENTED", "PROPOSED", "PROJECTED", "UNKNOWN"}
SECURITY_FUNCTIONS = {"PREVENT", "CONTAIN", "DETECT", "RECOVER"}
PHASE5_COVERAGE_STATUSES = {
    "RG-ME-001": "CORE",
    "RG-ME-002": "CORE",
    "RG-RA-001": "CORE",
    "RG-RA-002": "CORE",
    "RG-RA-003": "PARTIAL",
}
PHASE6_COVERAGE_STATUSES = {
    "RG-TL-004": "CORE",
    "RG-AG-003": "CORE",
    "RG-AG-004": "CORE",
    "RG-AG-005": "CORE",
    "RG-SC-001": "CORE",
    "RG-EX-001": "CORE",
    "RG-RC-001": "CORE",
}
PHASE6_COVERAGE_COUNTS = {"CORE": 32, "PARTIAL": 5, "PLANNED": 1}
MCP_STABLE_VERSION = "2026-07-28"
MCP_VERIFIED_ON = "2026-10-10"
TOOL_CAPABILITY_CLASSES = {"TC0", "TC1", "TC2", "TC3", "TC4"}
REQUIRED_HARDENING_FIELDS = (
    "Control Layer",
    "Strength",
    "Security Functions",
    "Implementation Status",
    "Purpose",
    "Threats Addressed",
    "Applicable RenGuard Techniques",
    "Implementation Guidance",
    "Example",
    "Limitations",
    "Failure Modes",
    "Verification Steps",
    "Residual Risk",
    "Related Patterns",
)
REQUIRED_TECHNIQUE_FIELDS = (
    "Category Family",
    "Definition",
    "Typical attack sources",
    "Detection signals",
    "Preconditions",
    "Security impact",
    "Example attack pattern",
    "Primary OWASP LLM 2026",
    "Secondary OWASP LLM 2026",
    "OWASP Agentic 2026",
    "Commonly confused with",
    "Boundary / non-example",
    "Prompt-level mitigations",
    "Application/runtime mitigations",
    "Current RenGuard Coverage Status",
)
RISK_DIMENSIONS = {
    "E": (1, "Exploitability", 14),
    "P": (2, "Preconditions / Required Access", 10),
    "H": (3, "Human Interaction / Dependency", 8),
    "V": (4, "Privilege / Authority", 9),
    "T": (5, "Tool / Action Capability", 9),
    "D": (6, "Sensitive Data Exposure", 9),
    "A": (7, "Autonomy", 6),
    "S": (8, "Persistence", 6),
    "B": (9, "Blast Radius", 8),
    "R": (10, "Reversibility", 6),
    "X": (11, "Detection Difficulty", 8),
    "G": (12, "External Reach", 7),
}
EXPOSURE_SYMBOLS = ("E", "P", "H", "X")
IMPACT_SYMBOLS = ("V", "T", "D", "A", "S", "B", "R", "G")
SEVERITY_BANDS = {
    "INFORMATIONAL": (0.0, 0.0),
    "LOW": (0.1, 3.9),
    "MEDIUM": (4.0, 6.9),
    "HIGH": (7.0, 8.9),
    "CRITICAL": (9.0, 10.0),
}
CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW"}
EXPLOITABILITY_LABELS = {"TRIVIAL", "EASY", "MODERATE", "HARD", "CONDITIONAL"}
RISK_CASES = {
    "A": ((0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), 0.0, "INFORMATIONAL"),
    "B": ((4, 4, 4, 0, 0, 0, 0, 0, 1, 1, 0, 0), 3.6, "LOW"),
    "C": ((3, 3, 4, 1, 2, 3, 1, 1, 2, 4, 2, 2), 6.0, "MEDIUM"),
    "D": ((3, 3, 4, 3, 3, 3, 3, 2, 3, 4, 3, 4), 7.9, "HIGH"),
    "E": ((4, 4, 4, 4, 4, 3, 4, 4, 4, 4, 3, 4), 9.6, "CRITICAL"),
}
TAXONOMY_FILES = (
    "references/vulnerability-taxonomy.md",
    "references/renguard-techniques.md",
    "references/owasp-llm-2026.md",
    "references/owasp-agentic-2026.md",
    "references/risk-scoring.md",
    "references/hardening-patterns.md",
    "references/rag-security.md",
    "references/memory-security.md",
    "references/tool-security.md",
    "references/mcp-security.md",
    "references/agentic-security.md",
)
EXAMPLE_FILES = (
    "examples/01-chatbot-prompt.md",
    "examples/02-rag-agent-prompt.md",
    "examples/03-tool-using-agent-prompt.md",
)
PHASE5_REFERENCE_FILES = (
    "references/rag-security.md",
    "references/memory-security.md",
)
PHASE6_REFERENCE_FILES = (
    "references/tool-security.md",
    "references/mcp-security.md",
    "references/agentic-security.md",
)
CURRENT_TAXONOMY_CONSUMERS = (
    "README.md",
    "SKILL.md",
    *TAXONOMY_FILES,
    *EXAMPLE_FILES,
)


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)
    metrics: dict[str, dict[str, float | int]] = field(default_factory=dict)
    eval_count: int = 0
    run_count: int = 0
    technique_count: int = 0
    hardening_pattern_count: int = 0


def _load_json(path: Path, label: str, errors: list[str]) -> Any | None:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        errors.append(f"{label}: missing file: {path}")
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{label}: cannot parse {path}: {exc}")
    return None


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def calculate_risk_score(values: dict[str, int] | tuple[int, ...]) -> float:
    """Calculate a one-decimal RenGuard Risk Score from the canonical 12 dimensions."""
    symbols = tuple(RISK_DIMENSIONS)
    if isinstance(values, dict):
        if set(values) != set(symbols):
            raise ValueError(f"risk dimensions must be exactly {symbols!r}")
        vector = tuple(values[symbol] for symbol in symbols)
    else:
        vector = tuple(values)
        if len(vector) != len(symbols):
            raise ValueError(f"risk vector must contain {len(symbols)} values")

    if any(not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 4 for value in vector):
        raise ValueError("risk dimension values must be integers from 0 through 4")

    weighted_total = sum(
        RISK_DIMENSIONS[symbol][2] * value
        for symbol, value in zip(symbols, vector, strict=True)
    )
    score = (Decimal(weighted_total) / Decimal(40)).quantize(
        Decimal("0.1"), rounding=ROUND_HALF_UP
    )
    return float(max(Decimal("0.0"), min(Decimal("10.0"), score)))


def severity_for_score(score: float) -> str:
    """Return the fixed RenGuard severity label for a valid one-decimal score."""
    if not _is_number(score) or not 0.0 <= float(score) <= 10.0:
        raise ValueError("risk score must be in the range 0.0 through 10.0")
    for severity, (minimum, maximum) in SEVERITY_BANDS.items():
        if minimum <= float(score) <= maximum:
            return severity
    raise ValueError(f"risk score {score!r} is not covered by the severity bands")


def _check_close(
    errors: list[str], label: str, actual: Any, expected: float, tolerance: float = ROUNDING_TOLERANCE
) -> None:
    if not _is_number(actual):
        errors.append(f"{label}: expected a number, found {actual!r}")
    elif not math.isclose(float(actual), expected, rel_tol=0.0, abs_tol=tolerance):
        errors.append(f"{label}: stored {actual!r}, recomputed {expected:.10g}")


def _validate_evals(root: Path, data: Any, errors: list[str]) -> dict[Any, str]:
    if not isinstance(data, dict) or not isinstance(data.get("evals"), list):
        errors.append("evals/evals.json: top-level 'evals' must be a list")
        return {}

    if data.get("corpus_status") != CURRENT_CORPUS_STATUS:
        errors.append(
            "evals/evals.json: corpus_status must identify the current RenGuard v2-alpha corpus"
        )
    if data.get("historical_benchmark_source_commit") != HISTORICAL_SOURCE_COMMIT:
        errors.append(
            "evals/evals.json: historical benchmark source commit is missing or incorrect"
        )

    eval_ids: dict[Any, str] = {}
    assertion_ids: set[Any] = set()

    for index, evaluation in enumerate(data["evals"]):
        label = f"evals/evals.json eval[{index}]"
        if not isinstance(evaluation, dict):
            errors.append(f"{label}: expected an object")
            continue

        eval_id = evaluation.get("id")
        eval_name = evaluation.get("eval_name")
        if eval_id in eval_ids:
            errors.append(f"{label}: duplicate eval ID {eval_id!r}")
        elif eval_id is None:
            errors.append(f"{label}: missing eval ID")
        else:
            eval_ids[eval_id] = eval_name

        files = evaluation.get("files")
        if not isinstance(files, list):
            errors.append(f"{label}: 'files' must be a list")
        else:
            for relative_name in files:
                if not isinstance(relative_name, str):
                    errors.append(f"{label}: fixture path must be a string")
                    continue
                fixture = root / relative_name
                if not fixture.is_file():
                    errors.append(f"{label}: missing eval fixture {relative_name!r}")

        assertions = evaluation.get("assertions")
        if not isinstance(assertions, list):
            errors.append(f"{label}: 'assertions' must be a list")
            continue
        local_assertion_ids: set[Any] = set()
        for assertion_index, assertion in enumerate(assertions):
            assertion_label = f"{label} assertion[{assertion_index}]"
            if not isinstance(assertion, dict):
                errors.append(f"{assertion_label}: expected an object")
                continue
            assertion_id = assertion.get("id")
            if assertion_id is None:
                errors.append(f"{assertion_label}: missing assertion ID")
            elif assertion_id in local_assertion_ids or assertion_id in assertion_ids:
                errors.append(f"{assertion_label}: duplicate assertion ID {assertion_id!r}")
            else:
                local_assertion_ids.add(assertion_id)
                assertion_ids.add(assertion_id)

    return eval_ids


def _validate_run(
    run: Any,
    index: int,
    eval_ids: dict[Any, str],
    errors: list[str],
) -> tuple[Any, Any, Any] | None:
    label = f"benchmarks/benchmark.json run[{index}]"
    if not isinstance(run, dict):
        errors.append(f"{label}: expected an object")
        return None

    eval_id = run.get("eval_id")
    configuration = run.get("configuration")
    run_number = run.get("run_number")
    if eval_id not in eval_ids:
        errors.append(f"{label}: benchmark references unknown eval ID {eval_id!r}")
    elif run.get("eval_name") != eval_ids[eval_id]:
        errors.append(
            f"{label}: eval_name {run.get('eval_name')!r} does not match {eval_ids[eval_id]!r}"
        )
    if configuration not in CONFIGURATIONS:
        errors.append(f"{label}: unsupported configuration {configuration!r}")

    result = run.get("result")
    if not isinstance(result, dict):
        errors.append(f"{label}: missing result object")
        return (eval_id, configuration, run_number)

    counts: dict[str, int] = {}
    for key in ("passed", "failed", "total"):
        value = result.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"{label}: result.{key} must be a non-negative integer")
        else:
            counts[key] = value

    if len(counts) == 3:
        if counts["passed"] + counts["failed"] != counts["total"]:
            errors.append(
                f"{label}: passed + failed must equal total "
                f"({counts['passed']} + {counts['failed']} != {counts['total']})"
            )
        if counts["total"] == 0:
            errors.append(f"{label}: result.total must be greater than zero")
        else:
            _check_close(
                errors,
                f"{label} result.pass_rate",
                result.get("pass_rate"),
                counts["passed"] / counts["total"],
            )

    expectations = run.get("expectations")
    if not isinstance(expectations, list):
        errors.append(f"{label}: expectations must be a list")
    elif len(counts) == 3:
        expectation_passes = sum(
            1 for expectation in expectations if isinstance(expectation, dict) and expectation.get("passed") is True
        )
        expectation_failures = sum(
            1 for expectation in expectations if isinstance(expectation, dict) and expectation.get("passed") is False
        )
        if len(expectations) != counts["total"]:
            errors.append(
                f"{label}: expectation count {len(expectations)} does not match total {counts['total']}"
            )
        if expectation_passes != counts["passed"] or expectation_failures != counts["failed"]:
            errors.append(
                f"{label}: expectation outcomes do not match stored passed/failed counts"
            )

    return (eval_id, configuration, run_number)


def _configuration_metrics(runs: list[dict[str, Any]]) -> dict[str, Any]:
    passed = sum(run["result"]["passed"] for run in runs)
    failed = sum(run["result"]["failed"] for run in runs)
    total = sum(run["result"]["total"] for run in runs)
    pass_rates = [
        run["result"]["passed"] / run["result"]["total"]
        for run in runs
    ]
    times = [float(run["result"]["time_seconds"]) for run in runs]
    tokens = [float(run["result"]["tokens"]) for run in runs]

    def distribution(values: list[float]) -> dict[str, float]:
        return {
            "mean": statistics.mean(values),
            "stddev": statistics.stdev(values) if len(values) > 1 else 0.0,
            "min": min(values),
            "max": max(values),
        }

    return {
        "assertions": {"passed": passed, "failed": failed, "total": total},
        "assertion_pass_rate": passed / total,
        "mean_eval_pass_rate": distribution(pass_rates),
        "time_seconds": distribution(times),
        "tokens": distribution(tokens),
    }


def _validate_summary(
    summary: Any,
    metrics: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    if not isinstance(summary, dict):
        errors.append("benchmarks/benchmark.json: missing run_summary object")
        return

    definitions = summary.get("metric_definitions")
    if not isinstance(definitions, dict) or not all(
        key in definitions for key in ("assertion_pass_rate", "mean_eval_pass_rate")
    ):
        errors.append("run_summary: metric_definitions must distinguish micro and macro rates")

    for configuration in CONFIGURATIONS:
        stored = summary.get(configuration)
        if not isinstance(stored, dict):
            errors.append(f"run_summary.{configuration}: missing object")
            continue
        expected = metrics[configuration]
        if stored.get("assertions") != expected["assertions"]:
            errors.append(
                f"run_summary.{configuration}.assertions: stored {stored.get('assertions')!r}, "
                f"recomputed {expected['assertions']!r}"
            )
        _check_close(
            errors,
            f"run_summary.{configuration}.assertion_pass_rate",
            stored.get("assertion_pass_rate"),
            expected["assertion_pass_rate"],
        )
        for group in ("mean_eval_pass_rate", "time_seconds", "tokens"):
            stored_group = stored.get(group)
            if not isinstance(stored_group, dict):
                errors.append(f"run_summary.{configuration}.{group}: missing object")
                continue
            for statistic_name, expected_value in expected[group].items():
                _check_close(
                    errors,
                    f"run_summary.{configuration}.{group}.{statistic_name}",
                    stored_group.get(statistic_name),
                    expected_value,
                )

    delta = summary.get("delta")
    if not isinstance(delta, dict):
        errors.append("run_summary.delta: missing object")
        return
    with_skill = metrics["with_skill"]
    without_skill = metrics["without_skill"]
    expected_delta = {
        "assertion_pass_rate": with_skill["assertion_pass_rate"]
        - without_skill["assertion_pass_rate"],
        "mean_eval_pass_rate": with_skill["mean_eval_pass_rate"]["mean"]
        - without_skill["mean_eval_pass_rate"]["mean"],
        "time_seconds": with_skill["time_seconds"]["mean"]
        - without_skill["time_seconds"]["mean"],
        "tokens": with_skill["tokens"]["mean"] - without_skill["tokens"]["mean"],
    }
    for key, expected_value in expected_delta.items():
        _check_close(errors, f"run_summary.delta.{key}", delta.get(key), expected_value)


def _validate_notes(notes: Any, time_delta: float, errors: list[str]) -> None:
    if not isinstance(notes, list) or not all(isinstance(note, str) for note in notes):
        errors.append("benchmarks/benchmark.json: notes must be a list of strings")
        return
    for note in notes:
        normalized = note.lower().replace("_", " ")
        if re.search(r"eval\s*8.*with[ -]?skill.*scor(?:e|ed)\s+0(?:\.0+)?%", normalized):
            errors.append("benchmark notes: Eval 8 with_skill cannot be described as scoring 0%")
        if "grader false negative" in normalized or "grader error" in normalized:
            errors.append("benchmark notes: unsupported grader-error interpretation is not allowed")
        overhead = re.search(
            r"(?:skill\s+adds|average\s+overhead).*?([0-9]+(?:\.[0-9]+)?)\s*(?:s|seconds)",
            normalized,
        )
        if overhead and not math.isclose(
            float(overhead.group(1)), time_delta, rel_tol=0.0, abs_tol=0.05
        ):
            errors.append(
                "benchmark notes: stated average time overhead does not match raw run data"
            )


def _validate_benchmark(
    data: Any,
    eval_ids: dict[Any, str],
    errors: list[str],
) -> tuple[dict[str, dict[str, Any]], int]:
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        errors.append("benchmarks/benchmark.json: top-level 'runs' must be a list")
        return {}, 0

    runs = data["runs"]
    run_keys: set[tuple[Any, Any, Any]] = set()
    for index, run in enumerate(runs):
        run_key = _validate_run(run, index, eval_ids, errors)
        if run_key in run_keys:
            errors.append(f"benchmarks/benchmark.json run[{index}]: duplicate run key {run_key!r}")
        elif run_key is not None:
            run_keys.add(run_key)

    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        errors.append("benchmarks/benchmark.json: missing metadata object")
    else:
        metadata_digest = hashlib.sha256(
            json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if metadata_digest != HISTORICAL_METADATA_SHA256:
            errors.append(
                "benchmark metadata: historical metadata changed from the Phase 2 checkpoint"
            )
        benchmark_corpus = metadata.get("benchmark_corpus")
        if not isinstance(benchmark_corpus, dict):
            errors.append("benchmark metadata: missing benchmark_corpus provenance object")
        else:
            if benchmark_corpus.get("source_commit") != HISTORICAL_SOURCE_COMMIT:
                errors.append("benchmark metadata: historical corpus source commit is incorrect")
            if benchmark_corpus.get("current_worktree_corpus_is_source") is not False:
                errors.append(
                    "benchmark metadata: current worktree corpus must not be identified as the source"
                )
            for key, expected_path in (
                ("eval_definitions_path", "evals/evals.json"),
                ("fixtures_path", "evals/files/"),
            ):
                if benchmark_corpus.get(key) != expected_path:
                    errors.append(
                        f"benchmark metadata: benchmark_corpus.{key} must be {expected_path!r}"
                    )
        listed_eval_ids = metadata.get("evals_run")
        if not isinstance(listed_eval_ids, list) or set(listed_eval_ids) != set(eval_ids):
            errors.append("benchmark metadata.evals_run must match the eval definition IDs")
        expected_runs = metadata.get("runs_per_configuration")
        if not isinstance(expected_runs, int) or isinstance(expected_runs, bool) or expected_runs < 1:
            errors.append("benchmark metadata.runs_per_configuration must be a positive integer")
        else:
            for eval_id in eval_ids:
                for configuration in CONFIGURATIONS:
                    actual_runs = sum(
                        1
                        for run in runs
                        if isinstance(run, dict)
                        and run.get("eval_id") == eval_id
                        and run.get("configuration") == configuration
                    )
                    if actual_runs != expected_runs:
                        errors.append(
                            f"benchmark eval {eval_id} {configuration}: expected {expected_runs} "
                            f"run(s), found {actual_runs}"
                        )

    metrics: dict[str, dict[str, Any]] = {}
    for configuration in CONFIGURATIONS:
        configuration_runs = [
            run
            for run in runs
            if isinstance(run, dict)
            and run.get("configuration") == configuration
            and isinstance(run.get("result"), dict)
            and all(
                _is_number(run["result"].get(key))
                for key in ("passed", "failed", "total", "pass_rate", "time_seconds", "tokens")
            )
        ]
        if not configuration_runs:
            errors.append(f"benchmark: no valid {configuration} runs found")
            continue
        try:
            metrics[configuration] = _configuration_metrics(configuration_runs)
        except (ZeroDivisionError, statistics.StatisticsError) as exc:
            errors.append(f"benchmark {configuration}: cannot calculate metrics: {exc}")

    if all(configuration in metrics for configuration in CONFIGURATIONS):
        _validate_summary(data.get("run_summary"), metrics, errors)
        time_delta = (
            metrics["with_skill"]["time_seconds"]["mean"]
            - metrics["without_skill"]["time_seconds"]["mean"]
        )
        _validate_notes(data.get("notes"), time_delta, errors)
    return metrics, len(runs)


def _validate_markdown_links(root: Path, relative_name: str, errors: list[str]) -> None:
    path = root / relative_name
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"{relative_name}: cannot read file: {exc}")
        return

    for target in re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", text):
        target = target.strip().strip("<>").split(maxsplit=1)[0]
        if not target or target.startswith(("#", "http://", "https://", "mailto:")):
            continue
        relative_target = unquote(target.split("#", 1)[0])
        if relative_target and not (path.parent / relative_target).exists():
            errors.append(f"{relative_name}: broken relative link {target!r}")


def _validate_readme_numbers(root: Path, errors: list[str]) -> None:
    try:
        readme = (root / "README.md").read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"README.md: cannot read file: {exc}")
        return
    required_fragments = (
        "Assertion Pass Rate (micro)",
        "Mean Eval Pass Rate (macro)",
        "**97.6%**",
        "**40 / 41**",
        "68.3%",
        "28 / 41",
        "**97.92%**",
        "70.42%",
        HISTORICAL_SOURCE_COMMIT,
        "were **not** used to",
    )
    for fragment in required_fragments:
        if fragment not in readme:
            errors.append(f"README.md: missing historical benchmark value/label {fragment!r}")


def _read_text(root: Path, relative_name: str, errors: list[str]) -> str | None:
    try:
        return (root / relative_name).read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"{relative_name}: cannot read file: {exc}")
        return None


def _validate_framework_entries(
    text: str,
    relative_name: str,
    heading_pattern: re.Pattern[str],
    expected_entries: dict[str, str],
    errors: list[str],
) -> None:
    entries = heading_pattern.findall(text)
    by_id: dict[str, list[str]] = {}
    for entry_id, name in entries:
        by_id.setdefault(entry_id, []).append(name.strip())

    for entry_id, expected_name in expected_entries.items():
        names = by_id.get(entry_id, [])
        if not names:
            errors.append(f"{relative_name}: missing mandatory framework entry {entry_id}")
        elif len(names) > 1:
            errors.append(f"{relative_name}: duplicate framework entry {entry_id}")
        elif names[0] != expected_name:
            errors.append(
                f"{relative_name}: {entry_id} name {names[0]!r} must be {expected_name!r}"
            )

    for entry_id in sorted(set(by_id) - set(expected_entries)):
        errors.append(f"{relative_name}: unknown framework entry {entry_id}")


def _validate_technique_catalog(text: str, errors: list[str]) -> set[str]:
    relative_name = "references/renguard-techniques.md"
    heading_pattern = re.compile(r"^## (RG-[^\s]+) — (.+)$", re.MULTILINE)
    heading_matches = list(heading_pattern.finditer(text))
    parsed_ids = [match.group(1) for match in heading_matches]

    for line in text.splitlines():
        if line.startswith("## RG-") and not heading_pattern.fullmatch(line):
            errors.append(f"{relative_name}: malformed RenGuard technique heading {line!r}")

    for technique_id in parsed_ids:
        if not TECHNIQUE_ID_PATTERN.fullmatch(technique_id):
            errors.append(f"{relative_name}: malformed RenGuard technique ID {technique_id!r}")
        if parsed_ids.count(technique_id) > 1:
            errors.append(f"{relative_name}: duplicate RenGuard technique ID {technique_id}")

    technique_ids = set(parsed_ids)
    for technique_id in sorted(REQUIRED_TECHNIQUE_IDS - technique_ids):
        errors.append(f"{relative_name}: missing required RenGuard technique {technique_id}")
    for technique_id in sorted(technique_ids - REQUIRED_TECHNIQUE_IDS):
        errors.append(f"{relative_name}: undocumented RenGuard technique ID {technique_id}")

    coverage_counts = {"CORE": 0, "PARTIAL": 0, "PLANNED": 0}
    for index, match in enumerate(heading_matches):
        technique_id = match.group(1)
        block_end = (
            heading_matches[index + 1].start()
            if index + 1 < len(heading_matches)
            else len(text)
        )
        block = text[match.end():block_end]
        for field_name in REQUIRED_TECHNIQUE_FIELDS:
            marker = f"- **{field_name}:**"
            if marker not in block:
                errors.append(f"{relative_name}: {technique_id} missing field {field_name!r}")
        coverage_match = re.search(
            r"^- \*\*Current RenGuard Coverage Status:\*\* (\S+)\s*$",
            block,
            re.MULTILINE,
        )
        if coverage_match and coverage_match.group(1) not in {"CORE", "PARTIAL", "PLANNED"}:
            errors.append(
                f"{relative_name}: {technique_id} has invalid coverage status "
                f"{coverage_match.group(1)!r}"
            )
        elif coverage_match:
            coverage_counts[coverage_match.group(1)] += 1
        expected_phase5_status = PHASE5_COVERAGE_STATUSES.get(technique_id)
        if (
            coverage_match
            and expected_phase5_status is not None
            and coverage_match.group(1) != expected_phase5_status
        ):
            errors.append(
                f"{relative_name}: {technique_id} Phase 5 coverage status must be "
                f"{expected_phase5_status}, found {coverage_match.group(1)}"
            )
        expected_phase6_status = PHASE6_COVERAGE_STATUSES.get(technique_id)
        if (
            coverage_match
            and expected_phase6_status is not None
            and coverage_match.group(1) != expected_phase6_status
        ):
            errors.append(
                f"{relative_name}: {technique_id} Phase 6 coverage status must be "
                f"{expected_phase6_status}, found {coverage_match.group(1)}"
            )

    if coverage_counts != PHASE6_COVERAGE_COUNTS:
        errors.append(
            f"{relative_name}: Phase 6 coverage counts must be {PHASE6_COVERAGE_COUNTS}, "
            f"found {coverage_counts}"
        )

    return technique_ids


def _validate_taxonomy(root: Path, errors: list[str]) -> int:
    texts: dict[str, str] = {}
    for relative_name in TAXONOMY_FILES:
        text = _read_text(root, relative_name, errors)
        if text is not None:
            texts[relative_name] = text

    llm_text = texts.get("references/owasp-llm-2026.md")
    if llm_text is not None:
        _validate_framework_entries(
            llm_text,
            "references/owasp-llm-2026.md",
            re.compile(r"^## (LLM(?:0[1-9]|10):2026) — (.+)$", re.MULTILINE),
            OWASP_LLM_2026,
            errors,
        )

    agentic_text = texts.get("references/owasp-agentic-2026.md")
    if agentic_text is not None:
        _validate_framework_entries(
            agentic_text,
            "references/owasp-agentic-2026.md",
            re.compile(r"^## (ASI(?:0[1-9]|10)) — (.+)$", re.MULTILINE),
            OWASP_AGENTIC_2026,
            errors,
        )

    technique_ids: set[str] = set()
    technique_text = texts.get("references/renguard-techniques.md")
    if technique_text is not None:
        technique_ids = _validate_technique_catalog(technique_text, errors)

    for relative_name in CURRENT_TAXONOMY_CONSUMERS:
        text = texts.get(relative_name)
        if text is None:
            text = _read_text(root, relative_name, errors)
        if text is None:
            continue
        for technique_id in set(re.findall(r"\bRG-[A-Z]{2}-[0-9]{3}\b", text)):
            if technique_id not in technique_ids:
                errors.append(f"{relative_name}: unknown RenGuard technique reference {technique_id}")
        for llm_id in set(re.findall(r"\bLLM[0-9]{2}:2026\b", text)):
            if llm_id not in OWASP_LLM_2026:
                errors.append(f"{relative_name}: unknown OWASP LLM 2026 mapping {llm_id}")
        for agentic_id in set(re.findall(r"\bASI[0-9]{2}\b", text)):
            if agentic_id not in OWASP_AGENTIC_2026:
                errors.append(f"{relative_name}: unknown OWASP Agentic 2026 mapping {agentic_id}")
        obsolete_ids = sorted(set(re.findall(r"\bLLM[0-9]{2}:2025\b", text)))
        for obsolete_id in obsolete_ids:
            errors.append(
                f"{relative_name}: obsolete {obsolete_id} is presented in current taxonomy content"
            )

    skill_text = _read_text(root, "SKILL.md", errors)
    if skill_text is not None:
        for relative_name in TAXONOMY_FILES[:4]:
            if f"({relative_name})" not in skill_text:
                errors.append(f"SKILL.md: missing taxonomy reference link {relative_name!r}")

    readme_text = _read_text(root, "README.md", errors)
    if readme_text is not None:
        for phrase in (
            "100% OWASP coverage",
            "full OWASP coverage",
            "complete OWASP compliance",
        ):
            if phrase.lower() in readme_text.lower():
                errors.append(f"README.md: unsupported empirical coverage claim {phrase!r}")
        if "Framework mapping support and empirical detection coverage are separate" not in readme_text:
            errors.append(
                "README.md: must distinguish framework mapping support from empirical coverage"
            )

    return len(technique_ids)


def _hardening_field(block: str, field_name: str) -> str | None:
    match = re.search(
        rf"^- \*\*{re.escape(field_name)}:\*\* (.+)$",
        block,
        re.MULTILINE,
    )
    return match.group(1).strip() if match else None


def _validate_hardening_catalog(
    root: Path,
    technique_ids: set[str],
    errors: list[str],
) -> int:
    relative_name = "references/hardening-patterns.md"
    text = _read_text(root, relative_name, errors)
    if text is None:
        return 0

    heading_pattern = re.compile(r"^### (RG-HARD-[^\s]+) — (.+)$", re.MULTILINE)
    headings = list(heading_pattern.finditer(text))
    parsed_ids = [match.group(1) for match in headings]

    for line in text.splitlines():
        if line.startswith("### RG-HARD-") and not heading_pattern.fullmatch(line):
            errors.append(f"{relative_name}: malformed hardening pattern heading {line!r}")
    for pattern_id in parsed_ids:
        if not HARDENING_ID_PATTERN.fullmatch(pattern_id):
            errors.append(f"{relative_name}: malformed hardening pattern ID {pattern_id!r}")
        if parsed_ids.count(pattern_id) > 1:
            errors.append(f"{relative_name}: duplicate hardening pattern ID {pattern_id}")

    pattern_ids = set(parsed_ids)
    parsed_layers: set[str] = set()
    for index, match in enumerate(headings):
        pattern_id = match.group(1)
        block_end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        block = text[match.end():block_end]
        for field_name in REQUIRED_HARDENING_FIELDS:
            if _hardening_field(block, field_name) is None:
                errors.append(f"{relative_name}: {pattern_id} missing field {field_name!r}")

        layer = _hardening_field(block, "Control Layer")
        strength = _hardening_field(block, "Strength")
        status = _hardening_field(block, "Implementation Status")
        functions_text = _hardening_field(block, "Security Functions")
        techniques_text = _hardening_field(block, "Applicable RenGuard Techniques")

        if layer is not None:
            parsed_layers.add(layer)
            if layer not in HARDENING_CONTROL_LAYERS:
                errors.append(
                    f"{relative_name}: {pattern_id} has invalid control layer {layer!r}"
                )
        if strength is not None and strength not in HARDENING_STRENGTHS:
            errors.append(
                f"{relative_name}: {pattern_id} has invalid control strength {strength!r}"
            )
        if status is not None and status not in IMPLEMENTATION_STATUSES:
            errors.append(
                f"{relative_name}: {pattern_id} has invalid implementation status {status!r}"
            )
        if functions_text is not None:
            functions = {value.strip() for value in functions_text.split(",")}
            invalid_functions = sorted(functions - SECURITY_FUNCTIONS)
            if not functions or invalid_functions:
                errors.append(
                    f"{relative_name}: {pattern_id} has invalid security function "
                    f"{', '.join(invalid_functions) if invalid_functions else functions_text!r}"
                )
        if techniques_text is not None:
            references = set(TECHNIQUE_ID_PATTERN.findall(techniques_text))
            if not references:
                errors.append(
                    f"{relative_name}: {pattern_id} must reference a RenGuard technique"
                )
            for technique_id in sorted(references - technique_ids):
                errors.append(
                    f"{relative_name}: {pattern_id} references unknown RenGuard technique "
                    f"{technique_id}"
                )
            broad_references = set(re.findall(r"RG-[A-Z]{2}-[0-9]{3}", techniques_text))
            for technique_id in sorted(broad_references - references):
                errors.append(
                    f"{relative_name}: {pattern_id} references unknown RenGuard technique "
                    f"{technique_id}"
                )

        if layer == "PROMPT" and strength not in {"GUIDANCE", "MODEL-ENFORCED"}:
            errors.append(
                f"{relative_name}: {pattern_id} prompt-only control is mislabeled as "
                "deterministic or platform enforced"
            )
        if status in {"PROPOSED", "PROJECTED"} and re.search(
            r"\b(?:this control|the control) (?:is|is already|has been) implemented\b",
            block,
            re.IGNORECASE,
        ):
            errors.append(
                f"{relative_name}: {pattern_id} proposed/projected control is described as implemented"
            )
        residual_risk = _hardening_field(block, "Residual Risk") or ""
        if re.search(
            r"\b(?:zero residual risk|no residual risk|eliminates? (?:all )?risk)\b",
            residual_risk,
            re.IGNORECASE,
        ):
            errors.append(f"{relative_name}: {pattern_id} claims zero residual risk")

    for layer in sorted(HARDENING_CONTROL_LAYERS - parsed_layers):
        errors.append(f"{relative_name}: missing required control layer {layer!r}")

    for fragment in (
        "prompt instructions are not a hard security boundary",
        "Pattern IDs are never reused or renumbered",
        "Detection is not prevention",
        "Projected residual risk if controls are implemented",
    ):
        if fragment.lower() not in text.lower():
            errors.append(f"{relative_name}: missing hardening rule {fragment!r}")

    hardening_consumers = (
        relative_name,
        "SKILL.md",
        *PHASE5_REFERENCE_FILES,
        *PHASE6_REFERENCE_FILES,
        *EXAMPLE_FILES,
    )
    for consumer in hardening_consumers:
        consumer_text = text if consumer == relative_name else _read_text(root, consumer, errors)
        if consumer_text is None:
            continue
        for reference in set(re.findall(r"RG-HARD-[A-Z]+-[0-9]+", consumer_text)):
            if not HARDENING_ID_PATTERN.fullmatch(reference):
                errors.append(f"{consumer}: malformed hardening pattern reference {reference!r}")
            elif reference not in pattern_ids:
                errors.append(f"{consumer}: unknown hardening pattern reference {reference}")
        if re.search(
            r"(?:type|just say)\s+[`\"'“”]?CONFIRM[`\"'“”]?"
            r"[^\n.]{0,80}(?:is|provides?|acts as|authorizes?)\s+"
            r"(?:authentication|authorization|the action)",
            consumer_text,
            re.IGNORECASE,
        ):
            errors.append(f"{consumer}: chat CONFIRM is presented as authentication/authorization")

    skill_text = _read_text(root, "SKILL.md", errors)
    if skill_text is not None:
        if "(references/hardening-patterns.md)" not in skill_text:
            errors.append("SKILL.md: missing hardening-patterns.md reference link")
        for fragment in (
            "**Prompt Mitigation:**",
            "**Deterministic Controls:**",
            "**Compensating Controls:**",
            "**Verification Guidance:**",
        ):
            if fragment not in skill_text:
                errors.append(f"SKILL.md: report template missing {fragment!r}")

    return len(pattern_ids)


def _validate_phase5_references(root: Path, errors: list[str]) -> None:
    rag_name, memory_name = PHASE5_REFERENCE_FILES
    rag_text = _read_text(root, rag_name, errors)
    memory_text = _read_text(root, memory_name, errors)
    skill_text = _read_text(root, "SKILL.md", errors)

    if rag_text is not None:
        normalized_rag = " ".join(rag_text.split())
        for concept in (
            "**Architecture:**",
            "**Trust:**",
            "**Provenance:**",
            "**Ingestion:**",
            "**Authorization:**",
            "**Tenant isolation:**",
            "**Chunk metadata:**",
            "**Retrieval:**",
            "**Query rewriting:**",
            "**Vector/index poisoning:**",
            "**Result authority:**",
            "**Caching:**",
            "**Tool escalation:**",
            "**Monitoring:**",
            "**Recovery:**",
        ):
            if concept not in rag_text:
                errors.append(f"{rag_name}: missing RAG checklist concept {concept!r}")
        for phrase in (
            "Retrieved content remains data",
            "Authorization should constrain retrieval **before** sensitive text enters model context",
            "Tenant identity comes from trusted session context",
            "does not claim to measure geometry",
            "UNKNOWN / INSUFFICIENT EVIDENCE — not zero",
        ):
            if phrase not in normalized_rag:
                errors.append(f"{rag_name}: missing Phase 5 RAG rule {phrase!r}")

    if memory_text is not None:
        normalized_memory = " ".join(memory_text.split())
        for concept in (
            "**Memory existence/type:**",
            "**Scope:**",
            "**Ownership:**",
            "**Read authorization:**",
            "**Write authorization:**",
            "**Provenance:**",
            "**Schema:**",
            "**Persistence:**",
            "**TTL:**",
            "**Cross-session:**",
            "**Cross-user:**",
            "**Cross-tenant:**",
            "**Shared agents:**",
            "**Conflict policy:**",
            "**Sensitive data:**",
            "**Action influence:**",
            "**Monitoring:**",
            "**Rollback/delete:**",
        ):
            if concept not in memory_text:
                errors.append(f"{memory_name}: missing memory checklist concept {concept!r}")
        for phrase in (
            "Memory is data, not security policy",
            "Tenant identity comes from trusted",
            "Monitoring is DETECT, not PREVENT",
            "UNKNOWN / INSUFFICIENT EVIDENCE — not zero",
        ):
            if phrase not in normalized_memory:
                errors.append(f"{memory_name}: missing Phase 5 memory rule {phrase!r}")

    if skill_text is not None:
        normalized_skill = " ".join(skill_text.split())
        for relative_name in PHASE5_REFERENCE_FILES:
            if f"({relative_name})" not in skill_text:
                errors.append(f"SKILL.md: missing conditional Phase 5 reference {relative_name!r}")
        for phrase in (
            "only when retrieval",
            "only when persistent",
            "Do not invent specialized findings",
        ):
            if phrase not in normalized_skill:
                errors.append(f"SKILL.md: missing conditional Phase 5 routing rule {phrase!r}")

    phase5_consumers = {
        rag_name: rag_text,
        memory_name: memory_text,
        "SKILL.md": skill_text,
    }
    for relative_name, text in phase5_consumers.items():
        if text is None:
            continue
        for forbidden_pattern, message in (
            (
                r"retrieved (?:text|content) is privileged authority",
                "retrieved text is described as privileged authority",
            ),
            (
                r"user-written memory is trusted system policy",
                "user-written memory is described as trusted system policy",
            ),
            (
                r"tenant identity (?:is|comes) from (?:the )?user prose",
                "tenant identity is based solely on user prose",
            ),
            (
                r"UNKNOWN[^\n]{0,80}(?:=|means|is|are treated as)\s*(?:numeric value )?(?:0|zero)",
                "UNKNOWN architecture facts are treated as zero",
            ),
        ):
            if re.search(forbidden_pattern, text, re.IGNORECASE):
                errors.append(f"{relative_name}: {message}")


def _validate_phase6_references(root: Path, errors: list[str]) -> None:
    tool_name, mcp_name, agentic_name = PHASE6_REFERENCE_FILES
    tool_text = _read_text(root, tool_name, errors)
    mcp_text = _read_text(root, mcp_name, errors)
    agentic_text = _read_text(root, agentic_name, errors)
    skill_text = _read_text(root, "SKILL.md", errors)
    example_text = _read_text(root, "examples/03-tool-using-agent-prompt.md", errors)

    if tool_text is not None:
        for capability_class in sorted(TOOL_CAPABILITY_CLASSES):
            if f"`{capability_class}`" not in tool_text:
                errors.append(f"{tool_name}: missing tool capability class {capability_class}")
        for concept in (
            "## Tool profile",
            "## Authority, descriptions, origin, and collisions",
            "## Inputs, outputs, errors, and parameters",
            "## Authorization, identity, credentials, and approval",
            "## Composition, code execution, budgets, and chains",
            "## Metadata and annotations",
        ):
            if concept not in tool_text:
                errors.append(f"{tool_name}: missing Phase 6 tool concept {concept!r}")
        for phrase in (
            "tool name does not prove identity",
            "Structured output remains untrusted content",
            "model judgment alone does not authorize a privileged tool call",
            "not hard enforcement",
            "material changes require fresh approval",
        ):
            if phrase not in " ".join(tool_text.split()):
                errors.append(f"{tool_name}: missing Phase 6 tool rule {phrase!r}")

    phase6_texts = {
        tool_name: tool_text,
        mcp_name: mcp_text,
        agentic_name: agentic_text,
        "SKILL.md": skill_text,
        "examples/03-tool-using-agent-prompt.md": example_text,
    }
    for relative_name, text in phase6_texts.items():
        if text is None:
            continue
        for capability_class in set(re.findall(r"\bTC[0-9]+\b", text)):
            if capability_class not in TOOL_CAPABILITY_CLASSES:
                errors.append(
                    f"{relative_name}: invalid tool capability class {capability_class}"
                )
        for forbidden_pattern, message in (
            (r"tool annotations? (?:are|is) (?:trusted|hard enforcement)",
             "tool annotations are treated as hard enforcement"),
            (r"(?:readOnlyHint|destructiveHint) guarantees?",
             "tool annotation is described as a guarantee"),
            (r"tool output (?:is|becomes) (?:a )?privileged instruction",
             "tool output is treated as privileged instructions"),
            (r"tool name (?:proves|is) identity", "tool name is treated as identity"),
            (r"model(?:-only| alone) authoriz(?:e|es) (?:a )?privileged tool",
             "model-only authorization is allowed for a privileged tool"),
            (r"sub-agents? (?:automatically )?inherit (?:all |every )?(?:parent )?privilege",
             "sub-agents automatically inherit privilege"),
            (r"self-reported agent (?:name|identity) is authenticated",
             "self-reported agent identity is treated as authenticated"),
            (r"approval applies to any parameters", "human approval is not parameter-bound"),
            (r"forward (?:the )?(?:client |access )?token (?:unchanged )?to (?:a |the )?downstream",
             "unsafe token passthrough is recommended"),
            (r"(?:native|current|stable)[^\n]{0,100}(?:Mcp-Session-Id|initialize)[^\n]{0,50}(?:is )?required",
             "obsolete MCP session lifecycle is required for the current stable version"),
            (r"(?:draft|proposal)[^\n]{0,80}\b(?:is|are) (?:a )?normative requirement",
             "draft/proposal is labeled as a normative MCP requirement"),
        ):
            if re.search(forbidden_pattern, text, re.IGNORECASE):
                errors.append(f"{relative_name}: {message}")

    if mcp_text is not None:
        version_match = re.search(
            r"\*\*Verified stable MCP version:\*\* `([^`]+)`", mcp_text
        )
        if version_match is None or version_match.group(1) != MCP_STABLE_VERSION:
            errors.append(
                f"{mcp_name}: verified stable MCP version must be {MCP_STABLE_VERSION}"
            )
        verified_match = re.search(r"\*\*Verified on:\*\* `([^`]+)`", mcp_text)
        if verified_match is None or verified_match.group(1) != MCP_VERIFIED_ON:
            errors.append(f"{mcp_name}: MCP verification date must be {MCP_VERIFIED_ON}")
        for phrase in (
            "official Model Context Protocol specification/project",
            "core is stateless at protocol level",
            "removed the legacy `initialize` / `notifications/initialized` exchange and `Mcp-Session-Id`",
            "Unsafe token passthrough is prohibited",
            "actual server origin, tool, normalized parameters",
            "JSON Schema 2020-12",
            "draft and experimental extensions remain non-normative",
        ):
            if phrase not in " ".join(mcp_text.split()):
                errors.append(f"{mcp_name}: missing Phase 6 MCP rule {phrase!r}")

    if agentic_text is not None:
        for phrase in (
            "marketing calls a product an “agent.”",
            "no parent privilege by default",
            "is not authenticated identity or authorization",
            "Monitoring is DETECT, not PREVENT",
            "Termination cannot rely on telling the model “please stop.”",
            "Material changes require fresh approval",
        ):
            if phrase not in " ".join(agentic_text.split()):
                errors.append(f"{agentic_name}: missing Phase 6 agentic rule {phrase!r}")

    if skill_text is not None:
        normalized_skill = " ".join(skill_text.split())
        for relative_name in PHASE6_REFERENCE_FILES:
            if f"({relative_name})" not in skill_text:
                errors.append(f"SKILL.md: missing conditional Phase 6 reference {relative_name!r}")
        for phrase in (
            "only when tools",
            "If MCP is evidenced",
            "only when autonomous planning",
            "Product branding alone does not establish an agentic architecture",
        ):
            if phrase not in normalized_skill:
                errors.append(f"SKILL.md: missing conditional Phase 6 routing rule {phrase!r}")

    if example_text is not None:
        for phrase in (
            "### Phase 6 Architecture and Tool Profile",
            "Tool names do not prove identity",
            "`TC4`",
            "host-assigned origin",
            "Sub-agents receive no parent privilege by default",
            "independent control plane",
        ):
            if phrase not in " ".join(example_text.split()):
                errors.append(
                    "examples/03-tool-using-agent-prompt.md: missing Phase 6 example rule "
                    f"{phrase!r}"
                )


def _validate_severity_pair(
    relative_name: str,
    score_text: str,
    severity: str,
    errors: list[str],
) -> None:
    try:
        score = float(score_text)
    except ValueError:
        errors.append(f"{relative_name}: invalid RenGuard Risk Score {score_text!r}")
        return
    if not 0.0 <= score <= 10.0:
        errors.append(f"{relative_name}: RenGuard Risk Score {score} is out of range 0.0–10.0")
        return
    try:
        expected_severity = severity_for_score(score)
    except ValueError as exc:
        errors.append(f"{relative_name}: {exc}")
        return
    if severity != expected_severity:
        errors.append(
            f"{relative_name}: risk score / severity mismatch: "
            f"{score:.1f} requires {expected_severity}, found {severity}"
        )


def _validate_risk_reference(root: Path, errors: list[str]) -> None:
    relative_name = "references/risk-scoring.md"
    text = _read_text(root, relative_name, errors)
    if text is None:
        return

    if "from **0.0 to 10.0**" not in text:
        errors.append(f"{relative_name}: score range 0.0–10.0 is not documented")
    if "It is not CVSS" not in text:
        errors.append(f"{relative_name}: non-CVSS disclaimer is missing")

    heading_pattern = re.compile(
        r"^### ([A-Z]) — (.+) \(weight ([0-9]+)%\)$",
        re.MULTILINE,
    )
    headings = list(heading_pattern.finditer(text))
    parsed_symbols: set[str] = set()
    parsed_weights: list[int] = []
    parsed_weight_by_symbol: dict[str, int] = {}
    for index, match in enumerate(headings):
        symbol = match.group(1)
        name = match.group(2)
        weight = int(match.group(3))
        parsed_symbols.add(symbol)
        parsed_weights.append(weight)
        parsed_weight_by_symbol[symbol] = weight
        expected = RISK_DIMENSIONS.get(symbol)
        if expected is None:
            errors.append(f"{relative_name}: unknown scoring dimension symbol {symbol!r}")
        elif (name, weight) != expected[1:]:
            errors.append(
                f"{relative_name}: scoring dimension {symbol} must be "
                f"{expected[1]} at weight {expected[2]}%"
            )
        block_end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        block = text[match.end():block_end]
        documented_values = {
            int(value)
            for value in re.findall(r"^\| ([0-4]) \|", block, re.MULTILINE)
        }
        if documented_values != {0, 1, 2, 3, 4}:
            errors.append(
                f"{relative_name}: scoring dimension {symbol} must define values 0 through 4"
            )

    for symbol, (_, name, _) in RISK_DIMENSIONS.items():
        if symbol not in parsed_symbols:
            errors.append(f"{relative_name}: missing scoring dimension {name!r} ({symbol})")
    if len(parsed_symbols) != len(headings):
        errors.append(f"{relative_name}: duplicate scoring dimension heading")
    if sum(parsed_weights) != 100:
        errors.append(
            f"{relative_name}: scoring dimension weights must total 100, found {sum(parsed_weights)}"
        )
    exposure_total = sum(parsed_weight_by_symbol.get(symbol, 0) for symbol in EXPOSURE_SYMBOLS)
    impact_total = sum(parsed_weight_by_symbol.get(symbol, 0) for symbol in IMPACT_SYMBOLS)
    if exposure_total != 40:
        errors.append(
            f"{relative_name}: Exploitability / Exposure component weights must total 40, "
            f"found {exposure_total}"
        )
    if impact_total != 60:
        errors.append(
            f"{relative_name}: Impact / Consequence component weights must total 60, "
            f"found {impact_total}"
        )

    severity_rows = re.findall(
        r"^\| (INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL) "
        r"\| ([0-9]+\.[0-9]) \| ([0-9]+\.[0-9]) \|$",
        text,
        re.MULTILINE,
    )
    parsed_bands: dict[str, tuple[float, float]] = {}
    for label, minimum_text, maximum_text in severity_rows:
        if label in parsed_bands:
            errors.append(f"{relative_name}: duplicate severity band {label}")
        parsed_bands[label] = (float(minimum_text), float(maximum_text))
    for label in SEVERITY_BANDS:
        if label not in parsed_bands:
            errors.append(f"{relative_name}: missing severity band {label}")

    ordered_bands = sorted(parsed_bands.items(), key=lambda item: item[1][0])
    if ordered_bands:
        if ordered_bands[0][1][0] != 0.0 or ordered_bands[-1][1][1] != 10.0:
            errors.append(f"{relative_name}: severity bands must cover 0.0 through 10.0")
        for (_, (_, previous_max)), (label, (current_min, _)) in zip(
            ordered_bands, ordered_bands[1:]
        ):
            if current_min <= previous_max:
                errors.append(f"{relative_name}: severity bands overlap at {label}")
            elif not math.isclose(current_min, previous_max + 0.1, abs_tol=1e-9):
                errors.append(f"{relative_name}: severity bands leave a gap before {label}")
    for label, expected_band in SEVERITY_BANDS.items():
        if label in parsed_bands and parsed_bands[label] != expected_band:
            errors.append(
                f"{relative_name}: {label} severity band must be "
                f"{expected_band[0]:.1f}–{expected_band[1]:.1f}"
            )

    confidence_headings = set(
        re.findall(r"^### Confidence: (HIGH|MEDIUM|LOW)$", text, re.MULTILINE)
    )
    if confidence_headings != CONFIDENCE_LEVELS:
        errors.append(
            f"{relative_name}: confidence levels must be exactly HIGH, MEDIUM, and LOW"
        )

    exploitability_section = text.split("## Exploitability labels", 1)
    parsed_exploitability: set[str] = set()
    if len(exploitability_section) == 2:
        section = exploitability_section[1].split("\n## ", 1)[0]
        parsed_exploitability = set(
            re.findall(
                r"^\| (TRIVIAL|EASY|MODERATE|HARD|CONDITIONAL) \|",
                section,
                re.MULTILINE,
            )
        )
    if parsed_exploitability != EXPLOITABILITY_LABELS:
        errors.append(
            f"{relative_name}: exploitability labels must define TRIVIAL, EASY, "
            "MODERATE, HARD, and CONDITIONAL"
        )

    for fragment in (
        "RenGuard Risk Score = round_half_up(weighted_total / 40, 1)",
        "KNOWN ZERO — numeric value 0",
        "NOT APPLICABLE — numeric value 0",
        "UNKNOWN / INSUFFICIENT EVIDENCE — no automatic numeric value",
        "UNKNOWN must never be silently",
        "The current score reflects only verified",
        "RenGuard does not estimate empirical exploit probability",
        "Exploitability / Exposure Component (40%)",
        "Impact / Consequence Component (60%)",
        "| **Total** | **Exploitability / Exposure Component** | **40** |",
        "| **Total** | **Impact / Consequence Component** | **60** |",
        "does not mean that a hard-to-detect attack is more",
        "Per-report finding IDs use `RG-F-001`",
        "They are not taxonomy identifiers",
        "Overall risk is not an average",
        "Projected residual risk if",
    ):
        if fragment not in text:
            errors.append(f"{relative_name}: missing scoring rule {fragment!r}")

    for forbidden_phrase in (
        "absent dimensions " "contribute zero",
        "unknown " "= 0",
        "missing " "= 0",
    ):
        if forbidden_phrase in text.lower():
            errors.append(
                f"{relative_name}: UNKNOWN must not be documented as equivalent to zero"
            )
    if re.search(r"UNKNOWN[^\n]{0,100}numeric value 0", text, re.IGNORECASE):
        errors.append(f"{relative_name}: UNKNOWN must not be documented as equivalent to zero")

    for consumer in ("SKILL.md", "README.md", relative_name, *EXAMPLE_FILES):
        consumer_text = text if consumer == relative_name else _read_text(root, consumer, errors)
        if consumer_text is not None and re.search(r"\bD[0-9]+\b", consumer_text):
            errors.append(
                f"{consumer}: stale numbered risk-dimension alias; use canonical symbols"
            )

    case_pattern = re.compile(
        r"^\| ([A-E]) — [^|]+ \| `([0-4](?:,[0-4]){11})` "
        r"\| ([0-9]+\.[0-9]) \| (INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL) \|$",
        re.MULTILINE,
    )
    parsed_cases = {match.group(1): match.groups()[1:] for match in case_pattern.finditer(text)}
    for case_id, (expected_vector, expected_score, expected_severity) in RISK_CASES.items():
        parsed = parsed_cases.get(case_id)
        if parsed is None:
            errors.append(f"{relative_name}: missing deterministic scoring case {case_id}")
            continue
        vector = tuple(int(value) for value in parsed[0].split(","))
        score = float(parsed[1])
        severity = parsed[2]
        if vector != expected_vector:
            errors.append(f"{relative_name}: scoring case {case_id} vector changed")
        calculated = calculate_risk_score(vector)
        if score != calculated or score != expected_score:
            errors.append(
                f"{relative_name}: scoring case {case_id} expected score must be "
                f"{calculated:.1f}"
            )
        if severity != expected_severity or severity != severity_for_score(score):
            errors.append(f"{relative_name}: scoring case {case_id} severity mismatch")

    skill_text = _read_text(root, "SKILL.md", errors)
    if skill_text is not None:
        if "(references/risk-scoring.md)" not in skill_text:
            errors.append("SKILL.md: missing risk-scoring.md reference link")
        for fragment in (
            "**RenGuard Risk Score:**",
            "#### RG-F-NNN",
            "**Scoring Dimensions (0–4):**",
            "**Evidence State / Sensitivity:**",
            "**Confidence:**",
        ):
            if fragment not in skill_text:
                errors.append(f"SKILL.md: report template missing {fragment!r}")


def _validate_example_report(
    root: Path,
    relative_name: str,
    technique_ids: set[str],
    errors: list[str],
) -> None:
    text = _read_text(root, relative_name, errors)
    if text is None:
        return
    lines = text.splitlines()
    try:
        header_index = lines.index(
            "| Finding ID | RenGuard Technique | Risk Score | Severity | Confidence | Exploitability | Location |"
        )
    except ValueError:
        errors.append(f"{relative_name}: missing Phase 3 vulnerability table")
        return

    table_findings: dict[str, tuple[str, float, str]] = {}
    for line in lines[header_index + 2:]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 7:
            errors.append(f"{relative_name}: malformed vulnerability table row {line!r}")
            continue
        finding_id = cells[0].strip("`")
        if not re.fullmatch(r"RG-F-[0-9]{3}", finding_id):
            errors.append(f"{relative_name}: malformed finding ID {finding_id!r}")
            continue
        if finding_id in table_findings:
            errors.append(f"{relative_name}: duplicate finding ID {finding_id}")
        technique_match = TECHNIQUE_ID_PATTERN.search(cells[1])
        if technique_match is None:
            errors.append(f"{relative_name}: {finding_id} missing valid technique ID")
            continue
        technique_id = technique_match.group(0)
        if technique_id not in technique_ids:
            errors.append(f"{relative_name}: {finding_id} uses unknown technique {technique_id}")
        score_text, severity, confidence, exploitability = cells[2:6]
        _validate_severity_pair(relative_name, score_text, severity, errors)
        if confidence not in CONFIDENCE_LEVELS:
            errors.append(f"{relative_name}: invalid confidence value {confidence!r}")
        if exploitability not in EXPLOITABILITY_LABELS:
            errors.append(f"{relative_name}: invalid exploitability label {exploitability!r}")
        try:
            score = float(score_text)
        except ValueError:
            score = -1.0
        table_findings[finding_id] = (technique_id, score, severity)

    heading_pattern = re.compile(
        r"^#### (RG-F-[0-9]{3}) — .+ \[(INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL)\]$",
        re.MULTILINE,
    )
    headings = list(heading_pattern.finditer(text))
    heading_ids = {match.group(1) for match in headings}
    if heading_ids != set(table_findings):
        errors.append(
            f"{relative_name}: detailed finding IDs must match the vulnerability table"
        )
    for line in lines:
        if line.startswith("#### RG-") and not heading_pattern.fullmatch(line):
            errors.append(f"{relative_name}: malformed finding heading {line!r}")

    for index, match in enumerate(headings):
        finding_id = match.group(1)
        block_end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        block = text[match.end():block_end]
        score_match = re.search(
            r"^\*\*RenGuard Risk Score:\*\* ([0-9]+\.[0-9]) "
            r"(INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL)$",
            block,
            re.MULTILINE,
        )
        vector_match = re.search(
            r"^\*\*Scoring Dimensions \(0–4\):\*\* "
            r"E=([0-4]), P=([0-4]), H=([0-4]), V=([0-4]), T=([0-4]), D=([0-4]), "
            r"A=([0-4]), S=([0-4]), B=([0-4]), R=([0-4]), X=([0-4]), G=([0-4])$",
            block,
            re.MULTILINE,
        )
        if score_match is None or vector_match is None:
            errors.append(f"{relative_name}: {finding_id} missing score or dimension vector")
            continue
        for required_field in (
            "Attack Technique",
            "Security Weakness",
            "Preconditions",
            "Impact",
        ):
            if f"**{required_field}:**" not in block:
                errors.append(
                    f"{relative_name}: {finding_id} missing {required_field.lower()}"
                )
        score = float(score_match.group(1))
        severity = score_match.group(2)
        vector = tuple(int(value) for value in vector_match.groups())
        calculated = calculate_risk_score(vector)
        if score != calculated:
            errors.append(
                f"{relative_name}: {finding_id} score {score:.1f} does not match "
                f"dimension formula result {calculated:.1f}"
            )
        table_entry = table_findings.get(finding_id)
        if table_entry is not None and (score, severity) != table_entry[1:]:
            errors.append(f"{relative_name}: {finding_id} detail/table score mismatch")
        if severity in {"HIGH", "CRITICAL"} and "**Blast Radius:**" not in block:
            errors.append(f"{relative_name}: {finding_id} must explicitly assess blast radius")

    for score_text, severity in re.findall(
        r"^\*\*(?:Overall Risk|Chain Risk):\*\* ([0-9]+\.[0-9]) "
        r"(INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL)",
        text,
        re.MULTILINE,
    ):
        _validate_severity_pair(relative_name, score_text, severity, errors)
    for score_text, severity in re.findall(
        r"^\| (?:Before remediation|After prompt-only hardening|After runtime enforcement) "
        r"\| ([0-9]+\.[0-9]) \| (INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL) \|",
        text,
        re.MULTILINE,
    ):
        _validate_severity_pair(relative_name, score_text, severity, errors)

    before_and_report = text.split("## AUDIT REPORT", 1)
    if len(before_and_report) == 2:
        synthetic_secrets = set(
            re.findall(
                r"\b(?:sk|pk)_[A-Za-z0-9_]{16,}\b|\bBearer [A-Za-z0-9._-]{16,}\b",
                before_and_report[0],
            )
        )
        for secret in synthetic_secrets:
            if secret in before_and_report[1]:
                errors.append(
                    f"{relative_name}: full synthetic secret is reproduced in the audit report"
                )


def _validate_phase3_examples(
    root: Path,
    technique_ids: set[str],
    errors: list[str],
) -> None:
    for relative_name in EXAMPLE_FILES:
        _validate_example_report(root, relative_name, technique_ids, errors)


def validate_repository(root: Path) -> ValidationResult:
    root = root.resolve()
    validation = ValidationResult()
    eval_data = _load_json(root / "evals" / "evals.json", "eval definitions", validation.errors)
    benchmark_data = _load_json(
        root / "benchmarks" / "benchmark.json", "benchmark artifact", validation.errors
    )

    eval_ids: dict[Any, str] = {}
    if eval_data is not None:
        eval_ids = _validate_evals(root, eval_data, validation.errors)
        validation.eval_count = len(eval_ids)
    if benchmark_data is not None:
        metrics, validation.run_count = _validate_benchmark(
            benchmark_data, eval_ids, validation.errors
        )
        validation.metrics = metrics

    _validate_readme_numbers(root, validation.errors)
    validation.technique_count = _validate_taxonomy(root, validation.errors)
    validation.hardening_pattern_count = _validate_hardening_catalog(
        root, REQUIRED_TECHNIQUE_IDS, validation.errors
    )
    _validate_phase5_references(root, validation.errors)
    _validate_phase6_references(root, validation.errors)
    _validate_risk_reference(root, validation.errors)
    _validate_phase3_examples(root, REQUIRED_TECHNIQUE_IDS, validation.errors)
    for relative_name in ("README.md", "SKILL.md", *TAXONOMY_FILES, *EXAMPLE_FILES):
        _validate_markdown_links(root, relative_name, validation.errors)
    return validation


def _format_rate(value: float) -> str:
    return f"{value * 100:.2f}%"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the parent of scripts/)",
    )
    args = parser.parse_args(argv)
    result = validate_repository(args.root)

    if result.errors:
        print(f"Repository validation FAILED with {len(result.errors)} error(s):", file=sys.stderr)
        for error in result.errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("Repository validation PASSED")
    print(f"- eval definitions: {result.eval_count}")
    print(f"- benchmark runs: {result.run_count}")
    print(f"- RenGuard techniques: {result.technique_count}")
    print(f"- hardening patterns: {result.hardening_pattern_count}")
    for configuration in CONFIGURATIONS:
        metrics = result.metrics[configuration]
        assertions = metrics["assertions"]
        print(
            f"- {configuration}: {assertions['passed']}/{assertions['total']} assertions "
            f"({_format_rate(metrics['assertion_pass_rate'])} micro); "
            f"{_format_rate(metrics['mean_eval_pass_rate']['mean'])} macro"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
