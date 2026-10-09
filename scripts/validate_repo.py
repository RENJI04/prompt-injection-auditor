#!/usr/bin/env python3
"""Validate RenGuard's taxonomy, evals, and historical benchmark artifact."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote


ROUNDING_TOLERANCE = 0.000051
CONFIGURATIONS = ("with_skill", "without_skill")
HISTORICAL_SOURCE_COMMIT = "c2e8de497b7550ca3ca4df081efae27ddd28d582"
CURRENT_CORPUS_STATUS = "current_renguard_v2_alpha"
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
TAXONOMY_FILES = (
    "references/vulnerability-taxonomy.md",
    "references/renguard-techniques.md",
    "references/owasp-llm-2026.md",
    "references/owasp-agentic-2026.md",
    "references/hardening-patterns.md",
)
CURRENT_TAXONOMY_CONSUMERS = (
    "README.md",
    "SKILL.md",
    *TAXONOMY_FILES,
    "examples/01-chatbot-prompt.md",
    "examples/02-rag-agent-prompt.md",
    "examples/03-tool-using-agent-prompt.md",
)


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)
    metrics: dict[str, dict[str, float | int]] = field(default_factory=dict)
    eval_count: int = 0
    run_count: int = 0
    technique_count: int = 0


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
    for relative_name in ("README.md", "SKILL.md", *TAXONOMY_FILES):
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
