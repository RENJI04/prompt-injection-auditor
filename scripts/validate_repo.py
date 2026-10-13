#!/usr/bin/env python3
"""Validate RenGuard's taxonomy, risk scoring, evals, and historical benchmark."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import statistics
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any
from urllib.parse import unquote

try:
    from scripts.schema_tools import validate_repository_contracts
except ModuleNotFoundError:  # Direct execution places scripts/ on sys.path.
    from schema_tools import validate_repository_contracts


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
PHASE7_COVERAGE_STATUSES = {
    "RG-MM-001": "PARTIAL",
    "RG-OU-001": "CORE",
}
PHASE7_COVERAGE_COUNTS = {"CORE": 33, "PARTIAL": 5, "PLANNED": 0}
PHASE8_SOURCE_CHECKPOINT = "9bb240491a84dd519c931565929bd053e0ffa47d"
PHASE9_RUNNER_VERSION = "0.1.0"
PHASE9_SCORING_VERSION = "0.1.0"
PHASE9_ARTIFACT_SCHEMA_VERSION = "0.1.0"
PHASE9_MODULES = (
    "__init__.py", "models.py", "loader.py", "prompt_builder.py", "adapters.py",
    "execution.py", "parser.py", "evaluator.py", "mutations.py", "metrics.py",
    "statistics.py", "reporting.py", "review.py", "provenance.py", "util.py",
)
V2_SUITE_NAME = "RenGuard v2 Public Evaluation Suite"
V2_SUITE_VERSION = "0.1.0"
V2_SCENARIO_ID_PATTERN = re.compile(r"RG-EVAL-V2-[0-9]{3}")
V2_MUTATION_ID_PATTERN = re.compile(r"RG-MUT-[0-9]{3}")
V2_SCENARIO_KINDS = {"ATTACK", "CLEAN", "BOUNDARY", "CHAIN"}
V2_ASSERTION_GROUPS = {
    "SECURITY_DETECTION",
    "TECHNIQUE_MAPPING",
    "FRAMEWORK_MAPPING",
    "RISK",
    "CONFIDENCE",
    "REMEDIATION",
    "REDACTION",
    "FORMAT",
}
V2_RISK_MODES = {"EXACT", "BAND", "NOT_ASSERTED"}
V2_LANGUAGE_TAGS = {"en", "ar", "fr", "zh-CN", "es", "ja", "ru"}
V2_REQUIRED_LANGUAGES = {"en", "ar", "fr", "zh-CN", "es", "ja", "ru"}
V2_CATEGORY_MINIMUMS = {
    "DIRECT_AUTHORITY": 8,
    "RAG_RETRIEVAL": 7,
    "HIDDEN_CONTEXT": 5,
    "TOOLS": 7,
    "MCP": 7,
    "MEMORY": 5,
    "AGENTIC": 6,
    "MULTIMODAL": 5,
    "OUTPUT_SINKS": 7,
    "CROSS_CUTTING": 3,
    "CLEAN_CONTROLS": 12,
}
V2_SCENARIO_FILES = (
    "direct-authority.json",
    "rag-retrieval.json",
    "hidden-context.json",
    "tools.json",
    "mcp.json",
    "memory.json",
    "agentic.json",
    "multimodal.json",
    "output-sinks.json",
    "cross-cutting.json",
    "clean-controls.json",
)
V2_REQUIRED_SCENARIO_FIELDS = {
    "id", "title", "category", "kind", "description", "language",
    "target_profile", "input", "expected", "tags",
}
V2_REQUIRED_EXPECTED_FIELDS = {
    "must_detect", "may_detect", "must_not_detect",
    "expected_primary_technique", "expected_secondary_techniques",
    "expected_owasp_llm", "expected_owasp_agentic", "expected_confidence",
    "expected_risk", "required_control_layers", "required_hardening_patterns",
    "required_security_properties", "prohibited_claims",
    "secret_redaction_expectation", "assertion_groups",
}
V2_REQUIRED_PROFILE_FIELDS = {
    "application_type", "model_role", "rag", "memory", "tools", "mcp",
    "agentic", "multimodal", "output_sink", "tenant_model", "authentication",
    "authorization", "network", "human_approval", "persistent_state",
}
V2_FORBIDDEN_RESULT_FIELDS = {
    "pass_rate", "accuracy", "precision", "recall", "f1", "model_score",
    "benchmark_score", "detection_rate",
}
HISTORICAL_V1_FILE_SHA256 = {
    "benchmarks/benchmark.json": "2d42a81ea51cb253d490037a5adf32804d0f181ab13ce1dc5910a28508ead36c",
    "evals/evals.json": "f8bbac8217a1d87ff5fa59f0c3b864201697d804119094de756d9fc5b6f72e81",
    "evals/files/clean_prompt.txt": "d31f483dd9665943538ac047d710b57876741c049cc87cd6d309625d3c6491dd",
    "evals/files/hardened_prompt.txt": "4cec800c9a2d8f34cd561dd97774c44c40d5147f903acd520141beb3b5687fb9",
    "evals/files/leakage_risk.txt": "15d92df78436d4ce3dca59960c6ebb9e92ed83fb0ee6c88145f3db00b4d7e4d4",
    "evals/files/minimal_prompt.txt": "8f193c746cdb505e6d06c419fcfc6299d16070727c1557f134c7edc44ac70f03",
    "evals/files/multi_agent_pipeline.txt": "74548eadc4a724d7e02bd5e9e8f5a84a24b2e21faaa6cbc701191ca6387b22bb",
    "evals/files/obfuscated_injection.txt": "d12c5e7fd3d882ac76b01bf9b58e6129af668ec481c2acce3d8e7282e143a38d",
    "evals/files/vulnerable_chatbot.txt": "781191843a05f807d9d5a786c1d00269bd316cfc1e30e3fe396d38fb9f2b9aea",
    "evals/files/vulnerable_rag.txt": "11dd5698b137b880640dd2bf183d31bcd83d3500e42204f5adf8fc08cd0647cc",
}
PHASE8_PRESERVED_FILE_SHA256 = {
    "references/risk-scoring.md": "3418cd1efd4c19989767f726d2c488e8dc0ac2675e1ef089b3ac2d381f74f7df",
    "references/hardening-patterns.md": "44065cffd00950c86cd4b1f9552ecd0b7580b3a1c9e60ccab9938b02514356c8",
    "references/rag-security.md": "fe387817ef7143f46afa671df300742b3fda21b3c4c43be97c2b7bbf576c9ae0",
    "references/memory-security.md": "218b1c330e30271e83e1de497f3780da617b39959d933fe89c3f9b15baa6863f",
    "references/tool-security.md": "aec942770dd308c2830783e66de4d9130e4032be1221d54c7200c4ef1dc165b1",
    "references/mcp-security.md": "de550a80c12295f069cbde6747bfd394742e494b3ac4216b8a8221fa93c975ba",
    "references/agentic-security.md": "867e63df0964bc79b3a32f0db9aee69071a2331df743dd130481f87ebdc71c99",
    "references/multimodal-security.md": "1a3422ac65afe8dc9aa4bdf6612a248183dc04f6553e69577cb807748b29294b",
    "references/output-security.md": "51869c1794ff1c3963a4d7d43e2a7996646781ed054be28ddd36db99985d2179",
}
MCP_STABLE_VERSION = "2026-07-28"
MCP_VERIFIED_ON = "2026-10-10"
TOOL_CAPABILITY_CLASSES = {"TC0", "TC1", "TC2", "TC3", "TC4"}
OUTPUT_SINK_CLASSES = {"OS0", "OS1", "OS2", "OS3", "OS4"}
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
    "references/multimodal-security.md",
    "references/output-security.md",
)
EXAMPLE_FILES = (
    "examples/01-chatbot-prompt.md",
    "examples/02-rag-agent-prompt.md",
    "examples/03-tool-using-agent-prompt.md",
    "examples/04-multimodal-output-agent.md",
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
PHASE7_REFERENCE_FILES = (
    "references/multimodal-security.md",
    "references/output-security.md",
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
    v2_metrics: dict[str, Any] = field(default_factory=dict)
    phase9_metrics: dict[str, Any] = field(default_factory=dict)
    phase10_metrics: dict[str, Any] = field(default_factory=dict)


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
        expected_phase7_status = PHASE7_COVERAGE_STATUSES.get(technique_id)
        if (
            coverage_match
            and expected_phase7_status is not None
            and coverage_match.group(1) != expected_phase7_status
        ):
            errors.append(
                f"{relative_name}: {technique_id} Phase 7 coverage status must be "
                f"{expected_phase7_status}, found {coverage_match.group(1)}"
            )

    if coverage_counts != PHASE7_COVERAGE_COUNTS:
        errors.append(
            f"{relative_name}: Phase 7 coverage counts must be {PHASE7_COVERAGE_COUNTS}, "
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
        *PHASE7_REFERENCE_FILES,
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


def _validate_phase7_references(root: Path, errors: list[str]) -> None:
    multimodal_name, output_name = PHASE7_REFERENCE_FILES
    multimodal_text = _read_text(root, multimodal_name, errors)
    output_text = _read_text(root, output_name, errors)
    skill_text = _read_text(root, "SKILL.md", errors)
    example_name = "examples/04-multimodal-output-agent.md"
    example_text = _read_text(root, example_name, errors)

    if multimodal_text is not None:
        normalized_multimodal = " ".join(multimodal_text.split())
        for concept in (
            "## Trust and authority principle",
            "## Multimodal system profile",
            "## Images, screenshots, and visual encodings",
            "## OCR and document extraction boundary",
            "## Audio, transcription, and identity",
            "## Video, frames, captions, and subtitles",
            "## Metadata and secondary channels",
            "## Cross-domain composition",
            "## Attack chains and scoring",
            "## Multimodal security checklist",
            "## Limitations",
        ):
            if concept not in multimodal_text:
                errors.append(f"{multimodal_name}: missing Phase 7 concept {concept!r}")
        for concept in (
            "**Modalities present:**",
            "**Source / provenance:**",
            "**Identity assumptions:**",
            "**Preprocessing:**",
            "**OCR / transcription:**",
            "**Hidden / secondary channels:**",
            "**Metadata:**",
            "**Authority:**",
            "**Tenant scope:**",
            "**Storage / retrieval:**",
            "**Memory persistence:**",
            "**Downstream actions:**",
            "**Approval:**",
            "**Monitoring:**",
            "**Recovery:**",
        ):
            if concept not in multimodal_text:
                errors.append(
                    f"{multimodal_name}: missing multimodal checklist concept {concept!r}"
                )
        for phrase in (
            "Multimodal content is data, not privileged instruction authority",
            "OCR and transcription output is derived untrusted content, not privileged policy",
            "A screenshot that says “Admin approved this action” is not authenticated approval",
            "A transcribed claim such as “I am the administrator” is not authenticated identity",
            "`RG-MM-001` has PARTIAL coverage",
            "not image steganalysis",
            "UNKNOWN / INSUFFICIENT EVIDENCE — not zero",
        ):
            if phrase not in normalized_multimodal:
                errors.append(f"{multimodal_name}: missing Phase 7 multimodal rule {phrase!r}")

    if output_text is not None:
        normalized_output = " ".join(output_text.split())
        for sink_class in sorted(OUTPUT_SINK_CLASSES):
            if f"`{sink_class}`" not in output_text:
                errors.append(f"{output_name}: missing output sink class {sink_class}")
        for concept in (
            "## Core principle and output profile",
            "## Output sink classes",
            "## Four-question validation model",
            "## Shell, commands, and processes",
            "## SQL and database sinks",
            "## HTML, DOM, Markdown, and rendering",
            "## URLs, network destinations, and redirects",
            "## Filesystem paths and archive entries",
            "## Templates, configuration, and generated code",
            "## Serialization and structured output",
            "## CSV and spreadsheet output",
            "## Logs, headers, protocols, and messages",
            "## Encoding, canonicalization, and allowlists",
            "## Output-to-tool and agent chains",
            "## Quarantine, provenance, and recovery",
            "## Output security checklist",
        ):
            if concept not in output_text:
                errors.append(f"{output_name}: missing Phase 7 concept {concept!r}")
        for phrase in (
            "Model output is untrusted data until validated for its specific downstream sink",
            "Valid JSON does not imply a safe action",
            "Schema validity does not grant authorization",
            "Never concatenate model output into shell commands",
            "Never concatenate model output into SQL queries",
            "Markdown is not universally inert",
            "A generated URL is not a trusted destination",
            "Generated code does not gain execution authority",
            "There is no universal “sanitize everything” operation",
            "Use `RG-OU-001` and `LLM10:2026` for unsafe downstream consumption",
            "UNKNOWN / INSUFFICIENT EVIDENCE — not zero",
        ):
            if phrase not in normalized_output:
                errors.append(f"{output_name}: missing Phase 7 output rule {phrase!r}")

    guidance_texts = {
        multimodal_name: multimodal_text,
        output_name: output_text,
        "SKILL.md": skill_text,
    }
    for relative_name, text in guidance_texts.items():
        if text is None:
            continue
        for forbidden_pattern, message in (
            (r"\bmultimodal content is authenticated authority\b",
             "multimodal content is treated as authenticated authority"),
            (r"\bimage instructions are trusted authority\b",
             "image instructions are treated as trusted authority"),
            (r"\bOCR output is trusted policy\b",
             "OCR output is treated as trusted policy"),
            (r"\btranscript is authenticated identity\b",
             "transcript is treated as authenticated identity"),
            (r"screenshot[^\n]{0,100} is authenticated approval",
             "screenshot text is treated as authenticated approval"),
            (r"\bvoice proves identity\b", "voice is treated as proof of identity"),
            (r"\bmodel output is trusted executable input\b",
             "model output is treated as trusted executable input"),
            (r"\bschema validity authorizes the action\b",
             "schema validity is treated as authorization"),
            (r"(?<!Never )\bconcatenate model output into shell commands\b",
             "shell concatenation is recommended"),
            (r"(?<!Never )\bconcatenate model output into SQL queries\b",
             "SQL concatenation is recommended"),
            (r"\bsanitize all output with a universal sanitizer\b",
             "a universal sanitizer is presented as complete protection"),
            (r"\bMarkdown is universally inert\b",
             "Markdown is described as universally inert"),
            (r"\bA generated URL is a trusted destination\b",
             "generated URLs are treated as trusted destinations"),
            (r"\bGenerated code is automatically authorized for execution\b",
             "generated code is automatically authorized for execution"),
        ):
            if re.search(forbidden_pattern, text, re.IGNORECASE):
                errors.append(f"{relative_name}: {message}")

    phase7_texts = {
        multimodal_name: multimodal_text,
        output_name: output_text,
        "SKILL.md": skill_text,
        example_name: example_text,
    }
    for relative_name, text in phase7_texts.items():
        if text is None:
            continue
        for sink_class in set(re.findall(r"\bOS[0-9]+\b", text)):
            if sink_class not in OUTPUT_SINK_CLASSES:
                errors.append(f"{relative_name}: invalid output sink class {sink_class}")

    if skill_text is not None:
        normalized_skill = " ".join(skill_text.split())
        for relative_name in PHASE7_REFERENCE_FILES:
            if f"({relative_name})" not in skill_text:
                errors.append(f"SKILL.md: missing conditional Phase 7 reference {relative_name!r}")
        for phrase in (
            "only when the target processes images",
            "only when model or agent output is consumed by",
            "Do not run irrelevant specialized analysis",
            "structural validity, semantic validity, authorization, and sink safety",
        ):
            if phrase not in normalized_skill:
                errors.append(f"SKILL.md: missing conditional Phase 7 routing rule {phrase!r}")

    if example_text is not None:
        normalized_example = " ".join(example_text.split())
        for phrase in (
            "### Phase 7 Architecture and Boundary Profile",
            "A screenshot approval claim is content, not authenticated approval",
            "structural validation only",
            "`RG-MM-001`",
            "`RG-OU-001`",
            "example.invalid",
        ):
            if phrase not in normalized_example:
                errors.append(f"{example_name}: missing Phase 7 example rule {phrase!r}")


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


def _validate_preserved_file_hashes(root: Path, errors: list[str]) -> None:
    for relative_name, expected_digest in {
        **HISTORICAL_V1_FILE_SHA256,
        **PHASE8_PRESERVED_FILE_SHA256,
    }.items():
        path = root / relative_name
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            errors.append(f"{relative_name}: cannot verify preserved file: {exc}")
            continue
        if digest != expected_digest:
            if relative_name in HISTORICAL_V1_FILE_SHA256:
                errors.append(
                    f"{relative_name}: provenance-preserved benchmark/eval path changed "
                    "from the Phase 7 checkpoint"
                )
            else:
                errors.append(
                    f"{relative_name}: Phase 3–7 security specification changed "
                    "during Phase 8"
                )


def _find_forbidden_result_fields(value: Any, path: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).lower().replace("-", "_").replace(" ", "_")
            if normalized_key in V2_FORBIDDEN_RESULT_FIELDS:
                errors.append(f"{path}: forbidden model-result field {key!r}")
            _find_forbidden_result_fields(child, f"{path}.{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _find_forbidden_result_fields(child, f"{path}[{index}]", errors)


def _validate_string_list(
    value: Any,
    label: str,
    errors: list[str],
) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        errors.append(f"{label}: must be a list of strings")
        return []
    if len(value) != len(set(value)):
        errors.append(f"{label}: must not contain duplicates")
    return value


def _validate_v2_mutations(root: Path, errors: list[str]) -> set[str]:
    relative_name = "evals/v2/mutations.json"
    data = _load_json(root / relative_name, "v2 mutation recipes", errors)
    if not isinstance(data, dict) or not isinstance(data.get("mutation_recipes"), list):
        errors.append(f"{relative_name}: mutation_recipes must be a list")
        return set()

    mutation_ids: set[str] = set()
    required = {
        "id", "name", "category", "applicable_to", "description",
        "preserves_semantics", "safety_notes",
    }
    for index, recipe in enumerate(data["mutation_recipes"]):
        label = f"{relative_name} mutation[{index}]"
        if not isinstance(recipe, dict):
            errors.append(f"{label}: expected an object")
            continue
        missing = required - set(recipe)
        if missing:
            errors.append(f"{label}: missing required field(s) {sorted(missing)!r}")
        mutation_id = recipe.get("id")
        if not isinstance(mutation_id, str) or not V2_MUTATION_ID_PATTERN.fullmatch(mutation_id):
            errors.append(f"{label}: malformed mutation ID {mutation_id!r}")
        elif mutation_id in mutation_ids:
            errors.append(f"{label}: duplicate mutation ID {mutation_id!r}")
        else:
            mutation_ids.add(mutation_id)
        applicable = _validate_string_list(recipe.get("applicable_to"), f"{label}.applicable_to", errors)
        for kind in applicable:
            if kind not in V2_SCENARIO_KINDS:
                errors.append(f"{label}: invalid applicable scenario kind {kind!r}")
        if recipe.get("preserves_semantics") is not True:
            errors.append(f"{label}: preserves_semantics must be true")
    return mutation_ids


def _validate_v2_risk(risk: Any, label: str, errors: list[str]) -> tuple[str | None, str | None]:
    if not isinstance(risk, dict):
        errors.append(f"{label}: expected_risk must be an object")
        return None, None
    mode = risk.get("mode")
    if not isinstance(mode, str) or mode not in V2_RISK_MODES:
        errors.append(f"{label}: invalid risk mode {mode!r}")
        return None, None
    if mode == "NOT_ASSERTED":
        if any(key in risk for key in ("dimensions", "score", "severity")):
            errors.append(f"{label}: NOT_ASSERTED risk must not fabricate score fields")
        return mode, None

    severity = risk.get("severity")
    if not isinstance(severity, str) or severity not in SEVERITY_BANDS:
        errors.append(f"{label}: invalid expected severity {severity!r}")
    if mode == "BAND":
        if "dimensions" in risk or "score" in risk:
            errors.append(f"{label}: BAND risk must not include an exact vector or score")
        return mode, severity if isinstance(severity, str) else None

    dimensions = risk.get("dimensions")
    if not isinstance(dimensions, dict) or set(dimensions) != set(RISK_DIMENSIONS):
        found = sorted(dimensions) if isinstance(dimensions, dict) else dimensions
        errors.append(
            f"{label}: EXACT risk dimensions must contain all 12 canonical symbols; found {found!r}"
        )
        return mode, severity if isinstance(severity, str) else None
    if any(
        not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 4
        for value in dimensions.values()
    ):
        errors.append(f"{label}: exact risk dimensions must be integers from 0 through 4")
        return mode, severity if isinstance(severity, str) else None
    evidence_basis = risk.get("evidence_basis")
    if (
        not isinstance(evidence_basis, dict)
        or set(evidence_basis) != set(RISK_DIMENSIONS)
        or not all(isinstance(value, str) and value.strip() for value in evidence_basis.values())
    ):
        errors.append(
            f"{label}: EXACT risk requires a non-empty evidence basis for all 12 dimensions"
        )
    expected_score = calculate_risk_score(dimensions)
    score = risk.get("score")
    if not _is_number(score) or float(score) != expected_score:
        errors.append(
            f"{label}: exact risk score mismatch; stored {score!r}, recomputed {expected_score:.1f}"
        )
    if (
        isinstance(severity, str)
        and severity in SEVERITY_BANDS
        and severity_for_score(expected_score) != severity
    ):
        errors.append(
            f"{label}: exact risk score / severity mismatch; {expected_score:.1f} requires "
            f"{severity_for_score(expected_score)}"
        )
    return mode, severity if isinstance(severity, str) else None


def _validate_v2_suite(
    root: Path,
    technique_ids: set[str],
    errors: list[str],
) -> dict[str, Any]:
    suite_root = root / "evals" / "v2"
    for relative_name in ("README.md", "HOLDOUT_POLICY.md", "manifest.json", "mutations.json"):
        if not (suite_root / relative_name).is_file():
            errors.append(f"evals/v2/{relative_name}: required Phase 8 file is missing")

    mutation_ids = _validate_v2_mutations(root, errors)
    hardening_text = _read_text(root, "references/hardening-patterns.md", errors) or ""
    hardening_ids = set(HARDENING_ID_PATTERN.findall(hardening_text))
    scenarios: list[dict[str, Any]] = []
    scenario_ids: set[str] = set()

    for filename in V2_SCENARIO_FILES:
        relative_name = f"evals/v2/{filename}"
        data = _load_json(suite_root / filename, f"v2 scenario group {filename}", errors)
        if not isinstance(data, dict) or not isinstance(data.get("scenarios"), list):
            errors.append(f"{relative_name}: scenarios must be a list")
            continue
        file_category = data.get("category")
        if not isinstance(file_category, str) or file_category not in V2_CATEGORY_MINIMUMS:
            errors.append(f"{relative_name}: invalid category {file_category!r}")
        _find_forbidden_result_fields(data, relative_name, errors)

        for index, scenario in enumerate(data["scenarios"]):
            label = f"{relative_name} scenario[{index}]"
            if not isinstance(scenario, dict):
                errors.append(f"{label}: expected an object")
                continue
            scenarios.append(scenario)
            missing = V2_REQUIRED_SCENARIO_FIELDS - set(scenario)
            if missing:
                errors.append(f"{label}: missing required field(s) {sorted(missing)!r}")

            scenario_id = scenario.get("id")
            if not isinstance(scenario_id, str) or not V2_SCENARIO_ID_PATTERN.fullmatch(scenario_id):
                errors.append(f"{label}: malformed v2 eval ID {scenario_id!r}")
            elif scenario_id in scenario_ids:
                errors.append(f"{label}: duplicate v2 eval ID {scenario_id!r}")
            else:
                scenario_ids.add(scenario_id)

            category = scenario.get("category")
            if (
                category != file_category
                or not isinstance(category, str)
                or category not in V2_CATEGORY_MINIMUMS
            ):
                errors.append(
                    f"{label}: scenario category {category!r} must match file category {file_category!r}"
                )
            kind = scenario.get("kind")
            if not isinstance(kind, str) or kind not in V2_SCENARIO_KINDS:
                errors.append(f"{label}: invalid scenario kind {kind!r}")
            if scenario.get("public_visibility") != "PUBLIC":
                errors.append(f"{label}: public scenario falsely labeled private/hidden holdout")

            language = scenario.get("language")
            languages = language if isinstance(language, list) else [language]
            if (
                not languages
                or any(not isinstance(tag, str) or tag not in V2_LANGUAGE_TAGS for tag in languages)
                or len(languages) != len(set(languages))
            ):
                errors.append(f"{label}: invalid language tag metadata {language!r}")

            profile = scenario.get("target_profile")
            if not isinstance(profile, dict):
                errors.append(f"{label}: target_profile must be an object")
                profile = {}
            profile_missing = V2_REQUIRED_PROFILE_FIELDS - set(profile)
            if profile_missing:
                errors.append(
                    f"{label}: target_profile missing field(s) {sorted(profile_missing)!r}"
                )
            for field_name in ("rag", "memory", "tools", "mcp", "agentic", "multimodal", "persistent_state"):
                if field_name in profile and profile[field_name] not in (True, False, "UNKNOWN"):
                    errors.append(f"{label}: target_profile.{field_name} must be true, false, or UNKNOWN")
            if "output_sink" in profile and not (
                profile["output_sink"] in (True, False, "UNKNOWN")
                or isinstance(profile["output_sink"], str)
            ):
                errors.append(f"{label}: target_profile.output_sink has invalid value")
            if scenario.get("agentic_applicable") not in (True, False):
                errors.append(f"{label}: agentic_applicable must be boolean")
            elif profile.get("agentic") in (True, False) and scenario["agentic_applicable"] != profile["agentic"]:
                errors.append(f"{label}: agentic_applicable conflicts with target_profile.agentic")

            if not isinstance(scenario.get("input"), dict):
                errors.append(f"{label}: input must be a structured object")
            tags = _validate_string_list(scenario.get("tags"), f"{label}.tags", errors)
            if not tags:
                errors.append(f"{label}: tags must not be empty")
            required_references = _validate_string_list(
                scenario.get("required_references", []), f"{label}.required_references", errors
            )
            for reference in required_references:
                if not (root / reference).is_file():
                    errors.append(f"{label}: unknown required reference {reference!r}")

            expected = scenario.get("expected")
            if not isinstance(expected, dict):
                errors.append(f"{label}: expected must be an object")
                continue
            expected_missing = V2_REQUIRED_EXPECTED_FIELDS - set(expected)
            if expected_missing:
                errors.append(f"{label}: expected missing field(s) {sorted(expected_missing)!r}")

            technique_lists: dict[str, list[str]] = {}
            for field_name in ("must_detect", "may_detect", "must_not_detect"):
                values = _validate_string_list(
                    expected.get(field_name), f"{label}.expected.{field_name}", errors
                )
                technique_lists[field_name] = values
                for technique_id in values:
                    if technique_id not in technique_ids:
                        errors.append(f"{label}: unknown RenGuard technique ID {technique_id!r}")
            if kind == "CLEAN" and technique_lists["must_detect"]:
                errors.append(f"{label}: CLEAN case must not require vulnerability detection")
            if kind in {"ATTACK", "CHAIN"} and not technique_lists["must_detect"]:
                errors.append(f"{label}: {kind} case must require security detection")

            primary = expected.get("expected_primary_technique")
            if primary is not None and (
                not isinstance(primary, str) or primary not in technique_ids
            ):
                errors.append(f"{label}: unknown primary RenGuard technique {primary!r}")
            secondary = _validate_string_list(
                expected.get("expected_secondary_techniques"),
                f"{label}.expected.expected_secondary_techniques",
                errors,
            )
            for technique_id in secondary:
                if technique_id not in technique_ids:
                    errors.append(f"{label}: unknown secondary RenGuard technique {technique_id!r}")
            if technique_lists["must_detect"]:
                if primary != technique_lists["must_detect"][0]:
                    errors.append(f"{label}: primary technique must be the first required detection")
                if secondary != technique_lists["must_detect"][1:]:
                    errors.append(f"{label}: secondary techniques must match remaining detections")

            llm_mappings = _validate_string_list(
                expected.get("expected_owasp_llm"), f"{label}.expected.expected_owasp_llm", errors
            )
            for mapping in llm_mappings:
                if mapping not in OWASP_LLM_2026:
                    errors.append(f"{label}: unknown OWASP LLM 2026 mapping {mapping!r}")
            agentic_mappings = _validate_string_list(
                expected.get("expected_owasp_agentic"),
                f"{label}.expected.expected_owasp_agentic",
                errors,
            )
            for mapping in agentic_mappings:
                if mapping not in OWASP_AGENTIC_2026:
                    errors.append(f"{label}: unknown OWASP Agentic 2026 mapping {mapping!r}")
            if agentic_mappings and scenario.get("agentic_applicable") is not True:
                errors.append(f"{label}: Agentic mapping used for non-agentic scenario")

            confidence = expected.get("expected_confidence")
            if not isinstance(confidence, str) or confidence not in CONFIDENCE_LEVELS:
                errors.append(f"{label}: invalid expected confidence {confidence!r}")
            _validate_v2_risk(expected.get("expected_risk"), f"{label}.expected", errors)

            control_layers = _validate_string_list(
                expected.get("required_control_layers"),
                f"{label}.expected.required_control_layers",
                errors,
            )
            for layer in control_layers:
                if layer not in HARDENING_CONTROL_LAYERS:
                    errors.append(f"{label}: invalid required control layer {layer!r}")
            pattern_ids = _validate_string_list(
                expected.get("required_hardening_patterns"),
                f"{label}.expected.required_hardening_patterns",
                errors,
            )
            for pattern_id in pattern_ids:
                if pattern_id not in hardening_ids:
                    errors.append(f"{label}: unknown hardening pattern ID {pattern_id!r}")
            assertion_groups = _validate_string_list(
                expected.get("assertion_groups"), f"{label}.expected.assertion_groups", errors
            )
            for group in assertion_groups:
                if group not in V2_ASSERTION_GROUPS:
                    errors.append(f"{label}: invalid assertion group {group!r}")
            security_properties = _validate_string_list(
                expected.get("required_security_properties"),
                f"{label}.expected.required_security_properties",
                errors,
            )
            _validate_string_list(
                expected.get("prohibited_claims"),
                f"{label}.expected.prohibited_claims",
                errors,
            )
            redaction_expectation = expected.get("secret_redaction_expectation")
            if redaction_expectation not in (
                "NONE", "REDACT", "REDACT_AND_ROTATE"
            ):
                errors.append(f"{label}: invalid secret redaction expectation")
            elif redaction_expectation != "NONE":
                required_redaction_properties = {
                    "REDACT_SECRETS",
                    "EXCLUDE_SECRET_FROM_HARDENED_REWRITE",
                    "RECOMMEND_ROTATION_OR_REVOCATION",
                }
                if not required_redaction_properties.issubset(security_properties):
                    errors.append(f"{label}: redaction case missing required secret-handling properties")
                if "REDACTION" not in assertion_groups:
                    errors.append(f"{label}: redaction case must include REDACTION assertion group")

            referenced_mutations = _validate_string_list(
                scenario.get("mutation_ids", []), f"{label}.mutation_ids", errors
            )
            for mutation_id in referenced_mutations:
                if mutation_id not in mutation_ids:
                    errors.append(f"{label}: unknown mutation ID {mutation_id!r}")
            if not isinstance(scenario.get("mutation_eligible"), bool):
                errors.append(f"{label}: mutation_eligible must be boolean")
            elif referenced_mutations and scenario.get("mutation_eligible") is not True:
                errors.append(f"{label}: mutation IDs require mutation_eligible=true")

            if kind == "CHAIN":
                chain = scenario.get("architecture", {}).get("ordered_attack_chain") if isinstance(scenario.get("architecture"), dict) else None
                if not isinstance(chain, list) or len(chain) < 3 or not all(isinstance(step, str) for step in chain):
                    errors.append(f"{label}: CHAIN case requires at least three ordered components")
            if "turns" in scenario:
                turns = scenario["turns"]
                if not isinstance(turns, list) or len(turns) < 2 or not all(
                    isinstance(turn, dict)
                    and isinstance(turn.get("role"), str)
                    and isinstance(turn.get("content"), str)
                    for turn in turns
                ):
                    errors.append(f"{label}: turns must contain at least two role/content objects")
            if profile.get("multimodal") is True:
                if scenario.get("input_representation") != "normalized_multimodal_descriptor":
                    errors.append(f"{label}: multimodal case must declare normalized descriptor input")
                if scenario.get("native_media_required_for_full_benchmark") is not True:
                    errors.append(f"{label}: multimodal case must disclose native-media limitation")

    manifest = _load_json(suite_root / "manifest.json", "v2 manifest", errors)
    if not isinstance(manifest, dict):
        errors.append("evals/v2/manifest.json: expected an object")
        return {}
    _find_forbidden_result_fields(manifest, "evals/v2/manifest.json", errors)
    for field_name, expected_value in (
        ("suite_name", V2_SUITE_NAME),
        ("suite_version", V2_SUITE_VERSION),
        ("created_for_phase", 8),
        ("source_checkpoint", PHASE8_SOURCE_CHECKPOINT),
        ("public_visibility", "PUBLIC"),
        ("results_status", "TEST_DEFINITIONS_ONLY_NO_MODEL_RESULTS"),
    ):
        if manifest.get(field_name) != expected_value:
            errors.append(
                f"evals/v2/manifest.json: {field_name} must be {expected_value!r}"
            )
    if manifest.get("mutation_file") != "mutations.json":
        errors.append("evals/v2/manifest.json: mutation_file must be 'mutations.json'")
    if manifest.get("holdout_policy") != "HOLDOUT_POLICY.md":
        errors.append("evals/v2/manifest.json: holdout_policy must be 'HOLDOUT_POLICY.md'")
    separation = manifest.get("historical_v1_separation")
    if not isinstance(separation, str) or "no v2 model results" not in separation.lower():
        errors.append("evals/v2/manifest.json: historical v1 separation must state no v2 model results")
    if manifest.get("scenario_files") != list(V2_SCENARIO_FILES):
        errors.append("evals/v2/manifest.json: scenario_files must match canonical grouped files")

    category_counts = Counter(
        scenario.get("category") for scenario in scenarios if isinstance(scenario.get("category"), str)
    )
    kind_counts = Counter(
        scenario.get("kind") for scenario in scenarios if isinstance(scenario.get("kind"), str)
    )
    language_counts: Counter[str] = Counter()
    for scenario in scenarios:
        language = scenario.get("language")
        languages = language if isinstance(language, list) else [language]
        language_counts.update(tag for tag in languages if isinstance(tag, str))
    multi_turn_count = sum(isinstance(scenario.get("turns"), list) for scenario in scenarios)
    chain_count = sum(scenario.get("kind") == "CHAIN" for scenario in scenarios)
    exact_count = sum(
        isinstance(scenario.get("expected"), dict)
        and isinstance(scenario["expected"].get("expected_risk"), dict)
        and scenario["expected"]["expected_risk"].get("mode") == "EXACT"
        for scenario in scenarios
    )
    non_english_count = sum(scenario.get("language") != "en" for scenario in scenarios)
    clean_boundary_count = kind_counts["CLEAN"] + kind_counts["BOUNDARY"]
    redaction_count = sum(
        isinstance(scenario.get("expected"), dict)
        and scenario["expected"].get("secret_redaction_expectation") in {"REDACT", "REDACT_AND_ROTATE"}
        for scenario in scenarios
    )

    recomputed_manifest = {
        "scenario_count": len(scenarios),
        "category_counts": dict(sorted(category_counts.items())),
        "kind_counts": dict(sorted(kind_counts.items())),
        "language_counts": dict(sorted(language_counts.items())),
        "multi_turn_count": multi_turn_count,
        "attack_chain_count": chain_count,
        "exact_score_count": exact_count,
        "non_english_or_mixed_count": non_english_count,
        "technique_coverage_count": len(technique_ids),
        "mutation_count": len(mutation_ids),
    }
    for field_name, expected_value in recomputed_manifest.items():
        if manifest.get(field_name) != expected_value:
            errors.append(
                f"evals/v2/manifest.json: {field_name} mismatch; stored "
                f"{manifest.get(field_name)!r}, recomputed {expected_value!r}"
            )

    if len(scenarios) < 72:
        errors.append(f"evals/v2: at least 72 public scenarios required; found {len(scenarios)}")
    for category, minimum in V2_CATEGORY_MINIMUMS.items():
        if category_counts[category] < minimum:
            errors.append(
                f"evals/v2: category {category} requires at least {minimum} scenarios; "
                f"found {category_counts[category]}"
            )
    if clean_boundary_count < 12:
        errors.append(
            f"evals/v2: at least 12 clean/boundary controls required; found {clean_boundary_count}"
        )
    if multi_turn_count < 10:
        errors.append(f"evals/v2: at least 10 multi-turn scenarios required; found {multi_turn_count}")
    if chain_count < 10:
        errors.append(f"evals/v2: at least 10 attack-chain scenarios required; found {chain_count}")
    if non_english_count < 16:
        errors.append(
            f"evals/v2: at least 16 non-English/mixed-language scenarios required; "
            f"found {non_english_count}"
        )
    missing_languages = V2_REQUIRED_LANGUAGES - set(language_counts)
    if missing_languages:
        errors.append(f"evals/v2: required languages missing {sorted(missing_languages)!r}")
    for language in V2_REQUIRED_LANGUAGES - {"en"}:
        if language_counts[language] < 2:
            errors.append(f"evals/v2: language {language} requires at least two scenarios")
    if exact_count < 12:
        errors.append(f"evals/v2: at least 12 exact-score scenarios required; found {exact_count}")
    if redaction_count < 3:
        errors.append(f"evals/v2: at least three secret-redaction scenarios required; found {redaction_count}")

    covered_techniques: set[str] = set()
    positive_by_technique: dict[str, list[str]] = {key: [] for key in technique_ids}
    negative_by_technique: dict[str, list[str]] = {key: [] for key in technique_ids}
    for scenario in scenarios:
        expected = scenario.get("expected")
        if not isinstance(expected, dict) or not isinstance(scenario.get("id"), str):
            continue
        for field_name in ("must_detect", "may_detect", "must_not_detect"):
            values = expected.get(field_name)
            if isinstance(values, list):
                covered_techniques.update(value for value in values if value in technique_ids)
        for technique_id in expected.get("must_detect", []):
            if technique_id in positive_by_technique:
                positive_by_technique[technique_id].append(scenario["id"])
        for technique_id in expected.get("must_not_detect", []):
            if technique_id in negative_by_technique:
                negative_by_technique[technique_id].append(scenario["id"])
    uncovered = technique_ids - covered_techniques
    if uncovered:
        errors.append(f"evals/v2: uncovered RenGuard technique(s) {sorted(uncovered)!r}")

    expected_coverage = []
    for technique_id in sorted(technique_ids):
        positive = positive_by_technique[technique_id]
        negative = negative_by_technique[technique_id]
        expected_coverage.append(
            {
                "technique_id": technique_id,
                "coverage_status": "PARTIAL" if technique_id in {
                    "RG-PI-007", "RG-PI-010", "RG-RA-003", "RG-MI-001", "RG-MM-001"
                } else "CORE",
                "positive_scenario_count": len(positive),
                "boundary_clean_scenario_count": len(negative),
                "scenario_ids": positive + negative,
            }
        )
    if manifest.get("technique_coverage") != expected_coverage:
        errors.append("evals/v2/manifest.json: technique coverage matrix mismatch")

    severities = {
        severity
        for scenario in scenarios
        if isinstance(scenario.get("expected"), dict)
        and isinstance(scenario["expected"].get("expected_risk"), dict)
        and isinstance(
            severity := scenario["expected"]["expected_risk"].get("severity"), str
        )
    }
    if not set(SEVERITY_BANDS).issubset(severities):
        errors.append("evals/v2: asserted severity coverage must include all five bands")
    confidences = {
        confidence
        for scenario in scenarios
        if isinstance(scenario.get("expected"), dict)
        and isinstance(confidence := scenario["expected"].get("expected_confidence"), str)
    }
    if not CONFIDENCE_LEVELS.issubset(confidences):
        errors.append("evals/v2: confidence coverage must include HIGH, MEDIUM, and LOW")

    return {
        **recomputed_manifest,
        "clean_boundary_count": clean_boundary_count,
        "redaction_count": redaction_count,
        "covered_techniques": len(covered_techniques),
    }


def _validate_phase9_runner(root: Path, errors: list[str]) -> dict[str, Any]:
    runner = root / "scripts" / "run_benchmark.py"
    package = root / "scripts" / "renguard_benchmark"
    if not runner.is_file():
        errors.append("scripts/run_benchmark.py: Phase 9 entry point is missing")
    for filename in PHASE9_MODULES:
        if not (package / filename).is_file():
            errors.append(f"scripts/renguard_benchmark/{filename}: required Phase 9 module is missing")

    init_text = _read_text(root, "scripts/renguard_benchmark/__init__.py", errors) or ""
    for name, version in (
        ("RUNNER_VERSION", PHASE9_RUNNER_VERSION),
        ("SCORING_VERSION", PHASE9_SCORING_VERSION),
        ("ARTIFACT_SCHEMA_VERSION", PHASE9_ARTIFACT_SCHEMA_VERSION),
    ):
        if f'{name} = "{version}"' not in init_text:
            errors.append(f"scripts/renguard_benchmark/__init__.py: {name} must be {version}")

    adapter_text = _read_text(root, "scripts/renguard_benchmark/adapters.py", errors) or ""
    for class_name in ("FixtureAdapter", "ReplayAdapter", "CommandAdapter"):
        if f"class {class_name}" not in adapter_text:
            errors.append(f"scripts/renguard_benchmark/adapters.py: missing {class_name}")
    for marker in ("shell=False", "stdin=subprocess.PIPE", "max_output_bytes", "process.kill()"):
        if marker not in adapter_text:
            errors.append(f"scripts/renguard_benchmark/adapters.py: missing command safety marker {marker!r}")
    if "shell=True" in adapter_text:
        errors.append("scripts/renguard_benchmark/adapters.py: shell=True is prohibited")

    prompt_text = _read_text(root, "scripts/renguard_benchmark/prompt_builder.py", errors) or ""
    for marker in ("RUNTIME_FIELDS", "FORBIDDEN_RUNTIME_FIELDS", "ground-truth leakage detected"):
        if marker not in prompt_text:
            errors.append(f"scripts/renguard_benchmark/prompt_builder.py: missing leakage protection {marker!r}")
    for forbidden_name in ("must_detect", "must_not_detect", "expected_primary_technique", "expected_risk", "expected_confidence"):
        if f'"{forbidden_name}"' not in prompt_text:
            errors.append(f"scripts/renguard_benchmark/prompt_builder.py: forbidden field {forbidden_name!r} is not guarded")

    execution_text = _read_text(root, "scripts/renguard_benchmark/execution.py", errors) or ""
    if "live-capable adapters require --execute-live" not in execution_text:
        errors.append("scripts/renguard_benchmark/execution.py: explicit live-network gate is missing")
    if "ThreadPoolExecutor" not in execution_text or "execution_key" not in execution_text:
        errors.append("scripts/renguard_benchmark/execution.py: concurrency/resume architecture is incomplete")

    gitignore = _read_text(root, ".gitignore", errors) or ""
    if not re.search(r"(?m)^benchmark-runs/$", gitignore):
        errors.append(".gitignore: generated benchmark-runs/ directory must be ignored")
    if re.search(r"(?m)^evals/v2/|^tests/fixtures/", gitignore):
        errors.append(".gitignore: committed corpus/fixture paths must not be ignored")

    fixture_path = root / "tests" / "fixtures" / "benchmark" / "fixture-profiles.json"
    fixture = _load_json(fixture_path, "Phase 9 fixture profiles", errors)
    if not isinstance(fixture, dict) or fixture.get("fixture_only") is not True:
        errors.append("tests/fixtures/benchmark/fixture-profiles.json: fixtures must be labeled test-only")
    if isinstance(fixture, dict) and "not RenGuard performance" not in fixture.get("warning", ""):
        errors.append("tests/fixtures/benchmark/fixture-profiles.json: synthetic performance disclaimer missing")

    if (root / ".git").exists():
        tracked = subprocess.run(
            ["git", "ls-files", "--", "benchmark-runs"], cwd=root,
            capture_output=True, text=True, check=False,
        )
        if tracked.stdout.strip():
            errors.append("benchmark-runs/: generated run artifacts must not be committed")
    credential_patterns = (
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        re.compile(r"\bBearer [A-Za-z0-9._-]{20,}\b"),
    )
    phase9_text_files = [
        runner, *(package / name for name in PHASE9_MODULES), root / "BENCHMARKING.md",
        root / "tests" / "test_benchmark.py", fixture_path,
    ]
    for path in phase9_text_files:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if any(pattern.search(text) for pattern in credential_patterns):
            errors.append(f"{path.relative_to(root)}: possible real credential in Phase 9 content")
    for relative_name in ("README.md", "BENCHMARKING.md", "evals/v2/README.md", "CHANGELOG.md"):
        text = _read_text(root, relative_name, errors) or ""
        if "no official" not in " ".join(text.lower().split()):
            errors.append(f"{relative_name}: must state that no official v2 live result exists")

    return {
        "runner_version": PHASE9_RUNNER_VERSION,
        "scoring_version": PHASE9_SCORING_VERSION,
        "artifact_schema_version": PHASE9_ARTIFACT_SCHEMA_VERSION,
        "module_count": len(PHASE9_MODULES),
    }


def _validate_phase10_engineering(root: Path, errors: list[str]) -> dict[str, Any]:
    schema_errors, schema_metrics = validate_repository_contracts(root)
    errors.extend(f"SCHEMA: {error}" for error in schema_errors)

    required_files = (
        ".github/workflows/ci.yml",
        ".editorconfig",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "schemas/README.md",
        "schemas/versions.json",
        "scripts/schema_tools.py",
        "scripts/check.py",
    )
    for relative_name in required_files:
        if not (root / relative_name).is_file():
            errors.append(f"STRUCTURE: missing Phase 10 engineering file {relative_name}")

    workflow = _read_text(root, ".github/workflows/ci.yml", errors) or ""
    for marker in (
        "push:", "pull_request:", "contents: read", "persist-credentials: false",
        "python scripts/check.py", "timeout-minutes:",
    ):
        if marker not in workflow:
            errors.append(f"REPOSITORY: CI workflow missing required marker {marker!r}")
    for forbidden in (
        "pull_request_target", "--execute-live", "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "MOONSHOT_API_KEY",
        "permissions: write",
    ):
        if forbidden in workflow:
            errors.append(f"SECURITY: CI workflow contains prohibited value {forbidden!r}")
    if "actions/checkout@" not in workflow or "actions/setup-python@" not in workflow:
        errors.append("REPOSITORY: CI must use official checkout and setup-python actions")

    check_script = _read_text(root, "scripts/check.py", errors) or ""
    for marker in ("sys.executable", "shell=False", "fixture", "schema_tools.py", "TemporaryDirectory"):
        if marker not in check_script:
            errors.append(f"REPOSITORY: scripts/check.py missing quality-gate marker {marker!r}")
    for forbidden in ("shell=True", "--execute-live", "http://", "https://"):
        if forbidden in check_script:
            errors.append(f"SECURITY: scripts/check.py contains prohibited value {forbidden!r}")

    gitignore = _read_text(root, ".gitignore", errors) or ""
    for marker in ("benchmark-runs/", "__pycache__/", "*.py[cod]", ".pytest_cache/"):
        if marker not in gitignore:
            errors.append(f"REPOSITORY: .gitignore missing generated-artifact pattern {marker!r}")
    for forbidden in ("evals/v2/", "schemas/", "tests/fixtures/"):
        if re.search(rf"(?m)^{re.escape(forbidden)}$", gitignore):
            errors.append(f"REPOSITORY: canonical path must not be ignored: {forbidden}")

    phase10_paths = [
        root / ".github/workflows/ci.yml",
        root / "CONTRIBUTING.md",
        root / "SECURITY.md",
        root / "scripts/check.py",
        root / "scripts/schema_tools.py",
        *(root / "schemas").rglob("*"),
    ]
    credential_patterns = (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    )
    for path in phase10_paths:
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            if any(pattern.search(text) for pattern in credential_patterns):
                errors.append(f"SECURITY: possible credential in Phase 10 file {path.relative_to(root)}")
    tooling_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (root / "scripts/check.py", root / "scripts/schema_tools.py")
        if path.is_file()
    )
    for forbidden in ("urllib.request", "requests.", "httpx.", "socket.create_connection"):
        if forbidden in tooling_text:
            errors.append(f"SECURITY: standard quality tooling must not make network calls ({forbidden})")

    portable_suffixes = {".py", ".md", ".json", ".yml", ".yaml"}
    workspace_marker = "/" + "workspace/"
    home_pattern = re.compile("/" + r"home/[^/<\s]+/")
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts or path.suffix.lower() not in portable_suffixes:
            continue
        text = path.read_text(encoding="utf-8")
        if workspace_marker in text or re.search(r"[A-Za-z]:\\\\Users\\\\", text) or home_pattern.search(text):
            errors.append(f"REPOSITORY: committed file contains an environment-specific path: {path.relative_to(root)}")

    return {
        "schema_count": schema_metrics.get("schemas", 0),
        "schema_scenarios": schema_metrics.get("scenarios", 0),
        "schema_mutations": schema_metrics.get("mutations", 0),
        "ci_python_versions": 4,
    }


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
    _validate_phase7_references(root, validation.errors)
    _validate_risk_reference(root, validation.errors)
    _validate_phase3_examples(root, REQUIRED_TECHNIQUE_IDS, validation.errors)
    _validate_preserved_file_hashes(root, validation.errors)
    validation.v2_metrics = _validate_v2_suite(
        root, REQUIRED_TECHNIQUE_IDS, validation.errors
    )
    validation.phase9_metrics = _validate_phase9_runner(root, validation.errors)
    validation.phase10_metrics = _validate_phase10_engineering(root, validation.errors)
    for relative_name in (
        "README.md",
        "BENCHMARKING.md",
        "SKILL.md",
        "evals/v2/README.md",
        "evals/v2/HOLDOUT_POLICY.md",
        *TAXONOMY_FILES,
        *EXAMPLE_FILES,
    ):
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
    if result.v2_metrics:
        print(f"- v2 public scenarios: {result.v2_metrics['scenario_count']}")
        print(
            f"- v2 corpus coverage: {result.v2_metrics['covered_techniques']}/"
            f"{len(REQUIRED_TECHNIQUE_IDS)} techniques"
        )
    if result.phase9_metrics:
        print(
            f"- Phase 9 runner/scoring/schema: {result.phase9_metrics['runner_version']} / "
            f"{result.phase9_metrics['scoring_version']} / "
            f"{result.phase9_metrics['artifact_schema_version']}"
        )
    if result.phase10_metrics:
        print(
            f"- Phase 10 schemas/scenarios/mutations: {result.phase10_metrics['schema_count']} / "
            f"{result.phase10_metrics['schema_scenarios']} / "
            f"{result.phase10_metrics['schema_mutations']}"
        )
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
