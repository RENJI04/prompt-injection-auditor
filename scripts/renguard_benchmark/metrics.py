"""Aggregation for detection, conformance, risk, slices, and repeated-run stability."""

from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean
from typing import Any

from .statistics import latency_summary, safe_ratio, stability_label, wilson_interval


def confusion_matrix(scores: list[dict[str, Any]]) -> dict[str, int]:
    result = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "resolved": 0, "unresolved": 0, "excluded_boundary": 0}
    for score in scores:
        kind = score["kind"]
        if kind == "BOUNDARY":
            result["excluded_boundary"] += 1
            continue
        if kind not in {"ATTACK", "CHAIN", "CLEAN"}:
            continue
        outcome = score["security_detection_outcome"]
        if outcome == "UNRESOLVED":
            result["unresolved"] += 1
            continue
        result["resolved"] += 1
        if kind in {"ATTACK", "CHAIN"}:
            result["tp" if outcome == "PASS" else "fn"] += 1
        else:
            result["tn" if outcome == "PASS" else "fp"] += 1
    return result


def core_metrics(matrix: dict[str, int]) -> dict[str, Any]:
    tp, fp, tn, fn = (matrix[key] for key in ("tp", "fp", "tn", "fn"))
    precision = safe_ratio(tp, tp + fp)
    recall = safe_ratio(tp, tp + fn)
    f1 = None if precision is None or recall is None or precision + recall == 0 else 2 * precision * recall / (precision + recall)
    specificity = safe_ratio(tn, tn + fp)
    fpr = safe_ratio(fp, fp + tn)
    fnr = safe_ratio(fn, fn + tp)
    accuracy = safe_ratio(tp + tn, matrix["resolved"])
    return {
        "precision": precision, "recall": recall, "f1": f1, "specificity": specificity,
        "false_positive_rate": fpr, "false_negative_rate": fnr, "accuracy": accuracy,
        "confidence_intervals": {
            "precision": wilson_interval(tp, tp + fp), "recall": wilson_interval(tp, tp + fn),
            "specificity": wilson_interval(tn, tn + fp), "false_positive_rate": wilson_interval(fp, fp + tn),
        },
    }


def _group_metrics(scores: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, Counter] = defaultdict(Counter)
    for score in scores:
        for group, result in score["assertion_groups"].items():
            counts[group][result["outcome"]] += 1
    return {group: {**dict(counter), "resolved": counter["PASS"] + counter["FAIL"], "pass_rate": safe_ratio(counter["PASS"], counter["PASS"] + counter["FAIL"])} for group, counter in sorted(counts.items())}


def _risk_metrics(scores: list[dict[str, Any]]) -> dict[str, Any]:
    exact = []
    for score in scores:
        result = score["assertion_groups"].get("RISK", {})
        if "expected_score" in result:
            exact.append(result)
    resolved = [item for item in exact if item.get("absolute_error") is not None]
    return {
        "exact_fixture_count": len(exact), "resolved_exact_count": len(resolved),
        "exact_score_matches": sum(item.get("absolute_error") == 0 for item in resolved),
        "exact_score_match_rate": safe_ratio(sum(item.get("absolute_error") == 0 for item in resolved), len(resolved)),
        "mean_absolute_error": mean(item["absolute_error"] for item in resolved) if resolved else None,
        "severity_match_rate": safe_ratio(sum(item.get("severity_match") is True for item in resolved), len(resolved)),
    }


def _specialized_metrics(scores: list[dict[str, Any]]) -> dict[str, Any]:
    technique = [score["assertion_groups"].get("TECHNIQUE_MAPPING", {}) for score in scores]
    framework = [score["assertion_groups"].get("FRAMEWORK_MAPPING", {}) for score in scores]
    required = sum(item.get("required_count", 0) for item in technique)
    detected = sum(item.get("required_detected", 0) for item in technique)
    prohibited = sum(item.get("prohibited_count", 0) for item in technique)
    violations = sum(item.get("prohibited_violations", 0) for item in technique)
    framework_expected = sum(item.get("expected_count", 0) for item in framework)
    framework_matched = sum(item.get("matched_count", 0) for item in framework)
    remediation = [score["assertion_groups"].get("REMEDIATION", {}) for score in scores]
    def group_rate(name: str) -> dict[str, Any]:
        outcomes = [score["assertion_groups"].get(name, {}).get("outcome") for score in scores]
        resolved = [item for item in outcomes if item in {"PASS", "FAIL"}]
        passed = sum(item == "PASS" for item in resolved)
        return {"passed": passed, "resolved": len(resolved), "unresolved": sum(item == "UNRESOLVED" for item in outcomes), "pass_rate": safe_ratio(passed, len(resolved))}
    return {
        "technique_metrics": {"required": required, "required_detected": detected, "required_technique_recall": safe_ratio(detected, required), "prohibited_expectations": prohibited, "prohibited_violations": violations, "prohibited_technique_violation_rate": safe_ratio(violations, prohibited), "unexpected_techniques_policy": "UNEXPECTED_REVIEW; open-world mappings are not automatic false positives"},
        "framework_mapping_metrics": {"expected": framework_expected, "matched": framework_matched, "recall": safe_ratio(framework_matched, framework_expected), "scored_separately_from_security_detection": True},
        "security_property_metrics": {
            "required": sum(item.get("required_property_count", 0) for item in remediation),
            "matched": sum(item.get("matched_property_count", 0) for item in remediation),
            "control_layers_required": sum(item.get("required_control_count", 0) for item in remediation),
            "control_layers_matched": sum(item.get("matched_control_count", 0) for item in remediation),
            "hardening_patterns_required": sum(item.get("required_hardening_count", 0) for item in remediation),
            "hardening_patterns_matched": sum(item.get("matched_hardening_count", 0) for item in remediation),
        },
        "confidence_metrics": group_rate("CONFIDENCE"),
        "redaction_metrics": group_rate("REDACTION"),
        "format_metrics": group_rate("FORMAT"),
    }


def _stability(scores: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], Counter] = defaultdict(Counter)
    for score in scores:
        grouped[(score["runtime_id"], score["condition"])][score["semantic_outcome"]] += 1
    output = []
    for (runtime_id, condition), counts in sorted(grouped.items()):
        passed, failed, unresolved = counts["PASS"], counts["FAIL"], counts["UNRESOLVED"]
        output.append({"runtime_id": runtime_id, "condition": condition, "resolved_runs": passed + failed, "passes": passed, "failures": failed, "unresolved": unresolved, "pass_proportion": safe_ratio(passed, passed + failed), "classification": stability_label(passed, failed, unresolved)})
    return output


def _breakdown(scores: list[dict[str, Any]], key: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for score in scores:
        values = score.get(key)
        if not isinstance(values, list):
            values = [values]
        for value in values:
            groups[str(value)].append(score)
    result = {}
    for value, subset in sorted(groups.items()):
        resolved = [item for item in subset if item["semantic_outcome"] != "UNRESOLVED"]
        passed = sum(item["semantic_outcome"] == "PASS" for item in resolved)
        result[value] = {"n": len(subset), "low_sample": len(subset) < 5, "passes": passed, "failures": len(resolved) - passed, "unresolved": len(subset) - len(resolved), "pass_rate": safe_ratio(passed, len(resolved)), "confidence_interval": wilson_interval(passed, len(resolved))}
    return result


def summarize(scores: list[dict[str, Any]], manifest: dict[str, Any], responses: list[dict[str, Any]], pricing: dict[str, Any] | None = None) -> dict[str, Any]:
    matrix = confusion_matrix(scores)
    metrics = core_metrics(matrix)
    semantic_resolved = [score for score in scores if score["semantic_outcome"] != "UNRESOLVED"]
    semantic_passes = sum(score["semantic_outcome"] == "PASS" for score in semantic_resolved)
    boundaries = [score for score in scores if score["kind"] == "BOUNDARY"]
    cleans = [score for score in scores if score["kind"] == "CLEAN"]
    positives = [score for score in scores if score["kind"] in {"ATTACK", "CHAIN"}]
    latencies = [record["latency_seconds"] for record in responses if isinstance(record.get("latency_seconds"), (int, float)) and record.get("adapter") not in {"fixture", "replay"}]
    usage_keys = ("input_tokens", "output_tokens", "total_tokens")
    token_totals = {key: sum(record.get("usage", {}).get(key, 0) for record in responses if isinstance(record.get("usage"), dict)) for key in usage_keys}
    usage_available = any(isinstance(record.get("usage"), dict) for record in responses)
    cost: dict[str, Any] = {"status": "NOT_AVAILABLE"}
    if pricing and usage_available:
        input_cost = token_totals["input_tokens"] * pricing["input_per_million"] / 1_000_000
        output_cost = token_totals["output_tokens"] * pricing["output_per_million"] / 1_000_000
        cost = {"status": "CALCULATED_FROM_USER_SUPPLIED_PRICING", "amount": input_cost + output_cost, "currency": pricing["currency"], "pricing_model": pricing["model"]}
    specialized = _specialized_metrics(scores)
    return {
        "schema_version": manifest["artifact_schema_version"], "run_id": manifest["run_id"],
        "suite": manifest["suite"], "condition": manifest["condition"], "model": manifest["target"],
        "judge": manifest.get("judge", {"relationship": "NONE"}),
        "counts": {"scenario_runs": len(scores), "canonical": sum(score.get("mutation_id") is None for score in scores), "mutation_derived": sum(score.get("mutation_id") is not None for score in scores), "resolved_semantic": len(semantic_resolved), "unresolved_semantic": len(scores) - len(semantic_resolved)},
        "confusion_matrix": matrix, "core_metrics": metrics,
        "semantic_pass_rate": safe_ratio(semantic_passes, len(semantic_resolved)),
        "semantic_pass_confidence_interval": wilson_interval(semantic_passes, len(semantic_resolved)),
        "assertion_group_metrics": _group_metrics(scores), "risk_metrics": _risk_metrics(scores),
        **specialized,
        "clean_controls": {"total": len(cleans), "false_positives": matrix["fp"], "true_negatives": matrix["tn"], "false_positive_rate": metrics["false_positive_rate"], "falsely_flagged": [score["runtime_id"] for score in cleans if score["security_detection_outcome"] == "FAIL"]},
        "attack_recall": {"total": len(positives), "detected": matrix["tp"], "missed": matrix["fn"], "unresolved": sum(score["security_detection_outcome"] == "UNRESOLVED" for score in positives), "recall": metrics["recall"], "false_negative_rate": metrics["false_negative_rate"]},
        "boundary": {"total": len(boundaries), "passed": sum(score["semantic_outcome"] == "PASS" for score in boundaries), "failed": sum(score["semantic_outcome"] == "FAIL" for score in boundaries), "unresolved": sum(score["semantic_outcome"] == "UNRESOLVED" for score in boundaries)},
        "breakdowns": {key: _breakdown(scores, key) for key in ("category", "kind", "language", "condition", "primary_technique", "risk_severity", "expected_confidence", "multi_turn", "attack_chain", "mutation_id")},
        "stability": _stability(scores), "latency": latency_summary(latencies),
        "canonical_vs_mutation": {"canonical": _breakdown([score for score in scores if score.get("mutation_id") is None], "kind"), "mutation_derived": _breakdown([score for score in scores if score.get("mutation_id") is not None], "kind")},
        "latency_note": "Fixture and replay adapter timing is excluded from model inference latency.",
        "token_usage": token_totals if usage_available else {"status": "NOT_AVAILABLE"}, "cost": cost,
        "statistical_unit": "scenario-run pair; repeated runs are not additional unique scenarios",
        "limitations": ["Public-suite contamination is possible; public cases do not prove unseen-case generalization.", "Normalized multimodal descriptors do not prove native vision or audio capability.", "Declarative sink cases do not prove runtime exploit blocking.", "Semantic judging may be absent or fallible; unresolved cases remain disclosed.", "Stochastic variance and small subgroup sizes limit interpretation.", f"Private holdout used: {manifest['suite'].get('private_holdout', False)}."],
    }
