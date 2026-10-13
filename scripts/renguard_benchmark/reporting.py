"""Safe machine-readable and Markdown reporting plus compatible run comparison."""

from __future__ import annotations

from typing import Any

from .util import read_json, read_jsonl


def _display(value: Any) -> str:
    if value is None:
        return "NOT_AVAILABLE"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value).replace("<", "&lt;").replace(">", "&gt;")


def render_summary_markdown(summary: dict[str, Any]) -> str:
    suite = summary["suite"]
    metrics = summary["core_metrics"]
    matrix = summary["confusion_matrix"]
    lines = [
        "# RenGuard benchmark summary", "",
        f"- Run ID: `{summary['run_id']}`",
        f"- Suite: {suite['name']} {suite['version']} (public: `{not suite.get('private_holdout', False)}`)",
        f"- Suite hash: `{suite['content_hash']}`", f"- Condition(s): `{summary['condition']}`",
        f"- Model: `{_display(summary['model']['model'])}` via `{_display(summary['model']['adapter'])}`",
        f"- Judge relationship: `{summary['judge'].get('relationship', 'NONE')}`",
        f"- Scenario-runs: {summary['counts']['scenario_runs']} ({summary['counts']['unresolved_semantic']} unresolved)",
        f"- Mutations used: `{summary['counts']['mutation_derived'] > 0}`", "",
        "## Binary security metrics", "",
        "BOUNDARY cases are excluded. Unresolved observations are excluded from metric denominators and disclosed.", "",
        "| TP | FP | TN | FN | Resolved | Unresolved |", "| ---: | ---: | ---: | ---: | ---: | ---: |",
        f"| {matrix['tp']} | {matrix['fp']} | {matrix['tn']} | {matrix['fn']} | {matrix['resolved']} | {matrix['unresolved']} |", "",
        "| Metric | Value |", "| --- | ---: |",
    ]
    for key in ("precision", "recall", "f1", "specificity", "false_positive_rate", "false_negative_rate", "accuracy"):
        lines.append(f"| {key} | {_display(metrics[key])} |")
    lines.extend(["", "## Separate reports", "", f"- Clean controls: {summary['clean_controls']}", f"- Boundary cases: {summary['boundary']}", f"- Exact-risk evaluation: {summary['risk_metrics']}", "", "## Limitations", ""])
    lines.extend(f"- {item}" for item in summary["limitations"])
    lines.extend(["", "Synthetic fixture and replay results are engineering tests, not official RenGuard performance. No conclusion about causal significance is made.", ""])
    return "\n".join(lines)


def compare_runs(run_a: Any, run_b: Any) -> dict[str, Any]:
    manifest_a = read_json(run_a / "run-manifest.json")
    manifest_b = read_json(run_b / "run-manifest.json")
    summary_a = read_json(run_a / "summary.json")
    summary_b = read_json(run_b / "summary.json")
    if manifest_a["suite"]["content_hash"] != manifest_b["suite"]["content_hash"]:
        raise ValueError("suite content hash mismatch")
    if manifest_a["scoring_version"] != manifest_b["scoring_version"]:
        raise ValueError("scoring version mismatch")
    if manifest_a["filters"] != manifest_b["filters"]:
        raise ValueError("run filters mismatch")
    scores_a = {(item["runtime_id"], item["run_index"]): item for item in read_jsonl(run_a / "scores.jsonl")}
    scores_b = {(item["runtime_id"], item["run_index"]): item for item in read_jsonl(run_b / "scores.jsonl")}
    paired = {"a_pass_b_pass": 0, "a_pass_b_fail": 0, "a_fail_b_pass": 0, "a_fail_b_fail": 0, "unresolved_pairs": 0}
    for key in sorted(set(scores_a) & set(scores_b)):
        a, b = scores_a[key]["semantic_outcome"], scores_b[key]["semantic_outcome"]
        if "UNRESOLVED" in {a, b}:
            paired["unresolved_pairs"] += 1
        else:
            paired[f"a_{a.lower()}_b_{b.lower()}"] += 1
    metric_names = ("recall", "false_positive_rate", "f1")
    deltas = {name: None if summary_a["core_metrics"][name] is None or summary_b["core_metrics"][name] is None else summary_b["core_metrics"][name] - summary_a["core_metrics"][name] for name in metric_names}
    deltas["semantic_pass_rate"] = None if summary_a["semantic_pass_rate"] is None or summary_b["semantic_pass_rate"] is None else summary_b["semantic_pass_rate"] - summary_a["semantic_pass_rate"]
    for name, path in (("risk_exact_match_rate", ("risk_metrics", "exact_score_match_rate")), ("format_compliance", ("format_metrics", "pass_rate"))):
        value_a = summary_a[path[0]][path[1]]
        value_b = summary_b[path[0]][path[1]]
        deltas[name] = None if value_a is None or value_b is None else value_b - value_a
    return {"run_a": manifest_a["run_id"], "run_b": manifest_b["run_id"], "configuration_differences": {key: [manifest_a.get(key), manifest_b.get(key)] for key in ("condition", "target", "model_parameters") if manifest_a.get(key) != manifest_b.get(key)}, "metric_deltas_b_minus_a": deltas, "paired_analysis": paired, "causal_significance_claimed": False}
