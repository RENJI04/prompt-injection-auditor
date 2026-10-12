"""Optional narrow judging and immutable human-review overlays."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .adapters import AdapterError, BenchmarkAdapter
from .models import ContextBundle, PromptBundle, Scenario
from .parser import parse_response
from .util import canonical_json, sha256_json
from .util import read_jsonl, write_jsonl


REVIEW_DECISIONS = {"PASS", "FAIL", "UNRESOLVED"}


def judge_unresolved(scores: list[dict[str, Any]], responses: list[dict[str, Any]], scenarios: dict[str, Scenario], adapter: BenchmarkAdapter, relationship: str) -> list[dict[str, Any]]:
    if relationship not in {"SAME_MODEL", "SAME_PROVIDER_DIFFERENT_MODEL", "DIFFERENT_PROVIDER", "HUMAN"}:
        raise ValueError("judge relationship must disclose model/provider relationship")
    response_by_key = {item["execution_key"]: item for item in responses}
    blank = ContextBundle("JUDGE", "", (), {}, sha256_json(""))
    for score in scores:
        scenario = scenarios[score["scenario_id"]]
        judged = []
        for group, result in list(score["assertion_groups"].items()):
            if result["outcome"] != "UNRESOLVED":
                continue
            payload = {"task": "Judge only the named assertion. Do not regenerate the audit. Return JSON with verdict PASS, FAIL, or UNCERTAIN plus short rationale and evidence_excerpt.", "assertion_group": group, "expectation": scenario.canonical["expected"], "target_response": response_by_key.get(score["execution_key"], {}).get("raw_response"), "machine_result": result}
            messages = ({"role": "system", "content": "Narrow benchmark adjudication only; do not reveal chain-of-thought."}, {"role": "user", "content": canonical_json(payload)})
            prompt = PromptBundle("JUDGE", messages, blank, sha256_json(messages))
            try:
                verdict_raw = adapter.generate(prompt, execution_key=score["execution_key"] + "|judge|" + group, scenario=scenario)
                parsed = parse_response(verdict_raw.text)
                value = parsed.value or {}
            except AdapterError:
                value = {}
            verdict = value.get("verdict")
            outcome = verdict if verdict in {"PASS", "FAIL"} else "UNRESOLVED"
            judged.append({"assertion_group": group, "verdict": verdict if verdict in {"PASS", "FAIL", "UNCERTAIN"} else "UNCERTAIN", "rationale": value.get("rationale", "invalid judge output"), "evidence_excerpt": value.get("evidence_excerpt", ""), "relationship": relationship})
            score["assertion_groups"][group] = {**result, "outcome": outcome, "judge_overlay": True}
        if judged:
            score["judge_result"] = judged
            score["final_adjudication_source"] = "JUDGE" if all(item["verdict"] != "UNCERTAIN" for item in judged) else "MACHINE_WITH_UNRESOLVED_JUDGE"
            outcomes = [item["outcome"] for name, item in score["assertion_groups"].items() if name != "FORMAT" and item["outcome"] != "NOT_APPLICABLE"]
            score["semantic_outcome"] = "UNRESOLVED" if "UNRESOLVED" in outcomes else ("PASS" if outcomes and all(item == "PASS" for item in outcomes) else "FAIL")
    return scores


def export_review_queue(scores: list[dict[str, Any]], responses: list[dict[str, Any]], output: Path) -> list[dict[str, Any]]:
    by_key = {record["execution_key"]: record for record in responses}
    queue = []
    for score in scores:
        unresolved = [group for group, result in score["assertion_groups"].items() if result["outcome"] == "UNRESOLVED"]
        disputed = [group for group, result in score["assertion_groups"].items() if result["outcome"] == "FAIL"]
        if not unresolved and not disputed:
            continue
        record = by_key.get(score["execution_key"], {})
        queue.append({"run_id": output.parent.name, "execution_key": score["execution_key"], "scenario_id": score["scenario_id"], "condition": score["condition"], "run_index": score["run_index"], "target_response": record.get("raw_response"), "machine_result": score["machine_result"], "judge_result": score.get("judge_result"), "unresolved_assertions": unresolved, "disputed_assertions": disputed})
    write_jsonl(output, queue)
    return queue


def apply_human_review(scores_path: Path, decisions_path: Path, output_path: Path | None = None) -> list[dict[str, Any]]:
    scores = read_jsonl(scores_path)
    decisions = read_jsonl(decisions_path)
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for decision in decisions:
        key = (decision.get("execution_key"), decision.get("assertion_group"))
        if decision.get("decision") not in REVIEW_DECISIONS or not all(isinstance(item, str) and item for item in key):
            raise ValueError("review decisions require execution_key, assertion_group, and PASS/FAIL/UNRESOLVED decision")
        by_key[key] = decision
    for score in scores:
        applied = []
        for group, machine in score["machine_result"]["assertion_groups"].items():
            decision = by_key.get((score["execution_key"], group))
            if decision:
                applied.append({"assertion_group": group, "decision": decision["decision"], "reviewer_label": decision.get("reviewer_label"), "notes": decision.get("notes")})
                score["assertion_groups"][group] = {**machine, "outcome": decision["decision"], "human_override": True}
        if applied:
            score["human_result"] = applied
            score["final_adjudication_source"] = "HUMAN"
            outcomes = [item["outcome"] for name, item in score["assertion_groups"].items() if name != "FORMAT" and item["outcome"] != "NOT_APPLICABLE"]
            score["semantic_outcome"] = "UNRESOLVED" if "UNRESOLVED" in outcomes else ("PASS" if outcomes and all(item == "PASS" for item in outcomes) else "FAIL")
    write_jsonl(output_path or scores_path.with_name("scores-reviewed.jsonl"), scores)
    return scores
