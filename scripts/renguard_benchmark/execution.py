"""Execution planning, retries, conservative concurrency, resume, and artifacts."""

from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .adapters import AdapterError, BenchmarkAdapter, TransientAdapterError
from .evaluator import evaluate_response
from .metrics import summarize
from .models import RuntimeCase, Suite
from .parser import parse_response
from .prompt_builder import ContextAssembler, build_prompt
from .provenance import build_manifest
from .reporting import render_summary_markdown
from .review import judge_unresolved
from .util import read_json, read_jsonl, safe_child, safe_run_id, sha256_file, sha256_json, utc_now, write_json, write_jsonl


def execution_key(runtime_id: str, condition: str, run_index: int) -> str:
    return f"{runtime_id}|{condition}|{run_index}"


def generated_run_id(condition: str) -> str:
    return safe_run_id(f"{utc_now().replace(':', '').replace('-', '')}-{condition.lower()}-{uuid.uuid4().hex[:12]}")


def plan_cases(cases: list[RuntimeCase], conditions: list[str], runs: int) -> list[dict[str, Any]]:
    if runs < 1:
        raise ValueError("runs must be positive")
    return [{"case": case, "condition": condition, "run_index": index, "execution_key": execution_key(case.runtime_id, condition, index)} for case in cases for condition in conditions for index in range(1, runs + 1)]


def _execute_one(item: dict[str, Any], adapter: BenchmarkAdapter, assembler: ContextAssembler, context_mode: str, retry_count: int) -> dict[str, Any]:
    case, condition = item["case"], item["condition"]
    context = assembler.assemble(case.scenario, context_mode, condition)
    prompt = build_prompt(case, condition, context)
    errors: list[str] = []
    for attempt in range(1, retry_count + 2):
        try:
            result = adapter.generate(prompt, execution_key=item["execution_key"], scenario=case.scenario)
            break
        except TransientAdapterError as exc:
            errors.append(str(exc))
            if attempt > retry_count:
                return {"execution_key": item["execution_key"], "runtime_id": case.runtime_id, "scenario_id": case.scenario.id, "condition": condition, "run_index": item["run_index"], "mutation_id": case.mutation_id, "status": "TRANSPORT_FAILED", "attempts": attempt, "transport_errors": errors, "prompt_hash": prompt.prompt_hash, "skill_hash": sha256_file(assembler.root / "SKILL.md"), "context_hash": context.assembled_hash, "context_files": list(context.files), "context_file_hashes": context.file_hashes}
            time.sleep(min(0.05 * attempt, 0.2))
        except AdapterError as exc:
            return {"execution_key": item["execution_key"], "runtime_id": case.runtime_id, "scenario_id": case.scenario.id, "condition": condition, "run_index": item["run_index"], "mutation_id": case.mutation_id, "status": "FAILED", "attempts": attempt, "transport_errors": [str(exc)], "prompt_hash": prompt.prompt_hash, "skill_hash": sha256_file(assembler.root / "SKILL.md"), "context_hash": context.assembled_hash, "context_files": list(context.files), "context_file_hashes": context.file_hashes}
    return {"execution_key": item["execution_key"], "runtime_id": case.runtime_id, "scenario_id": case.scenario.id, "condition": condition, "run_index": item["run_index"], "mutation_id": case.mutation_id, "status": result.status, "attempts": attempt, "transport_errors": errors + result.errors, "adapter": adapter.name, "provider": result.provider, "model": result.model, "latency_seconds": result.latency_seconds, "usage": result.usage, "prompt_hash": prompt.prompt_hash, "skill_hash": sha256_file(assembler.root / "SKILL.md"), "context_hash": context.assembled_hash, "context_files": list(context.files), "context_file_hashes": context.file_hashes, "raw_response": result.text}


def score_records(records: list[dict[str, Any]], suite: Suite) -> list[dict[str, Any]]:
    scenarios = {scenario.id: scenario for scenario in suite.scenarios}
    scores = []
    for record in records:
        scenario = scenarios.get(record.get("scenario_id"))
        if scenario is None:
            raise ValueError(f"unknown response scenario {record.get('scenario_id')!r}")
        parsed = parse_response(record.get("raw_response", "")) if record.get("status") == "COMPLETED" else parse_response("")
        score = evaluate_response(scenario, parsed)
        expected = scenario.canonical["expected"]
        score.update({key: record.get(key) for key in ("execution_key", "runtime_id", "condition", "run_index", "mutation_id")})
        score.update({"language": scenario.canonical["language"], "primary_technique": expected["expected_primary_technique"], "risk_severity": expected["expected_risk"].get("severity"), "expected_confidence": expected["expected_confidence"], "multi_turn": bool(scenario.canonical.get("turns")), "attack_chain": scenario.kind == "CHAIN", "machine_result": {"assertion_groups": score["assertion_groups"], "semantic_outcome": score["semantic_outcome"]}, "judge_result": None, "human_result": None, "final_adjudication_source": "MACHINE"})
        scores.append(score)
    return scores


def run_benchmark(*, repository_root: Path, suite: Suite, cases: list[RuntimeCase], conditions: list[str], adapter: BenchmarkAdapter,
                  output_base: Path, run_id: str | None, runs: int, context_mode: str, concurrency: int,
                  retry_count: int, execute_live: bool, resume: bool, filters: dict[str, Any], mutation_ids: list[str],
                  parameters: dict[str, Any], argv: list[str], private_holdout: bool, pricing: dict[str, Any] | None = None,
                  minimal_artifacts: bool = False) -> Path:
    if adapter.live_capable and not execute_live:
        raise PermissionError("live-capable adapters require --execute-live")
    if concurrency < 1 or concurrency > 64:
        raise ValueError("concurrency must be from 1 through 64")
    chosen_id = run_id or generated_run_id("-".join(condition.lower() for condition in conditions))
    run_dir = safe_child(output_base, chosen_id)
    if run_dir.exists() and (run_dir / "run-manifest.json").exists() and not resume:
        raise FileExistsError(f"run directory already exists: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)
    response_path = run_dir / "responses.jsonl"
    if resume and (run_dir / "run-manifest.json").exists():
        existing_manifest = read_json(run_dir / "run-manifest.json")
        expected_resume = {
            "suite_hash": suite.suite_hash, "condition": conditions, "repeats": runs,
            "filters": filters, "parameters": parameters,
            "target": {"adapter": adapter.name, "provider": adapter.provider, "model": adapter.model},
            "mutation_policy": {"selected": mutation_ids, "default": "none"},
            "artifact_mode": "MINIMAL_NO_RAW_RESPONSES" if minimal_artifacts else "REPRODUCIBLE_RAW_RESPONSES",
        }
        actual_resume = {
            "suite_hash": existing_manifest.get("suite", {}).get("content_hash"),
            "condition": existing_manifest.get("condition"), "repeats": existing_manifest.get("repeats"),
            "filters": existing_manifest.get("filters"), "parameters": existing_manifest.get("model_parameters"),
            "target": existing_manifest.get("target"),
            "mutation_policy": existing_manifest.get("mutation_policy"),
            "artifact_mode": existing_manifest.get("artifact_mode"),
        }
        if actual_resume != expected_resume:
            raise ValueError("resume configuration does not match the existing run manifest")
    prior = read_jsonl(response_path) if resume and response_path.exists() else []
    completed = {record["execution_key"] for record in prior if record.get("status") == "COMPLETED"}
    plan = [item for item in plan_cases(cases, conditions, runs) if item["execution_key"] not in completed]
    assembler = ContextAssembler(repository_root)
    all_contexts = [assembler.assemble(case.scenario, context_mode, condition) for case in cases for condition in conditions]
    contexts = list({item.assembled_hash: item for item in all_contexts}.values())
    manifest = build_manifest(run_id=chosen_id, repository_root=repository_root, suite=suite, condition=conditions, adapter=adapter, contexts=contexts, runs=runs, filters=filters, mutation_ids=mutation_ids, parameters=parameters, argv=argv, private_holdout=private_holdout, pricing=pricing, minimal_artifacts=minimal_artifacts)
    write_json(run_dir / "run-manifest.json", manifest)
    new: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(_execute_one, item, adapter, assembler, context_mode, retry_count) for item in plan]
        for future in as_completed(futures):
            new.append(future.result())
    records = sorted(prior + new, key=lambda item: item["execution_key"])
    if minimal_artifacts and prior:
        prior_scores = {
            item["execution_key"]: item
            for item in read_jsonl(run_dir / "scores.jsonl")
        } if (run_dir / "scores.jsonl").exists() else {}
        scores = sorted(
            list(prior_scores.values()) + score_records(new, suite),
            key=lambda item: item["execution_key"],
        )
    else:
        scores = score_records(records, suite)
    persisted_records = records
    if minimal_artifacts:
        persisted_records = []
        for record in records:
            stored = dict(record)
            raw = stored.pop("raw_response", None)
            stored["raw_response_hash"] = sha256_json(raw) if raw is not None else None
            persisted_records.append(stored)
    write_jsonl(response_path, persisted_records)
    write_jsonl(run_dir / "scores.jsonl", scores)
    manifest["status"] = "COMPLETED" if all(record.get("status") == "COMPLETED" for record in records) else "COMPLETED_WITH_ERRORS"
    manifest["ended_at"] = utc_now()
    write_json(run_dir / "run-manifest.json", manifest)
    summary = summarize(scores, manifest, records, pricing)
    write_json(run_dir / "summary.json", summary)
    (run_dir / "summary.md").write_text(render_summary_markdown(summary), encoding="utf-8")
    return run_dir


def rescore_run(run_dir: Path, suite: Suite, pricing: dict[str, Any] | None = None,
                judge_adapter: BenchmarkAdapter | None = None,
                judge_relationship: str = "NONE") -> dict[str, Any]:
    manifest = read_json(run_dir / "run-manifest.json")
    records = read_jsonl(run_dir / "responses.jsonl")
    if manifest.get("artifact_mode") == "MINIMAL_NO_RAW_RESPONSES":
        raise ValueError("minimal artifact runs cannot be rescored because raw responses were not retained")
    scores = score_records(records, suite)
    if judge_adapter is not None:
        scores = judge_unresolved(
            scores, records, {scenario.id: scenario for scenario in suite.scenarios},
            judge_adapter, judge_relationship,
        )
        manifest["judge"] = {
            "adapter": judge_adapter.name, "provider": judge_adapter.provider,
            "model": judge_adapter.model, "relationship": judge_relationship,
        }
        write_json(run_dir / "run-manifest.json", manifest)
    write_jsonl(run_dir / "scores.jsonl", scores)
    summary = summarize(scores, manifest, records, pricing)
    write_json(run_dir / "summary.json", summary)
    (run_dir / "summary.md").write_text(render_summary_markdown(summary), encoding="utf-8")
    return summary
