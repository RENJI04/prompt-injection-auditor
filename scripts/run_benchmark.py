#!/usr/bin/env python3
"""Run, replay, score, summarize, compare, and review RenGuard v2 benchmarks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from renguard_benchmark import ARTIFACT_SCHEMA_VERSION, RUNNER_VERSION, SCORING_VERSION
from renguard_benchmark.adapters import CommandAdapter, FixtureAdapter, ReplayAdapter
from renguard_benchmark.execution import rescore_run, run_benchmark
from renguard_benchmark.loader import filter_scenarios, load_suite
from renguard_benchmark.mutations import load_mutation_recipes, make_runtime_case
from renguard_benchmark.reporting import compare_runs, render_summary_markdown
from renguard_benchmark.review import apply_human_review, export_review_queue
from renguard_benchmark.util import read_json, read_jsonl, sha256_file, sha256_json, write_json


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUITE = ROOT / "evals" / "v2"
DEFAULT_OUTPUT = ROOT / "benchmark-runs"


def _csv(value: str | None) -> set[str] | None:
    return set(filter(None, (item.strip() for item in value.split(",")))) if value else None


def _filters(args: argparse.Namespace) -> dict[str, Any]:
    return {name: sorted(value) if value else None for name in ("ids", "categories", "kinds", "languages", "techniques", "risk_modes") if (value := _csv(getattr(args, name, None))) is not None} | {name: getattr(args, name, None) for name in ("multi_turn", "chain") if getattr(args, name, None) is not None}


def _selected(args: argparse.Namespace, suite: Any) -> tuple[Any, ...]:
    values = {name: _csv(getattr(args, name, None)) for name in ("ids", "categories", "kinds", "languages", "techniques", "risk_modes")}
    return filter_scenarios(suite.scenarios, **values, multi_turn=getattr(args, "multi_turn", None), chain=getattr(args, "chain", None))


def _pricing(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    value = read_json(path)
    required = {"model", "input_per_million", "output_per_million", "currency"}
    if not isinstance(value, dict) or set(value) != required or not isinstance(value["model"], str) or not isinstance(value["currency"], str) or any(not isinstance(value[key], (int, float)) or isinstance(value[key], bool) or value[key] < 0 for key in ("input_per_million", "output_per_million")):
        raise ValueError("pricing file must contain model, non-negative input/output rates, and currency")
    return value


def _add_filters(parser: argparse.ArgumentParser) -> None:
    for name in ("ids", "categories", "kinds", "languages", "techniques", "risk-modes"):
        parser.add_argument("--" + name, help="comma-separated filter")
    parser.add_argument("--multi-turn", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--chain", action=argparse.BooleanOptionalAction, default=None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"runner {RUNNER_VERSION}; scoring {SCORING_VERSION}; artifacts {ARTIFACT_SCHEMA_VERSION}")
    sub = parser.add_subparsers(dest="command")
    validate = sub.add_parser("validate", help="validate and hash a suite without model execution")
    validate.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    plan = sub.add_parser("plan", help="show deterministic execution keys without execution")
    plan.add_argument("--suite", type=Path, default=DEFAULT_SUITE); plan.add_argument("--condition", choices=("RENGuard", "BASELINE", "BOTH"), default="BOTH"); plan.add_argument("--runs", type=int, default=1); _add_filters(plan)
    run = sub.add_parser("run", help="execute an explicitly selected adapter")
    run.add_argument("--suite", type=Path, default=DEFAULT_SUITE); run.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT); run.add_argument("--run-id"); run.add_argument("--condition", choices=("RENGuard", "BASELINE", "BOTH"), default="RENGuard"); run.add_argument("--runs", type=int, default=1); run.add_argument("--context", choices=("CORE", "CONDITIONAL", "FULL"), default="CONDITIONAL"); run.add_argument("--concurrency", type=int, default=1); run.add_argument("--retries", type=int, default=0); run.add_argument("--resume", action="store_true"); run.add_argument("--execute-live", action="store_true"); run.add_argument("--adapter", choices=("fixture", "replay", "command"), default="fixture"); run.add_argument("--fixture-profile", default="perfect"); run.add_argument("--replay-path", type=Path); run.add_argument("--command-arg", action="append", default=[]); run.add_argument("--max-output-bytes", type=int, default=1_000_000); run.add_argument("--timeout", type=float, default=60.0); run.add_argument("--mutation", action="append", default=[]); run.add_argument("--pricing", type=Path); _add_filters(run)
    run.add_argument("--minimal-artifacts", action="store_true", help="do not retain raw responses (recommended for private holdouts)")
    for name in ("score", "summarize"):
        command = sub.add_parser(name, help=f"{name} captured responses without model execution")
        command.add_argument("--suite", type=Path, default=DEFAULT_SUITE); command.add_argument("--run-dir", type=Path, required=True); command.add_argument("--pricing", type=Path)
        command.add_argument("--judge-fixture-profile", choices=("judge-pass", "judge-uncertainty"))
        command.add_argument("--judge-relationship", choices=("SAME_MODEL", "SAME_PROVIDER_DIFFERENT_MODEL", "DIFFERENT_PROVIDER", "HUMAN"))
    compare = sub.add_parser("compare", help="compare compatible completed runs"); compare.add_argument("--run-a", type=Path, required=True); compare.add_argument("--run-b", type=Path, required=True); compare.add_argument("--output", type=Path)
    export = sub.add_parser("export-review", help="export unresolved/disputed cases for offline review"); export.add_argument("--run-dir", type=Path, required=True); export.add_argument("--output", type=Path)
    apply = sub.add_parser("apply-review", help="apply human decisions without overwriting machine results"); apply.add_argument("--run-dir", type=Path, required=True); apply.add_argument("--decisions", type=Path, required=True); apply.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser(); args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(); return 0
    if args.command == "validate":
        suite = load_suite(args.suite); print(json.dumps({"suite": suite.manifest["suite_name"], "version": suite.manifest["suite_version"], "scenarios": len(suite.scenarios), "suite_hash": suite.suite_hash, "runner_version": RUNNER_VERSION, "scoring_version": SCORING_VERSION, "artifact_schema_version": ARTIFACT_SCHEMA_VERSION}, indent=2)); return 0
    if args.command == "plan":
        suite = load_suite(args.suite); selected = _selected(args, suite); conditions = ["RENGuard", "BASELINE"] if args.condition == "BOTH" else [args.condition]; keys = [f"{scenario.id}|{condition}|{index}" for scenario in selected for condition in conditions for index in range(1, args.runs + 1)]; print(json.dumps({"scenario_count": len(selected), "execution_count": len(keys), "execution_keys": keys}, indent=2)); return 0
    if args.command == "run":
        suite = load_suite(args.suite); selected = _selected(args, suite)
        if not selected: raise ValueError("filters selected no scenarios")
        recipes = load_mutation_recipes(suite.root); cases = [make_runtime_case(item) for item in selected]
        for mutation in args.mutation:
            if mutation not in recipes: raise ValueError(f"unknown mutation {mutation}")
            for scenario in selected:
                if scenario.canonical.get("mutation_eligible") and mutation in scenario.canonical.get("mutation_ids", []): cases.append(make_runtime_case(scenario, mutation))
        if args.adapter == "fixture": adapter = FixtureAdapter(args.fixture_profile)
        elif args.adapter == "replay":
            if args.replay_path is None: raise ValueError("replay adapter requires --replay-path")
            adapter = ReplayAdapter(args.replay_path)
        else:
            if not args.command_arg: raise ValueError("command adapter requires one or more --command-arg values")
            adapter = CommandAdapter(args.command_arg, args.timeout, args.max_output_bytes)
        conditions = ["RENGuard", "BASELINE"] if args.condition == "BOTH" else [args.condition]
        adapter_configuration = {
            "fixture_profile": args.fixture_profile if args.adapter == "fixture" else None,
            "replay_file_hash": sha256_file(args.replay_path) if args.adapter == "replay" and args.replay_path else None,
            "command_hash": sha256_json(args.command_arg) if args.adapter == "command" else None,
        }
        run_dir = run_benchmark(repository_root=ROOT, suite=suite, cases=cases, conditions=conditions, adapter=adapter, output_base=args.output_dir, run_id=args.run_id, runs=args.runs, context_mode=args.context, concurrency=args.concurrency, retry_count=args.retries, execute_live=args.execute_live, resume=args.resume, filters=_filters(args), mutation_ids=args.mutation, parameters={"temperature": None, "top_p": None, "max_output_tokens": None, "seed": None, "timeout": args.timeout, "retry_policy": {"transport_only": True, "retries": args.retries}, "concurrency": args.concurrency, **adapter_configuration}, argv=sys.argv if argv is None else [sys.argv[0], *argv], private_holdout=args.suite.resolve() != DEFAULT_SUITE.resolve(), pricing=_pricing(args.pricing), minimal_artifacts=args.minimal_artifacts); print(run_dir); return 0
    if args.command in {"score", "summarize"}:
        judge = FixtureAdapter(args.judge_fixture_profile) if args.judge_fixture_profile else None
        if judge is not None and args.judge_relationship is None:
            raise ValueError("optional judge requires --judge-relationship")
        summary = rescore_run(args.run_dir.resolve(), load_suite(args.suite), _pricing(args.pricing), judge, args.judge_relationship or "NONE"); print(render_summary_markdown(summary) if args.command == "summarize" else json.dumps(summary, indent=2)); return 0
    if args.command == "compare":
        comparison = compare_runs(args.run_a.resolve(), args.run_b.resolve());
        if args.output: write_json(args.output, comparison)
        print(json.dumps(comparison, indent=2)); return 0
    if args.command == "export-review":
        output = args.output or args.run_dir / "review_queue.jsonl"; queue = export_review_queue(read_jsonl(args.run_dir / "scores.jsonl"), read_jsonl(args.run_dir / "responses.jsonl"), output); print(f"exported {len(queue)} records to {output}"); return 0
    if args.command == "apply-review":
        output = args.output or args.run_dir / "scores-reviewed.jsonl"; reviewed = apply_human_review(args.run_dir / "scores.jsonl", args.decisions, output); print(f"wrote {len(reviewed)} reviewed scores to {output}"); return 0
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, PermissionError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
