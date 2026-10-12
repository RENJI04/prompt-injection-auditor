from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.renguard_benchmark import ARTIFACT_SCHEMA_VERSION, RUNNER_VERSION, SCORING_VERSION
from scripts.renguard_benchmark.adapters import AdapterError, BenchmarkAdapter, CommandAdapter, FixtureAdapter, ReplayAdapter, TransientAdapterError
from scripts.renguard_benchmark.evaluator import calculate_risk_score, evaluate_response, severity_for_score
from scripts.renguard_benchmark.execution import plan_cases, run_benchmark, score_records
from scripts.renguard_benchmark.loader import SuiteError, filter_scenarios, load_suite
from scripts.renguard_benchmark.metrics import confusion_matrix, core_metrics, summarize
from scripts.renguard_benchmark.models import RuntimeCase, Scenario
from scripts.renguard_benchmark.mutations import UNSUPPORTED_AUTOMATIC, make_runtime_case
from scripts.renguard_benchmark.parser import parse_response
from scripts.renguard_benchmark.prompt_builder import ContextAssembler, build_prompt, runtime_view
from scripts.renguard_benchmark.reporting import compare_runs, render_summary_markdown
from scripts.renguard_benchmark.review import apply_human_review, export_review_queue, judge_unresolved
from scripts.renguard_benchmark.statistics import latency_summary, safe_ratio, stability_label, wilson_interval
from scripts.renguard_benchmark.util import read_json, read_jsonl, safe_child, sha256_json, write_jsonl


ROOT = Path(__file__).resolve().parents[1]
SUITE_PATH = ROOT / "evals" / "v2"


class BenchmarkUnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.suite = load_suite(SUITE_PATH)
        cls.by_id = {scenario.id: scenario for scenario in cls.suite.scenarios}
        cls.assembler = ContextAssembler(ROOT)

    def prompt(self, scenario_id: str = "RG-EVAL-V2-001", condition: str = "RENGuard"):
        case = make_runtime_case(self.by_id[scenario_id])
        context = self.assembler.assemble(case.scenario, "CONDITIONAL", condition)
        return build_prompt(case, condition, context)

    def fixture_parse(self, scenario_id: str, profile: str = "perfect"):
        scenario = self.by_id[scenario_id]
        result = FixtureAdapter(profile).generate(self.prompt(scenario_id), execution_key="x", scenario=scenario)
        return parse_response(result.text)

    def test_versions_are_separate(self) -> None:
        self.assertEqual(("0.1.0", "0.1.0", "0.1.0"), (RUNNER_VERSION, SCORING_VERSION, ARTIFACT_SCHEMA_VERSION))

    def test_suite_loads_72_in_deterministic_order(self) -> None:
        self.assertEqual(72, len(self.suite.scenarios))
        self.assertEqual(sorted(item.id for item in self.suite.scenarios), [item.id for item in self.suite.scenarios])

    def test_suite_hash_is_deterministic(self) -> None:
        self.assertEqual(self.suite.suite_hash, load_suite(SUITE_PATH).suite_hash)

    def test_duplicate_scenario_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            subprocess.run(["cp", "-R", str(SUITE_PATH) + "/.", str(target)], check=True)
            manifest = read_json(target / "manifest.json")
            data = read_json(target / manifest["scenario_files"][0])
            data["scenarios"].append(data["scenarios"][0])
            (target / manifest["scenario_files"][0]).write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(SuiteError):
                load_suite(target)

    def test_filters_cover_all_requested_dimensions(self) -> None:
        selected = filter_scenarios(self.suite.scenarios, ids={"RG-EVAL-V2-010"}, categories={"RAG_RETRIEVAL"}, kinds={"ATTACK"}, languages={"zh-CN"}, techniques={"RG-RA-002"}, multi_turn=False, chain=False, risk_modes={"BAND"})
        self.assertEqual(["RG-EVAL-V2-010"], [item.id for item in selected])

    def test_runtime_view_is_a_deep_copy(self) -> None:
        scenario = self.by_id["RG-EVAL-V2-001"]
        view = runtime_view(scenario)
        view["input"]["content"] = "changed"
        self.assertNotEqual("changed", scenario.canonical["input"]["content"])

    def test_ground_truth_is_absent_from_every_prompt(self) -> None:
        forbidden = ("RG-EVAL-V2-", "must_detect", "must_not_detect", "expected_primary_technique", "expected_risk", "expected_confidence", "ordered_attack_chain", '"kind"', '"category"', '"notes"')
        for scenario in self.suite.scenarios:
            prompt = self.prompt(scenario.id)
            serialized = json.dumps(prompt.messages)
            self.assertFalse(any(value in serialized for value in forbidden), scenario.id)

    def test_baseline_has_no_renguard_context(self) -> None:
        prompt = self.prompt(condition="BASELINE")
        self.assertEqual("", prompt.context.text)
        self.assertNotIn("Apply the following RenGuard", prompt.messages[0]["content"])

    def test_renguard_has_guidance_and_baseline_contract_is_same(self) -> None:
        renguard = self.prompt(condition="RENGuard")
        baseline = self.prompt(condition="BASELINE")
        self.assertIn("Apply the following RenGuard", renguard.messages[0]["content"])
        self.assertIn("Response contract", baseline.messages[0]["content"])

    def test_conditional_context_routes_rag(self) -> None:
        scenario = next(item for item in self.suite.scenarios if item.canonical["target_profile"]["rag"] is True)
        context = self.assembler.assemble(scenario, "CONDITIONAL", "RENGuard")
        self.assertIn("references/rag-security.md", context.files)

    def test_conditional_context_does_not_activate_absent_domains(self) -> None:
        context = self.assembler.assemble(self.by_id["RG-EVAL-V2-001"], "CONDITIONAL", "RENGuard")
        self.assertNotIn("references/rag-security.md", context.files)
        self.assertNotIn("references/memory-security.md", context.files)

    def test_full_context_loads_all_specialized_references(self) -> None:
        context = self.assembler.assemble(self.by_id["RG-EVAL-V2-001"], "FULL", "RENGuard")
        self.assertIn("references/output-security.md", context.files)
        self.assertIn("references/mcp-security.md", context.files)

    def test_context_hash_changes_by_condition(self) -> None:
        self.assertNotEqual(self.prompt(condition="RENGuard").context.assembled_hash, self.prompt(condition="BASELINE").context.assembled_hash)

    def test_multiturn_order_is_preserved(self) -> None:
        scenario = next(item for item in self.suite.scenarios if item.canonical.get("turns"))
        prompt = self.prompt(scenario.id)
        self.assertEqual(scenario.canonical["turns"], list(prompt.messages[-len(scenario.canonical["turns"]):]))

    def test_parser_accepts_plain_and_fenced_json(self) -> None:
        value = '{"material_vulnerability":false,"findings":[]}'
        self.assertEqual("PARSED", parse_response(value).state)
        self.assertEqual("PARSED", parse_response("```json\n" + value + "\n```").state)

    def test_parser_marks_partial_without_inventing(self) -> None:
        parsed = parse_response('{"findings":[]}')
        self.assertEqual("PARTIALLY_PARSED", parsed.state)
        self.assertNotIn("material_vulnerability", parsed.value)

    def test_parser_marks_unparseable(self) -> None:
        self.assertEqual("UNPARSEABLE", parse_response("not-json").state)

    def test_perfect_attack_passes_detection_and_technique(self) -> None:
        result = evaluate_response(self.by_id["RG-EVAL-V2-001"], self.fixture_parse("RG-EVAL-V2-001"))
        self.assertEqual("PASS", result["assertion_groups"]["SECURITY_DETECTION"]["outcome"])
        self.assertEqual("PASS", result["assertion_groups"]["TECHNIQUE_MAPPING"]["outcome"])

    def test_false_negative_is_not_retried_or_reclassified(self) -> None:
        result = evaluate_response(self.by_id["RG-EVAL-V2-001"], self.fixture_parse("RG-EVAL-V2-001", "false_negative"))
        self.assertEqual("FAIL", result["security_detection_outcome"])

    def test_clean_false_positive(self) -> None:
        result = evaluate_response(self.by_id["RG-EVAL-V2-061"], self.fixture_parse("RG-EVAL-V2-061", "false_positive"))
        self.assertEqual("FAIL", result["security_detection_outcome"])

    def test_may_detect_is_not_required(self) -> None:
        raw = copy.deepcopy(self.by_id["RG-EVAL-V2-001"].canonical)
        raw["expected"]["may_detect"] = ["RG-PI-002"]
        scenario = Scenario(raw, "synthetic-test")
        response = FixtureAdapter().generate(self.prompt(), execution_key="x", scenario=scenario)
        result = evaluate_response(scenario, parse_response(response.text))
        self.assertEqual("PASS", result["assertion_groups"]["TECHNIQUE_MAPPING"]["outcome"])

    def test_must_not_detect_violation(self) -> None:
        result = evaluate_response(self.by_id["RG-EVAL-V2-061"], self.fixture_parse("RG-EVAL-V2-061", "false_positive"))
        self.assertEqual("FAIL", result["assertion_groups"]["TECHNIQUE_MAPPING"]["outcome"])

    def test_unparseable_format_fails_security_unresolved(self) -> None:
        result = evaluate_response(self.by_id["RG-EVAL-V2-001"], parse_response("not-json"))
        self.assertEqual("FAIL", result["assertion_groups"]["FORMAT"]["outcome"])
        self.assertEqual("UNRESOLVED", result["security_detection_outcome"])

    def test_exact_risk_math_and_severity(self) -> None:
        dimensions = {key: 4 for key in "EPHVTDASBRXG"}
        self.assertEqual(10.0, calculate_risk_score(dimensions))
        self.assertEqual("CRITICAL", severity_for_score(10.0))

    def test_phase3_round_half_up_reference(self) -> None:
        dimensions = {"E": 3, "P": 3, "H": 4, "V": 1, "T": 2, "D": 3, "A": 1, "S": 1, "B": 2, "R": 4, "X": 2, "G": 2}
        self.assertEqual(6.0, calculate_risk_score(dimensions))

    def test_exact_risk_fixture_passes(self) -> None:
        result = evaluate_response(self.by_id["RG-EVAL-V2-061"], self.fixture_parse("RG-EVAL-V2-061"))
        self.assertEqual("PASS", result["assertion_groups"]["RISK"]["outcome"])

    def test_wrong_severity_fails_risk(self) -> None:
        result = evaluate_response(self.by_id["RG-EVAL-V2-001"], self.fixture_parse("RG-EVAL-V2-001", "wrong_severity"))
        self.assertEqual("FAIL", result["assertion_groups"]["RISK"]["outcome"])

    def test_exact_risk_error_reports_absolute_error(self) -> None:
        result = evaluate_response(self.by_id["RG-EVAL-V2-061"], self.fixture_parse("RG-EVAL-V2-061", "risk_score_error"))
        risk = result["assertion_groups"]["RISK"]
        self.assertEqual("FAIL", risk["outcome"])
        self.assertEqual(0.5, risk["absolute_error"])

    def test_confidence_is_independent(self) -> None:
        result = evaluate_response(self.by_id["RG-EVAL-V2-001"], self.fixture_parse("RG-EVAL-V2-001", "confidence_mismatch"))
        self.assertEqual("FAIL", result["assertion_groups"]["CONFIDENCE"]["outcome"])
        self.assertEqual("PASS", result["assertion_groups"]["RISK"]["outcome"])

    def test_redaction_failure_is_deterministic(self) -> None:
        result = evaluate_response(self.by_id["RG-EVAL-V2-001"], self.fixture_parse("RG-EVAL-V2-001", "redaction_failure"))
        self.assertEqual("FAIL", result["assertion_groups"]["REDACTION"]["outcome"])

    def test_required_control_layer_and_hardening_pattern(self) -> None:
        control_case = next(item for item in self.suite.scenarios if item.canonical["expected"]["required_control_layers"])
        pattern_raw = copy.deepcopy(control_case.canonical)
        pattern_raw["expected"]["required_hardening_patterns"] = ["RG-HARD-P-001"]
        pattern_case = Scenario(pattern_raw, "synthetic-test")
        for scenario, response_key, finding_key, missing_key in (
            (control_case, "control_layers", "control_layers", "missing_control_layers"),
            (pattern_case, "hardening_ids", "hardening_ids", "missing_hardening_patterns"),
        ):
            fixture = FixtureAdapter().generate(
                self.prompt(scenario.id), execution_key="x", scenario=scenario
            )
            value = parse_response(fixture.text).value
            assert value is not None
            value[response_key] = []
            for finding in value["findings"]:
                finding[finding_key] = []
            remediation = evaluate_response(scenario, parse_response(json.dumps(value)))["assertion_groups"]["REMEDIATION"]
            self.assertEqual("FAIL", remediation["outcome"])
            self.assertTrue(remediation[missing_key])

    def test_wrong_framework_does_not_change_detection(self) -> None:
        result = evaluate_response(self.by_id["RG-EVAL-V2-001"], self.fixture_parse("RG-EVAL-V2-001", "wrong_framework"))
        self.assertEqual("FAIL", result["assertion_groups"]["FRAMEWORK_MAPPING"]["outcome"])
        self.assertEqual("PASS", result["security_detection_outcome"])

    def test_boundary_excluded_from_confusion(self) -> None:
        score = {"kind": "BOUNDARY", "security_detection_outcome": "FAIL"}
        matrix = confusion_matrix([score])
        self.assertEqual((0, 1), (matrix["resolved"], matrix["excluded_boundary"]))

    def test_unresolved_excluded_from_confusion(self) -> None:
        matrix = confusion_matrix([{"kind": "ATTACK", "security_detection_outcome": "UNRESOLVED"}])
        self.assertEqual((0, 1), (matrix["resolved"], matrix["unresolved"]))

    def test_metric_math_known_matrix(self) -> None:
        metrics = core_metrics({"tp": 8, "fp": 2, "tn": 18, "fn": 2, "resolved": 30, "unresolved": 0, "excluded_boundary": 0})
        self.assertAlmostEqual(0.8, metrics["precision"]); self.assertAlmostEqual(0.8, metrics["recall"]); self.assertAlmostEqual(0.8, metrics["f1"]); self.assertAlmostEqual(0.9, metrics["specificity"]); self.assertAlmostEqual(0.1, metrics["false_positive_rate"]); self.assertAlmostEqual(0.2, metrics["false_negative_rate"]); self.assertAlmostEqual(26 / 30, metrics["accuracy"])

    def test_zero_denominator_is_not_zero(self) -> None:
        self.assertIsNone(safe_ratio(0, 0))
        self.assertIsNone(core_metrics({"tp": 0, "fp": 0, "tn": 0, "fn": 0, "resolved": 0, "unresolved": 0, "excluded_boundary": 0})["precision"])

    def test_wilson_known_interval(self) -> None:
        interval = wilson_interval(8, 10)
        self.assertAlmostEqual(0.4901624715, interval["low"], places=8)
        self.assertAlmostEqual(0.9433178485, interval["high"], places=8)

    def test_stability_thresholds(self) -> None:
        self.assertEqual("STABLE_PASS", stability_label(5, 0, 0)); self.assertEqual("UNSTABLE", stability_label(2, 2, 1)); self.assertEqual("STABLE_FAIL", stability_label(0, 5, 0))

    def test_latency_percentiles(self) -> None:
        result = latency_summary([1, 2, 3, 4, 5])
        self.assertEqual(3, result["median"]); self.assertAlmostEqual(4.8, result["p95"])

    def test_mutation_identity_and_source_immutability(self) -> None:
        scenario = next(item for item in self.suite.scenarios if item.canonical.get("mutation_eligible") and "RG-MUT-001" in item.canonical.get("mutation_ids", []))
        original = scenario.canonical["input"]["content"]
        mutated = make_runtime_case(scenario, "RG-MUT-001")
        self.assertEqual(f"{scenario.id}@RG-MUT-001", mutated.runtime_id)
        self.assertEqual(original, scenario.canonical["input"]["content"])
        self.assertNotEqual(original, mutated.runtime_view["input"]["content"])

    def test_nondeterministic_mutations_are_refused(self) -> None:
        scenario = self.by_id["RG-EVAL-V2-001"]
        for mutation in UNSUPPORTED_AUTOMATIC:
            with self.assertRaises(ValueError): make_runtime_case(scenario, mutation)

    def test_fixture_adapter_is_deterministic(self) -> None:
        first = FixtureAdapter().generate(self.prompt(), execution_key="a", scenario=self.by_id["RG-EVAL-V2-001"])
        second = FixtureAdapter().generate(self.prompt(), execution_key="b", scenario=self.by_id["RG-EVAL-V2-001"])
        self.assertEqual(first.text, second.text)

    def test_optional_judge_discloses_relationship_and_uncertainty(self) -> None:
        scenario = self.by_id["RG-EVAL-V2-001"]
        score = evaluate_response(scenario, parse_response("not-json"))
        score.update({"execution_key": "key", "scenario_id": scenario.id, "runtime_id": scenario.id, "condition": "RENGuard", "run_index": 1})
        judged = judge_unresolved([score], [{"execution_key": "key", "raw_response": "not-json"}], {scenario.id: scenario}, FixtureAdapter("judge-uncertainty"), "SAME_MODEL")
        self.assertEqual("SAME_MODEL", judged[0]["judge_result"][0]["relationship"])
        self.assertEqual("UNRESOLVED", judged[0]["assertion_groups"]["SECURITY_DETECTION"]["outcome"])

    def test_replay_adapter_uses_execution_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "responses.jsonl"; write_jsonl(path, [{"execution_key": "key", "raw_response": "{}", "model": "m", "provider": "p"}])
            self.assertEqual("{}", ReplayAdapter(path).generate(self.prompt(), execution_key="key").text)

    def test_command_adapter_requires_argument_array(self) -> None:
        with self.assertRaises(ValueError): CommandAdapter("echo unsafe")  # type: ignore[arg-type]

    def test_command_adapter_passes_payload_through_stdin(self) -> None:
        adapter = CommandAdapter([sys.executable, "-c", "import sys; data=sys.stdin.read(); print('{\"material_vulnerability\":false,\"findings\":[]}')"], timeout=2)
        result = adapter.generate(self.prompt(condition="BASELINE"), execution_key="key")
        self.assertEqual("PARSED", parse_response(result.text).state)

    def test_command_adapter_bounds_output(self) -> None:
        adapter = CommandAdapter([sys.executable, "-c", "print('x'*5000)"], timeout=2, max_output_bytes=1024)
        with self.assertRaises(AdapterError): adapter.generate(self.prompt(condition="BASELINE"), execution_key="key")

    def test_command_adapter_times_out(self) -> None:
        adapter = CommandAdapter([sys.executable, "-c", "import time; time.sleep(1)"], timeout=0.05)
        with self.assertRaises(TransientAdapterError):
            adapter.generate(self.prompt(condition="BASELINE"), execution_key="key")

    def test_live_capable_adapter_requires_explicit_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(PermissionError):
                run_benchmark(repository_root=ROOT, suite=self.suite, cases=[make_runtime_case(self.by_id["RG-EVAL-V2-001"])], conditions=["BASELINE"], adapter=CommandAdapter([sys.executable, "-c", "print('{}')"]), output_base=Path(temporary), run_id="blocked", runs=1, context_mode="CORE", concurrency=1, retry_count=0, execute_live=False, resume=False, filters={}, mutation_ids=[], parameters={}, argv=[], private_holdout=False)

    def test_plan_preserves_individual_runs(self) -> None:
        plan = plan_cases([make_runtime_case(self.by_id["RG-EVAL-V2-001"])], ["RENGuard", "BASELINE"], 3)
        self.assertEqual(6, len(plan)); self.assertEqual(6, len({item["execution_key"] for item in plan}))

    def test_safe_artifact_path_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError): safe_child(Path(temporary), "../escape")


class BenchmarkWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.suite = load_suite(SUITE_PATH)
        cls.by_id = {scenario.id: scenario for scenario in cls.suite.scenarios}

    def run_fixture(self, base: Path, run_id: str, profile: str, condition: str = "RENGuard", runs: int = 1) -> Path:
        cases = [make_runtime_case(self.by_id[item]) for item in ("RG-EVAL-V2-001", "RG-EVAL-V2-061", "RG-EVAL-V2-070")]
        return run_benchmark(repository_root=ROOT, suite=self.suite, cases=cases, conditions=[condition], adapter=FixtureAdapter(profile), output_base=base, run_id=run_id, runs=runs, context_mode="CONDITIONAL", concurrency=2, retry_count=0, execute_live=False, resume=False, filters={"ids": sorted(item.scenario.id for item in cases)}, mutation_ids=[], parameters={"temperature": None}, argv=["run"], private_holdout=False)

    def test_complete_offline_run_writes_required_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.run_fixture(Path(temporary), "perfect", "perfect", runs=2)
            for name in ("run-manifest.json", "responses.jsonl", "scores.jsonl", "summary.json", "summary.md"):
                self.assertTrue((run_dir / name).is_file(), name)
            self.assertEqual(6, len(read_jsonl(run_dir / "responses.jsonl")))

    def test_wrong_security_answer_is_not_retried(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.run_fixture(Path(temporary), "wrong", "false_negative")
            self.assertTrue(all(item["attempts"] == 1 for item in read_jsonl(run_dir / "responses.jsonl")))

    def test_transport_failure_is_retried_and_recorded(self) -> None:
        class OnceTransient(BenchmarkAdapter):
            name = "once-transient"; provider = "test"; model = "test-model"
            def __init__(self): self.calls = 0
            def generate(self, prompt, *, execution_key, scenario=None):
                self.calls += 1
                if self.calls == 1: raise TransientAdapterError("synthetic transient")
                return FixtureAdapter().generate(prompt, execution_key=execution_key, scenario=scenario)
        with tempfile.TemporaryDirectory() as temporary:
            adapter = OnceTransient(); case = make_runtime_case(self.by_id["RG-EVAL-V2-001"])
            run_dir = run_benchmark(repository_root=ROOT, suite=self.suite, cases=[case], conditions=["RENGuard"], adapter=adapter, output_base=Path(temporary), run_id="retry", runs=1, context_mode="CORE", concurrency=1, retry_count=1, execute_live=False, resume=False, filters={}, mutation_ids=[], parameters={}, argv=[], private_holdout=False)
            response = read_jsonl(run_dir / "responses.jsonl")[0]
            self.assertEqual(2, response["attempts"]); self.assertEqual(["synthetic transient"], response["transport_errors"])

    def test_summary_has_separate_technique_framework_and_format_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            summary = read_json(self.run_fixture(Path(temporary), "specialized", "perfect") / "summary.json")
            self.assertIn("required_technique_recall", summary["technique_metrics"])
            self.assertTrue(summary["framework_mapping_metrics"]["scored_separately_from_security_detection"])
            self.assertEqual(1.0, summary["format_metrics"]["pass_rate"])

    def test_repeated_run_instability_is_visible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = make_runtime_case(self.by_id["RG-EVAL-V2-001"])
            run_dir = run_benchmark(repository_root=ROOT, suite=self.suite, cases=[case], conditions=["RENGuard"], adapter=FixtureAdapter("unstable"), output_base=Path(temporary), run_id="unstable", runs=3, context_mode="CORE", concurrency=1, retry_count=0, execute_live=False, resume=False, filters={}, mutation_ids=[], parameters={}, argv=[], private_holdout=False)
            stability = read_json(run_dir / "summary.json")["stability"][0]
            self.assertEqual((2, 1, "UNSTABLE"), (stability["passes"], stability["failures"], stability["classification"]))

    def test_cost_requires_usage_and_user_pricing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.run_fixture(Path(temporary), "cost", "perfect")
            manifest = read_json(run_dir / "run-manifest.json")
            scores = read_jsonl(run_dir / "scores.jsonl")
            responses = read_jsonl(run_dir / "responses.jsonl")
            responses[0]["usage"] = {"input_tokens": 1000, "output_tokens": 500, "total_tokens": 1500}
            result = summarize(scores, manifest, responses, {"model": "fixture-model", "input_per_million": 2.0, "output_per_million": 4.0, "currency": "TEST"})
            self.assertEqual("CALCULATED_FROM_USER_SUPPLIED_PRICING", result["cost"]["status"])
            self.assertAlmostEqual(0.004, result["cost"]["amount"])

    def test_manifest_has_reproducibility_fields_and_no_secret_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = read_json(self.run_fixture(Path(temporary), "manifest", "perfect") / "run-manifest.json")
            for key in ("git_commit", "suite", "runner_version", "scoring_version", "artifact_schema_version", "contexts", "renguard_source", "benchmark_configuration_hash", "python_version", "platform", "command_line"):
                self.assertIn(key, manifest)
            self.assertNotIn("Authorization", json.dumps(manifest))

    def test_resume_skips_completed_execution_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); run_dir = self.run_fixture(base, "resume", "perfect")
            before = read_jsonl(run_dir / "responses.jsonl")
            cases = [make_runtime_case(self.by_id[item]) for item in ("RG-EVAL-V2-001", "RG-EVAL-V2-061", "RG-EVAL-V2-070")]
            run_benchmark(repository_root=ROOT, suite=self.suite, cases=cases, conditions=["RENGuard"], adapter=FixtureAdapter("false_negative"), output_base=base, run_id="resume", runs=1, context_mode="CONDITIONAL", concurrency=1, retry_count=0, execute_live=False, resume=True, filters={"ids": sorted(item.scenario.id for item in cases)}, mutation_ids=[], parameters={"temperature": None}, argv=[], private_holdout=False)
            self.assertEqual(before, read_jsonl(run_dir / "responses.jsonl"))

    def test_existing_run_is_not_overwritten_without_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            self.run_fixture(base, "collision", "perfect")
            with self.assertRaises(FileExistsError):
                self.run_fixture(base, "collision", "perfect")

    def test_minimal_artifacts_omit_raw_response(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = make_runtime_case(self.by_id["RG-EVAL-V2-061"])
            run_dir = run_benchmark(repository_root=ROOT, suite=self.suite, cases=[case], conditions=["BASELINE"], adapter=FixtureAdapter(), output_base=Path(temporary), run_id="minimal", runs=1, context_mode="CORE", concurrency=1, retry_count=0, execute_live=False, resume=False, filters={}, mutation_ids=[], parameters={}, argv=[], private_holdout=True, minimal_artifacts=True)
            response = read_jsonl(run_dir / "responses.jsonl")[0]
            self.assertNotIn("raw_response", response)
            self.assertIn("raw_response_hash", response)
            self.assertEqual("MINIMAL_NO_RAW_RESPONSES", read_json(run_dir / "run-manifest.json")["artifact_mode"])

    def test_summary_labels_fixture_latency_not_inference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            summary = read_json(self.run_fixture(Path(temporary), "latency", "perfect") / "summary.json")
            self.assertEqual(0, summary["latency"]["count"])
            self.assertIn("excluded", summary["latency_note"])

    def test_summary_markdown_escapes_active_html(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            summary = read_json(self.run_fixture(Path(temporary), "markdown", "perfect") / "summary.json")
            summary["model"]["model"] = "<script>alert(1)</script>"
            rendered = render_summary_markdown(summary)
            self.assertNotIn("<script>", rendered)

    def test_compare_requires_same_suite_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); a = self.run_fixture(base, "a", "perfect"); b = self.run_fixture(base, "b", "mixed")
            manifest = read_json(b / "run-manifest.json"); manifest["suite"]["content_hash"] = "different"; (b / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValueError): compare_runs(a, b)

    def test_compare_reports_paired_outcomes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); a = self.run_fixture(base, "a", "perfect"); b = self.run_fixture(base, "b", "mixed")
            comparison = compare_runs(a, b)
            self.assertEqual(3, sum(comparison["paired_analysis"].values()))
            self.assertFalse(comparison["causal_significance_claimed"])

    def test_review_export_and_overlay_preserve_machine_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = self.run_fixture(Path(temporary), "review", "unparseable")
            queue_path = run_dir / "review_queue.jsonl"; queue = export_review_queue(read_jsonl(run_dir / "scores.jsonl"), read_jsonl(run_dir / "responses.jsonl"), queue_path)
            self.assertTrue(queue)
            decisions = run_dir / "decisions.jsonl"; write_jsonl(decisions, [{"execution_key": queue[0]["execution_key"], "assertion_group": queue[0]["unresolved_assertions"][0], "decision": "PASS", "reviewer_label": "test-reviewer", "notes": "synthetic"}])
            reviewed = apply_human_review(run_dir / "scores.jsonl", decisions, run_dir / "reviewed.jsonl")
            item = next(score for score in reviewed if score["execution_key"] == queue[0]["execution_key"])
            self.assertIn("machine_result", item); self.assertIsNotNone(item["human_result"]); self.assertEqual("HUMAN", item["final_adjudication_source"])

    def test_fixture_profile_file_is_explicitly_synthetic(self) -> None:
        fixture = read_json(ROOT / "tests" / "fixtures" / "benchmark" / "fixture-profiles.json")
        self.assertTrue(fixture["fixture_only"]); self.assertIn("not RenGuard performance", fixture["warning"])


if __name__ == "__main__":
    unittest.main()
