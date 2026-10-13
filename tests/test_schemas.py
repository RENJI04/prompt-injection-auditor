from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.schema_tools import (
    DIALECT,
    EXPECTED_SCHEMA_KEYS,
    SchemaContractError,
    ensure_compatible_version,
    load_json,
    load_registry,
    resolve_ref,
    schema_for,
    validate_repository_contracts,
    validate_run_directory,
    validate_schema_documents,
    validate_value,
)
from scripts.validate_repo import validate_repository


ROOT = Path(__file__).resolve().parents[1]


class SchemaContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_json(ROOT / "evals/v2/manifest.json")
        cls.mutations = load_json(ROOT / "evals/v2/mutations.json")
        cls.scenarios = []
        for filename in cls.manifest["scenario_files"]:
            cls.scenarios.extend(load_json(ROOT / "evals/v2" / filename)["scenarios"])
        cls.scenario = cls.scenarios[0]
        cls.temporary_directory = tempfile.TemporaryDirectory()
        output = Path(cls.temporary_directory.name) / "runs"
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        subprocess.run(
            [
                sys.executable, "scripts/run_benchmark.py", "run",
                "--adapter", "fixture", "--fixture-profile", "unparseable",
                "--ids", "RG-EVAL-V2-001", "--output-dir", str(output),
                "--run-id", "schema-fixture",
            ],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        cls.run_dir = output / "schema-fixture"
        subprocess.run(
            [sys.executable, "scripts/run_benchmark.py", "export-review", "--run-dir", str(cls.run_dir)],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary_directory.cleanup()

    def test_all_required_schema_registry_entries_exist(self) -> None:
        self.assertEqual(EXPECTED_SCHEMA_KEYS, set(load_registry()["schemas"]))

    def test_all_schema_documents_parse_and_validate(self) -> None:
        self.assertEqual([], validate_schema_documents())

    def test_schema_dialect_is_consistent(self) -> None:
        for key in EXPECTED_SCHEMA_KEYS:
            schema, _ = schema_for(key)
            self.assertEqual(DIALECT, schema["$schema"])

    def test_schema_ids_are_unique(self) -> None:
        ids = [schema_for(key)[0]["$id"] for key in EXPECTED_SCHEMA_KEYS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_registry_versions_are_semantic(self) -> None:
        registry = load_registry()
        self.assertRegex(registry["registry_version"], r"^[0-9]+\.[0-9]+\.[0-9]+$")
        for entry in registry["schemas"].values():
            self.assertRegex(entry["version"], r"^[0-9]+\.[0-9]+\.[0-9]+$")

    def test_schema_id_must_match_registered_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "repository"
            shutil.copytree(ROOT / "schemas", target / "schemas")
            registry_path = target / "schemas/versions.json"
            registry = load_json(registry_path)
            registry["schemas"]["eval.scenario"]["version"] = "1.0.1"
            registry_path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
            self.assertTrue(
                any("schema id does not match version" in item for item in validate_schema_documents(target))
            )

    def test_registry_keeps_artifact_version_separate(self) -> None:
        registry = load_registry()
        self.assertEqual("0.1.0", registry["artifact_contract_version"])
        self.assertTrue(all(entry["version"] == "1.0.0" for entry in registry["schemas"].values()))

    def test_suite_version_is_separate_from_schema_versions(self) -> None:
        registry = load_registry()
        self.assertEqual("0.1.0", self.manifest["suite_version"])
        self.assertNotIn(
            self.manifest["suite_version"],
            {entry["version"] for entry in registry["schemas"].values()},
        )

    def test_all_internal_references_resolve(self) -> None:
        self.assertEqual([], validate_schema_documents())

    def test_external_reference_is_rejected_without_fetch(self) -> None:
        schema_path = ROOT / "schemas/eval/scenario.schema.json"
        with self.assertRaisesRegex(SchemaContractError, "external or absolute"):
            resolve_ref("https://example.invalid/schema.json", schema_path)

    def test_reference_path_traversal_is_rejected(self) -> None:
        schema_path = ROOT / "schemas/eval/scenario.schema.json"
        with self.assertRaisesRegex(SchemaContractError, "escapes approved schema root"):
            resolve_ref("../../../evals/v2/manifest.json", schema_path)

    def test_broken_internal_reference_is_rejected(self) -> None:
        schema_path = ROOT / "schemas/eval/scenario.schema.json"
        with self.assertRaisesRegex(SchemaContractError, "unresolved JSON pointer"):
            resolve_ref("#/$defs/doesNotExist", schema_path)

    def test_canonical_repository_contracts_validate(self) -> None:
        errors, counts = validate_repository_contracts()
        self.assertEqual([], errors)
        self.assertEqual(9, counts["schemas"])
        self.assertEqual(72, counts["scenarios"])
        self.assertEqual(15, counts["mutations"])
        self.assertGreaterEqual(counts["json_files"], 26)

    def test_repository_contract_check_rejects_any_malformed_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "repository"
            shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
            (target / "unregistered.json").write_text("{not-json}\n", encoding="utf-8")
            errors, counts = validate_repository_contracts(target)
            self.assertEqual(28, counts["json_files"])
            self.assertTrue(any("unregistered.json" in item for item in errors))

    def test_all_72_scenarios_validate_structurally(self) -> None:
        self.assertEqual(72, len(self.scenarios))
        for scenario in self.scenarios:
            self.assertEqual([], validate_value(scenario, "eval.scenario"), scenario["id"])

    def test_multilingual_scenarios_preserve_unicode(self) -> None:
        languages = {item if isinstance(item, str) else tuple(item) for item in (scenario["language"] for scenario in self.scenarios)}
        self.assertTrue({"ar", "zh-CN", "ja", "ru"} <= languages)
        arabic = next(item for item in self.scenarios if item["language"] == "ar")
        self.assertIn("أنا", json.dumps(arabic, ensure_ascii=False))
        self.assertEqual([], validate_value(arabic, "eval.scenario"))

    def test_scenario_missing_required_field_fails(self) -> None:
        scenario = copy.deepcopy(self.scenario)
        del scenario["id"]
        self.assertTrue(any("missing required property 'id'" in item for item in validate_value(scenario, "eval.scenario")))

    def test_scenario_invalid_kind_fails(self) -> None:
        scenario = copy.deepcopy(self.scenario)
        scenario["kind"] = "UNKNOWN"
        self.assertTrue(validate_value(scenario, "eval.scenario"))

    def test_scenario_invalid_language_type_fails(self) -> None:
        scenario = copy.deepcopy(self.scenario)
        scenario["language"] = {"name": "en"}
        self.assertTrue(validate_value(scenario, "eval.scenario"))

    def test_scenario_unexpected_property_fails(self) -> None:
        scenario = copy.deepcopy(self.scenario)
        scenario["answer_hint"] = "do not expose"
        self.assertTrue(any("unexpected property 'answer_hint'" in item for item in validate_value(scenario, "eval.scenario")))

    def test_scenario_invalid_confidence_fails(self) -> None:
        scenario = copy.deepcopy(self.scenario)
        scenario["expected"]["expected_confidence"] = "CERTAIN"
        self.assertTrue(validate_value(scenario, "eval.scenario"))

    def test_exact_risk_missing_dimension_fails_structurally(self) -> None:
        scenario = copy.deepcopy(next(item for item in self.scenarios if item["expected"]["expected_risk"]["mode"] == "EXACT"))
        del scenario["expected"]["expected_risk"]["dimensions"]["E"]
        self.assertTrue(validate_value(scenario, "eval.scenario"))

    def test_band_risk_rejects_invented_exact_score(self) -> None:
        scenario = copy.deepcopy(self.scenario)
        scenario["expected"]["expected_risk"]["score"] = 9.9
        self.assertTrue(validate_value(scenario, "eval.scenario"))

    def test_manifest_positive_validation(self) -> None:
        self.assertEqual([], validate_value(self.manifest, "eval.suite_manifest"))

    def test_manifest_missing_count_fails(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        del manifest["scenario_count"]
        self.assertTrue(validate_value(manifest, "eval.suite_manifest"))

    def test_manifest_wrong_count_type_fails(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["scenario_count"] = "72"
        self.assertTrue(validate_value(manifest, "eval.suite_manifest"))

    def test_structurally_valid_manifest_can_still_fail_semantics(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["scenario_count"] = 71
        self.assertEqual([], validate_value(manifest, "eval.suite_manifest"))
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "repository"
            shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
            (target / "evals/v2/manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            self.assertTrue(any("scenario_count" in item for item in validate_repository(target).errors))

    def test_mutation_catalog_positive_validation(self) -> None:
        self.assertEqual([], validate_value(self.mutations, "eval.mutations"))

    def test_mutation_missing_safety_notes_fails(self) -> None:
        value = copy.deepcopy(self.mutations)
        del value["mutation_recipes"][0]["safety_notes"]
        self.assertTrue(validate_value(value, "eval.mutations"))

    def test_mutation_invalid_applicability_fails(self) -> None:
        value = copy.deepcopy(self.mutations)
        value["mutation_recipes"][0]["applicable_to"] = ["CLEAN"]
        self.assertTrue(validate_value(value, "eval.mutations"))

    def test_pricing_positive_validation(self) -> None:
        value = {"model": "fixture", "input_per_million": 0, "output_per_million": 0.5, "currency": "TEST"}
        self.assertEqual([], validate_value(value, "benchmark.pricing"))

    def test_pricing_rejects_negative_rate(self) -> None:
        value = {"model": "fixture", "input_per_million": -1, "output_per_million": 0, "currency": "USD"}
        self.assertTrue(validate_value(value, "benchmark.pricing"))

    def test_pricing_rejects_unknown_property(self) -> None:
        value = {"model": "fixture", "input_per_million": 0, "output_per_million": 0, "currency": "USD", "api_key": "forbidden"}
        self.assertTrue(validate_value(value, "benchmark.pricing"))

    def test_fixture_run_directory_validates(self) -> None:
        self.assertEqual([], validate_run_directory(self.run_dir))

    def test_generated_run_manifest_validates(self) -> None:
        value = load_json(self.run_dir / "run-manifest.json")
        self.assertEqual([], validate_value(value, "benchmark.run_manifest"))

    def test_run_manifest_missing_artifact_version_fails(self) -> None:
        value = load_json(self.run_dir / "run-manifest.json")
        del value["artifact_schema_version"]
        self.assertTrue(validate_value(value, "benchmark.run_manifest"))

    def test_generated_response_record_validates(self) -> None:
        value = json.loads((self.run_dir / "responses.jsonl").read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual([], validate_value(value, "benchmark.response_record"))

    def test_response_record_rejects_invalid_run_index(self) -> None:
        value = json.loads((self.run_dir / "responses.jsonl").read_text(encoding="utf-8").splitlines()[0])
        value["run_index"] = 0
        self.assertTrue(validate_value(value, "benchmark.response_record"))

    def test_generated_score_record_validates(self) -> None:
        value = json.loads((self.run_dir / "scores.jsonl").read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual([], validate_value(value, "benchmark.score_record"))

    def test_score_record_rejects_invalid_parser_state(self) -> None:
        value = json.loads((self.run_dir / "scores.jsonl").read_text(encoding="utf-8").splitlines()[0])
        value["parser_state"] = "GUESSED"
        self.assertTrue(validate_value(value, "benchmark.score_record"))

    def test_generated_summary_validates(self) -> None:
        value = load_json(self.run_dir / "summary.json")
        self.assertEqual([], validate_value(value, "benchmark.summary"))

    def test_summary_allows_undefined_nullable_rate(self) -> None:
        value = load_json(self.run_dir / "summary.json")
        value["semantic_pass_rate"] = None
        value["semantic_pass_confidence_interval"] = None
        self.assertEqual([], validate_value(value, "benchmark.summary"))

    def test_summary_rejects_unknown_property(self) -> None:
        value = load_json(self.run_dir / "summary.json")
        value["official_result"] = True
        self.assertTrue(validate_value(value, "benchmark.summary"))

    def test_generated_review_queue_records_validate(self) -> None:
        records = [json.loads(line) for line in (self.run_dir / "review_queue.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertTrue(records)
        for value in records:
            self.assertEqual([], validate_value(value, "benchmark.review_record"))

    def test_human_review_decision_validates_without_identity(self) -> None:
        value = {"execution_key": "RG-EVAL-V2-001|RENGuard|1", "assertion_group": "SECURITY_DETECTION", "decision": "UNRESOLVED"}
        self.assertEqual([], validate_value(value, "benchmark.review_record"))

    def test_human_review_invalid_decision_fails(self) -> None:
        value = {"execution_key": "x", "assertion_group": "RISK", "decision": "APPROVE"}
        self.assertTrue(validate_value(value, "benchmark.review_record"))

    def test_current_artifact_version_is_supported(self) -> None:
        ensure_compatible_version("0.1.0", "0.1.0", label="artifact")

    def test_unknown_artifact_major_is_rejected(self) -> None:
        with self.assertRaisesRegex(SchemaContractError, "unsupported major"):
            ensure_compatible_version("1.0.0", "0.1.0", label="artifact")

    def test_unknown_pre_one_artifact_version_is_rejected(self) -> None:
        with self.assertRaisesRegex(SchemaContractError, "not explicitly supported"):
            ensure_compatible_version("0.2.0", "0.1.0", label="artifact")

    def test_malformed_artifact_version_is_rejected(self) -> None:
        with self.assertRaisesRegex(SchemaContractError, "semantic versioning"):
            ensure_compatible_version("v0.1", "0.1.0", label="artifact")

    def test_benchmark_cli_rejects_unknown_artifact_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "run"
            shutil.copytree(self.run_dir, target)
            manifest = load_json(target / "run-manifest.json")
            manifest["artifact_schema_version"] = "1.0.0"
            (target / "run-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "scripts/run_benchmark.py", "score", "--run-dir", str(target)],
                cwd=ROOT,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                capture_output=True,
                text=True,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("unsupported major version", result.stderr)

    def test_future_one_x_schema_version_is_rejected(self) -> None:
        with self.assertRaisesRegex(SchemaContractError, "future schema version"):
            ensure_compatible_version("1.1.0", "1.0.0", label="schema")


if __name__ == "__main__":
    unittest.main()
