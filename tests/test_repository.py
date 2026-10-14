from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.renguard_benchmark import ARTIFACT_SCHEMA_VERSION, RUNNER_VERSION, SCORING_VERSION
from scripts.schema_tools import validate_repository_contracts
from scripts.validate_repo import HISTORICAL_V1_FILE_SHA256, PHASE8_PRESERVED_FILE_SHA256, validate_repository


ROOT = Path(__file__).resolve().parents[1]


class RepositoryEngineeringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        cls.check_script = (ROOT / "scripts/check.py").read_text(encoding="utf-8")

    def test_ci_workflow_exists(self) -> None:
        self.assertTrue((ROOT / ".github/workflows/ci.yml").is_file())

    def test_ci_runs_on_push_and_pull_request(self) -> None:
        self.assertIn("push:", self.workflow)
        self.assertIn("pull_request:", self.workflow)
        self.assertNotIn("pull_request_target", self.workflow)

    def test_ci_python_matrix_is_documented_target_set(self) -> None:
        for version in ("3.10", "3.11", "3.12", "3.13"):
            self.assertIn(f'"{version}"', self.workflow)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("CI is configured to test Python 3.10–3.13", readme)
        self.assertIn("local verification was\nperformed on Python 3.12.14 only", readme)
        self.assertIn("the other target versions remain unverified", contributing)
        self.assertIn("Python 3.10–3.13 target\n  matrix", changelog)
        self.assertNotIn("repository supports Python 3.10–3.13", readme)
        self.assertNotIn("CI-supported\nPython version", contributing)

    def test_ci_permissions_are_read_only(self) -> None:
        self.assertIn("permissions:\n  contents: read", self.workflow)
        self.assertNotRegex(self.workflow, r"(?m)^\s+[^#\n]+:\s*write\s*$")

    def test_ci_checkout_does_not_persist_credentials(self) -> None:
        self.assertIn("persist-credentials: false", self.workflow)

    def test_ci_uses_only_official_actions(self) -> None:
        actions = re.findall(r"uses:\s*([^\s]+)", self.workflow)
        self.assertEqual(["actions/checkout@v4", "actions/setup-python@v5"], actions)

    def test_ci_has_bounded_timeout(self) -> None:
        self.assertRegex(self.workflow, r"timeout-minutes:\s*15")

    def test_ci_invokes_shared_quality_gate(self) -> None:
        self.assertIn("run: python scripts/check.py", self.workflow)

    def test_ci_contains_no_live_execution_flag(self) -> None:
        self.assertNotIn("--execute-live", self.workflow)

    def test_ci_contains_no_provider_credentials(self) -> None:
        for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "MOONSHOT_API_KEY"):
            self.assertNotIn(name, self.workflow)

    def test_ci_uploads_no_benchmark_artifacts(self) -> None:
        self.assertNotIn("upload-artifact", self.workflow)

    def test_quality_gate_uses_argument_arrays_without_shell(self) -> None:
        self.assertIn("subprocess.run(command", self.check_script)
        self.assertIn("shell=False", self.check_script)
        self.assertIn('["git", "diff", "--check"]', self.check_script)
        self.assertNotIn("shell=True", self.check_script)

    def test_quality_gate_has_all_five_sections(self) -> None:
        for label in ("Repository validation", "Unit tests", "Compile", "Schema and JSON validation", "Offline benchmark smoke"):
            self.assertIn(label, self.check_script)

    def test_quality_gate_smoke_is_fixture_only(self) -> None:
        self.assertIn('"--adapter", "fixture"', self.check_script)
        self.assertNotIn("--execute-live", self.check_script)

    def test_quality_gate_uses_temporary_output(self) -> None:
        self.assertIn("TemporaryDirectory", self.check_script)
        self.assertIn('temporary_root / "benchmark-runs"', self.check_script)

    def test_focused_schema_gate_executes_successfully(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/check.py", "--only", "schemas"],
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_focused_smoke_gate_executes_successfully(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/check.py", "--only", "smoke"],
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_generated_runtime_directory_is_ignored(self) -> None:
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("benchmark-runs/", ignore)
        self.assertIn("__pycache__/", ignore)
        self.assertNotIn("\nschemas/\n", "\n" + ignore)

    def test_no_generated_benchmark_runs_are_tracked(self) -> None:
        result = subprocess.run(["git", "ls-files", "--", "benchmark-runs"], cwd=ROOT, capture_output=True, text=True, check=True)
        self.assertEqual("", result.stdout)

    def test_no_workspace_specific_paths_are_committed(self) -> None:
        marker = "/" + "workspace/"
        for path in ROOT.rglob("*"):
            if path.is_file() and ".git" not in path.parts and path.suffix in {".py", ".md", ".json", ".yml", ".yaml"}:
                self.assertNotIn(marker, path.read_text(encoding="utf-8"), str(path))

    def test_production_subprocess_adapters_never_use_shell_true(self) -> None:
        adapter = (ROOT / "scripts/renguard_benchmark/adapters.py").read_text(encoding="utf-8")
        self.assertNotIn("shell=True", adapter)
        self.assertIn("shell=False", adapter)

    def test_skill_and_references_contain_no_eval_ids(self) -> None:
        paths = [ROOT / "SKILL.md", *sorted((ROOT / "references").glob("*.md"))]
        for path in paths:
            self.assertNotIn("RG-EVAL-V2-", path.read_text(encoding="utf-8"), str(path))

    def test_phase9_versions_remain_unchanged(self) -> None:
        self.assertEqual(("0.1.0", "0.1.0", "0.1.0"), (RUNNER_VERSION, SCORING_VERSION, ARTIFACT_SCHEMA_VERSION))

    def test_phase3_risk_reference_hash_remains_registered(self) -> None:
        self.assertEqual("3418cd1efd4c19989767f726d2c488e8dc0ac2675e1ef089b3ac2d381f74f7df", PHASE8_PRESERVED_FILE_SHA256["references/risk-scoring.md"])

    def test_historical_v1_integrity_registry_remains_present(self) -> None:
        self.assertIn("benchmarks/benchmark.json", HISTORICAL_V1_FILE_SHA256)
        self.assertIn("evals/evals.json", HISTORICAL_V1_FILE_SHA256)
        self.assertTrue(any(path.startswith("evals/files/") for path in HISTORICAL_V1_FILE_SHA256))

    def test_legacy_identity_is_confined_to_protected_historical_benchmark(self) -> None:
        legacy_patterns = (
            "prompt" + "-injection-" + "auditor",
            "prompt" + "_injection_" + "auditor",
            "prompt" + " injection " + "auditor",
            "shield" + " " + "claude",
            "claude" + "-skill",
        )
        exempt_path = Path("benchmarks/benchmark.json")
        tracked = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout.split(b"\0")
        matches: list[str] = []
        for encoded_path in tracked:
            if not encoded_path:
                continue
            relative = Path(encoded_path.decode("utf-8"))
            if relative == exempt_path:
                continue
            data = (ROOT / relative).read_bytes()
            if b"\0" in data:
                continue
            try:
                text = data.decode("utf-8").lower()
            except UnicodeDecodeError:
                continue
            for pattern in legacy_patterns:
                if pattern in text:
                    matches.append(f"{relative}: {pattern}")
        self.assertEqual([], matches)

        historical_text = (ROOT / exempt_path).read_text(encoding="utf-8").lower()
        historical_occurrences = sum(
            historical_text.count(pattern) for pattern in legacy_patterns
        )
        self.assertEqual(4, historical_occurrences)

    def test_repository_validator_covers_phase10_contracts(self) -> None:
        result = validate_repository(ROOT)
        self.assertEqual([], result.errors)
        self.assertEqual(9, result.phase10_metrics["schema_count"])

    def test_schema_and_semantic_validation_are_both_green(self) -> None:
        errors, counts = validate_repository_contracts(ROOT)
        self.assertEqual([], errors)
        self.assertEqual(72, counts["scenarios"])

    def test_all_repository_json_is_utf8_and_parseable(self) -> None:
        paths = sorted(ROOT.rglob("*.json"))
        self.assertGreaterEqual(len(paths), 26)
        for path in paths:
            if ".git" not in path.parts:
                json.loads(path.read_text(encoding="utf-8"))

    def test_editorconfig_preserves_markdown_examples(self) -> None:
        value = (ROOT / ".editorconfig").read_text(encoding="utf-8")
        self.assertIn("charset = utf-8", value)
        self.assertIn("[*.md]\ntrim_trailing_whitespace = false", value)

    def test_engineering_guidance_exists(self) -> None:
        self.assertTrue((ROOT / "CONTRIBUTING.md").is_file())
        self.assertTrue((ROOT / "SECURITY.md").is_file())

    def test_existing_license_is_unchanged_in_scope(self) -> None:
        self.assertIn("MIT License", (ROOT / "LICENSE").read_text(encoding="utf-8"))

    def test_no_packaging_or_dependency_stack_was_added(self) -> None:
        self.assertFalse((ROOT / "pyproject.toml").exists())
        self.assertFalse((ROOT / "requirements.txt").exists())

    def test_no_codeowners_identity_is_fabricated(self) -> None:
        self.assertFalse((ROOT / ".github/CODEOWNERS").exists())

    def test_schema_files_contain_no_credential_shaped_values(self) -> None:
        pattern = re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bsk-[A-Za-z0-9]{20,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b)")
        for path in (ROOT / "schemas").rglob("*"):
            if path.is_file():
                self.assertIsNone(pattern.search(path.read_text(encoding="utf-8")), str(path))


if __name__ == "__main__":
    unittest.main()
