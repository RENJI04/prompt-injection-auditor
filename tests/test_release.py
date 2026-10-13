from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from scripts.renguard_benchmark import (
    ARTIFACT_SCHEMA_VERSION,
    RUNNER_VERSION,
    SCORING_VERSION,
)


ROOT = Path(__file__).resolve().parents[1]
PHASE11_CHECKPOINT = "835de825c0a587dc9932c5eaac75100ce2885f7b"
VALIDATED_MAIN_COMMIT = "d8ec26b9b19f79f9a134f838ba2f4b3d34211963"
TAGGED_RELEASE_COMMIT = "cb2ad88029bb224d9cfe0dd58b2339a0bb6fdaec"
RELEASE_URL = "https://github.com/RENJI04/renguard/releases/tag/v2.0.0"


class ReleaseReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest_path = ROOT / "release/release-manifest.json"
        cls.notes_path = ROOT / "RELEASE_NOTES.md"
        cls.checklist_path = ROOT / "RELEASE_CHECKLIST.md"
        cls.skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")

    def test_release_readiness_artifacts_exist(self) -> None:
        for path in (self.manifest_path, self.notes_path, self.checklist_path):
            self.assertTrue(path.is_file(), path.relative_to(ROOT))

    def test_product_version_uses_skill_frontmatter_as_source(self) -> None:
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        match = re.search(r"(?m)^version: ([0-9]+\.[0-9]+\.[0-9]+)$", self.skill)
        self.assertIsNotNone(match)
        self.assertEqual("SKILL.md frontmatter", manifest["product_version_source"])
        self.assertEqual(match.group(1), manifest["release_target"])
        self.assertEqual("2.0.0", manifest["release_target"])

    def test_release_identity_records_published_state(self) -> None:
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual("RenGuard", manifest["product"])
        self.assertEqual(12, manifest["phase"])
        self.assertEqual("RELEASED", manifest["release_status"])
        self.assertEqual("PASS", manifest["local_release_validation"])
        self.assertEqual(PHASE11_CHECKPOINT, manifest["source_checkpoint"])
        self.assertEqual(VALIDATED_MAIN_COMMIT, manifest["source_commit"])
        self.assertIn("validated product-source merge", manifest["source_commit_note"])
        self.assertIn(TAGGED_RELEASE_COMMIT, manifest["source_commit_note"])
        self.assertIn("self-referential commit binding is intentionally avoided", manifest["source_commit_note"])

    def test_independent_contract_versions_match_sources(self) -> None:
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        versions = manifest["contract_versions"]
        suite = json.loads((ROOT / "evals/v2/manifest.json").read_text(encoding="utf-8"))
        schemas = json.loads((ROOT / "schemas/versions.json").read_text(encoding="utf-8"))
        self.assertEqual(suite["suite_version"], versions["public_evaluation_suite"])
        self.assertEqual(RUNNER_VERSION, versions["benchmark_runner"])
        self.assertEqual(SCORING_VERSION, versions["benchmark_scoring"])
        self.assertEqual(ARTIFACT_SCHEMA_VERSION, versions["benchmark_artifact_schema"])
        self.assertEqual(schemas["registry_version"], versions["schema_registry"])
        self.assertEqual(
            sorted({entry["version"] for entry in schemas["schemas"].values()}),
            versions["schema_versions"],
        )

    def test_release_counts_match_canonical_sources(self) -> None:
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        counts = manifest["counts"]
        technique_text = (ROOT / "references/renguard-techniques.md").read_text(encoding="utf-8")
        statuses = re.findall(
            r"Current RenGuard Coverage Status:\*\* (CORE|PARTIAL|PLANNED)",
            technique_text,
        )
        hardening_text = (ROOT / "references/hardening-patterns.md").read_text(encoding="utf-8")
        hardening = re.findall(r"^### RG-HARD-[A-Z]+-[0-9]{3} —", hardening_text, re.MULTILINE)
        suite = json.loads((ROOT / "evals/v2/manifest.json").read_text(encoding="utf-8"))
        schemas = json.loads((ROOT / "schemas/versions.json").read_text(encoding="utf-8"))
        mutations = json.loads((ROOT / "evals/v2/mutations.json").read_text(encoding="utf-8"))
        self.assertEqual(len(statuses), counts["techniques"])
        self.assertEqual(
            {name: statuses.count(name) for name in ("CORE", "PARTIAL", "PLANNED")},
            counts["technique_status"],
        )
        self.assertEqual(len(hardening), counts["hardening_patterns"])
        self.assertEqual(suite["scenario_count"], counts["public_scenarios"])
        self.assertEqual(len(mutations["mutation_recipes"]), counts["mutations"])
        self.assertEqual(len(schemas["schemas"]), counts["schemas"])

    def test_external_release_gates_match_observed_state(self) -> None:
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        gates = manifest["external_gates"]
        self.assertEqual("PASS", gates["hosted_ci"])
        self.assertEqual("PERFORMED", gates["push"])
        for name in ("public_tag", "github_release"):
            self.assertEqual("PERFORMED", gates[name])
        self.assertEqual("PERFORMED", gates["repository_rename"])
        benchmark = gates["official_live_benchmark"]
        self.assertEqual("NOT_PERFORMED", benchmark["status"])
        self.assertFalse(benchmark["required_for_core_release"])
        publication = manifest["publication"]
        self.assertEqual("v2.0.0", publication["tag"])
        self.assertEqual(TAGGED_RELEASE_COMMIT, publication["tagged_commit"])
        self.assertEqual("RenGuard v2.0.0", publication["github_release"])
        self.assertEqual(RELEASE_URL, publication["release_url"])
        self.assertEqual("2026-10-13T07:01:50Z", publication["published_at"])
        evidence = manifest["python_compatibility_evidence"]
        self.assertEqual(["3.10", "3.11", "3.12", "3.13"], evidence["ci_target_matrix"])
        self.assertEqual("3.12.14", evidence["locally_verified"])
        self.assertEqual("PASS", evidence["hosted_ci"])

    def test_release_notes_state_benchmark_and_publication_limits(self) -> None:
        notes = self.notes_path.read_text(encoding="utf-8")
        normalized_notes = re.sub(r"\s+", " ", notes)
        self.assertIn("Release status: **published**", notes)
        self.assertIn("RenGuard v2.0.0 was published on 2026-10-13", notes)
        self.assertIn("No official RenGuard v2 live-model benchmark result is included", notes)
        self.assertIn("72 scenarios are public evaluation definitions", normalized_notes)
        self.assertIn(
            "FixtureAdapter results are synthetic engineering validation",
            normalized_notes,
        )
        self.assertIn(VALIDATED_MAIN_COMMIT, notes)
        self.assertIn(TAGGED_RELEASE_COMMIT, notes)
        self.assertIn(RELEASE_URL, notes)
        self.assertIn("GitHub-hosted Python 3.10–3.13 CI passed", normalized_notes)

    def test_release_checklist_separates_local_and_external_gates(self) -> None:
        checklist = self.checklist_path.read_text(encoding="utf-8")
        self.assertIn("## Local and repository gates", checklist)
        self.assertIn("## External and publication gates", checklist)
        for gate in (
            "Final RC approved",
            "RC pushed",
            "RC push hosted CI",
            "Release PR",
            "PR CI",
            "Merge to main",
            "Main hosted CI",
            "Python 3.10",
            "Python 3.11",
            "Python 3.12",
            "Python 3.13",
        ):
            matching = [line for line in checklist.splitlines() if f"| {gate} |" in line]
            self.assertEqual(1, len(matching), gate)
            self.assertIn("| PASS |", matching[0])
        for gate in ("GitHub About application", "Topics application"):
            matching = [line for line in checklist.splitlines() if f"| {gate} |" in line]
            self.assertEqual(1, len(matching), gate)
            self.assertIn("| PASS |", matching[0])
        matching = [line for line in checklist.splitlines() if "| Social Preview configuration |" in line]
        self.assertEqual(1, len(matching))
        self.assertIn("| MANUALLY_CONFIGURED |", matching[0])
        for gate in ("`v2.0.0` annotated tag", "GitHub Release"):
            matching = [line for line in checklist.splitlines() if f"| {gate} |" in line]
            self.assertEqual(1, len(matching), gate)
            self.assertIn("| PERFORMED |", matching[0])
        self.assertIn("| Latest release | YES |", checklist)

    def test_release_docs_have_no_stale_pending_or_performance_claim(self) -> None:
        corpus = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (self.notes_path, self.checklist_path, self.manifest_path)
        ).lower()
        for forbidden in (
            "release candidate",
            "public tag and github release have not been performed",
            "github release creation remain pending",
            "official v2 performance percentage",
            "python 3.10–3.13 supported",
        ):
            self.assertNotIn(forbidden, corpus)
        self.assertNotRegex(
            corpus,
            r"(?:renguard\s+)?v2[^\n%]{0,120}\d+(?:\.\d+)?%",
        )


if __name__ == "__main__":
    unittest.main()
