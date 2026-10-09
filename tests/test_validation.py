from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.validate_repo import (
    EXPOSURE_SYMBOLS,
    IMPACT_SYMBOLS,
    RISK_DIMENSIONS,
    calculate_risk_score,
    severity_for_score,
    validate_repository,
)


SOURCE_ROOT = Path(__file__).resolve().parents[1]


class RepositoryValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name) / "repository"
        shutil.copytree(
            SOURCE_ROOT,
            self.root,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )

    def _read_json(self, relative_name: str) -> dict:
        with (self.root / relative_name).open(encoding="utf-8") as handle:
            return json.load(handle)

    def _write_json(self, relative_name: str, data: dict) -> None:
        with (self.root / relative_name).open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")

    def _errors_after_text_replacement(
        self, relative_name: str, old: str, new: str
    ) -> list[str]:
        path = self.root / relative_name
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")
        return validate_repository(self.root).errors

    def _errors_after_benchmark_change(self, change) -> list[str]:
        relative_name = "benchmarks/benchmark.json"
        data = self._read_json(relative_name)
        change(data)
        self._write_json(relative_name, data)
        return validate_repository(self.root).errors

    def test_repository_fixture_is_valid(self) -> None:
        self.assertEqual([], validate_repository(self.root).errors)

    def test_rejects_invalid_pass_counts(self) -> None:
        errors = self._errors_after_benchmark_change(
            lambda data: data["runs"][0]["result"].__setitem__("passed", 7)
        )
        self.assertTrue(any("passed + failed must equal total" in error for error in errors))

    def test_rejects_bad_pass_rate(self) -> None:
        errors = self._errors_after_benchmark_change(
            lambda data: data["runs"][0]["result"].__setitem__("pass_rate", 0.5)
        )
        self.assertTrue(any("result.pass_rate" in error for error in errors))

    def test_rejects_missing_eval_fixture(self) -> None:
        (self.root / "evals/files/vulnerable_chatbot.txt").unlink()
        errors = validate_repository(self.root).errors
        self.assertTrue(any("missing eval fixture" in error for error in errors))

    def test_rejects_duplicate_eval_ids(self) -> None:
        relative_name = "evals/evals.json"
        data = self._read_json(relative_name)
        data["evals"][1]["id"] = data["evals"][0]["id"]
        self._write_json(relative_name, data)
        errors = validate_repository(self.root).errors
        self.assertTrue(any("duplicate eval ID" in error for error in errors))

    def test_rejects_benchmark_eval_mismatch(self) -> None:
        errors = self._errors_after_benchmark_change(
            lambda data: data["runs"][0].__setitem__("eval_id", 999)
        )
        self.assertTrue(any("references unknown eval ID" in error for error in errors))

    def test_rejects_missing_historical_corpus_provenance(self) -> None:
        errors = self._errors_after_benchmark_change(
            lambda data: data["metadata"].pop("benchmark_corpus")
        )
        self.assertTrue(any("missing benchmark_corpus provenance" in error for error in errors))

    def test_rejects_duplicate_renguard_technique_id(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/renguard-techniques.md",
            "## RG-PI-002 — Indirect Content Injection",
            "## RG-PI-001 — Indirect Content Injection",
        )
        self.assertTrue(any("duplicate RenGuard technique ID" in error for error in errors))

    def test_rejects_malformed_renguard_technique_id(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/renguard-techniques.md",
            "## RG-PI-001 — Direct Instruction Override",
            "## RG-PI-01 — Direct Instruction Override",
        )
        self.assertTrue(any("malformed RenGuard technique ID" in error for error in errors))

    def test_rejects_unknown_owasp_llm_mapping(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/renguard-techniques.md",
            "**Primary OWASP LLM 2026:** `LLM01:2026`",
            "**Primary OWASP LLM 2026:** `LLM99:2026`",
        )
        self.assertTrue(any("unknown OWASP LLM 2026 mapping" in error for error in errors))

    def test_rejects_wrong_owasp_2026_name(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/owasp-llm-2026.md",
            "## LLM08:2026 — Hidden Context Exposure",
            "## LLM08:2026 — System Prompt Leakage",
        )
        self.assertTrue(any("LLM08:2026 name" in error for error in errors))

    def test_rejects_unknown_agentic_mapping(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/renguard-techniques.md",
            "**OWASP Agentic 2026:** `ASI01`",
            "**OWASP Agentic 2026:** `ASI99`",
        )
        self.assertTrue(any("unknown OWASP Agentic 2026 mapping" in error for error in errors))

    def test_rejects_missing_mandatory_framework_entry(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/owasp-agentic-2026.md",
            "## ASI10 — Rogue Agents\n",
            "",
        )
        self.assertTrue(any("missing mandatory framework entry ASI10" in error for error in errors))

    def test_rejects_duplicate_hardening_pattern_id(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/hardening-patterns.md",
            "### RG-HARD-P-002 — Scope, confidentiality, and refusal guidance",
            "### RG-HARD-P-001 — Scope, confidentiality, and refusal guidance",
        )
        self.assertTrue(any("duplicate hardening pattern ID" in error for error in errors))

    def test_rejects_malformed_hardening_pattern_id(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/hardening-patterns.md",
            "### RG-HARD-P-001 — Authority-aware instruction hierarchy",
            "### RG-HARD-P-01 — Authority-aware instruction hierarchy",
        )
        self.assertTrue(any("malformed hardening pattern ID" in error for error in errors))

    def test_rejects_unknown_hardening_technique_reference(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/hardening-patterns.md",
            "`RG-PI-001`, `RG-PI-002`, `RG-PI-003`, `RG-PI-004`",
            "`RG-PI-999`, `RG-PI-002`, `RG-PI-003`, `RG-PI-004`",
        )
        self.assertTrue(any("unknown RenGuard technique RG-PI-999" in error for error in errors))

    def test_rejects_unknown_example_hardening_pattern_reference(self) -> None:
        errors = self._errors_after_text_replacement(
            "examples/01-chatbot-prompt.md",
            "`RG-HARD-P-001`",
            "`RG-HARD-P-999`",
        )
        self.assertTrue(
            any("unknown hardening pattern reference RG-HARD-P-999" in error for error in errors)
        )

    def test_rejects_invalid_hardening_control_layer(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/hardening-patterns.md",
            "- **Control Layer:** PROMPT",
            "- **Control Layer:** CONVERSATION",
        )
        self.assertTrue(any("invalid control layer" in error for error in errors))

    def test_rejects_invalid_hardening_strength(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/hardening-patterns.md",
            "- **Strength:** MODEL-ENFORCED",
            "- **Strength:** MAGIC-ENFORCED",
        )
        self.assertTrue(any("invalid control strength" in error for error in errors))

    def test_rejects_invalid_implementation_status(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/hardening-patterns.md",
            "- **Implementation Status:** PROPOSED",
            "- **Implementation Status:** ASSUMED",
        )
        self.assertTrue(any("invalid implementation status" in error for error in errors))

    def test_rejects_invalid_security_function(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/hardening-patterns.md",
            "- **Security Functions:** PREVENT",
            "- **Security Functions:** GUARANTEE",
        )
        self.assertTrue(any("invalid security function" in error for error in errors))

    def test_rejects_prompt_control_mislabeled_as_platform_enforced(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/hardening-patterns.md",
            "- **Strength:** MODEL-ENFORCED",
            "- **Strength:** PLATFORM-ENFORCED",
        )
        self.assertTrue(any("prompt-only control is mislabeled" in error for error in errors))

    def test_rejects_chat_confirm_presented_as_authorization(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/hardening-patterns.md",
            "Chat confirmation such as “type CONFIRM”; it is a usability cue, not "
            "authentication or authorization.",
            "Chat confirmation such as “type CONFIRM authorizes the action.”",
        )
        self.assertTrue(any("chat CONFIRM is presented" in error for error in errors))

    def test_rejects_proposed_control_described_as_implemented(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/hardening-patterns.md",
            "- **Purpose:** Keep task instructions within authority granted by trusted policy.",
            "- **Purpose:** Keep task instructions within authority granted by trusted "
            "policy. The control is implemented.",
        )
        self.assertTrue(any("proposed/projected control is described as implemented" in error for error in errors))

    def test_rejects_zero_residual_risk_claim(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/hardening-patterns.md",
            "- **Residual Risk:** Model behavior remains probabilistic; pair with authorization and tool mediation.",
            "- **Residual Risk:** Zero residual risk after this pattern.",
        )
        self.assertTrue(any("claims zero residual risk" in error for error in errors))

    def test_rejects_out_of_range_risk_score(self) -> None:
        errors = self._errors_after_text_replacement(
            "examples/01-chatbot-prompt.md",
            "| `RG-F-001` | `RG-HC-003` Credential or Secret Exposure | 7.5 | HIGH |",
            "| `RG-F-001` | `RG-HC-003` Credential or Secret Exposure | 10.1 | HIGH |",
        )
        self.assertTrue(any("out of range 0.0–10.0" in error for error in errors))

    def test_rejects_risk_score_severity_mismatch(self) -> None:
        errors = self._errors_after_text_replacement(
            "examples/01-chatbot-prompt.md",
            "| `RG-F-001` | `RG-HC-003` Credential or Secret Exposure | 7.5 | HIGH |",
            "| `RG-F-001` | `RG-HC-003` Credential or Secret Exposure | 7.5 | CRITICAL |",
        )
        self.assertTrue(any("risk score / severity mismatch" in error for error in errors))

    def test_rejects_overlapping_severity_bands(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/risk-scoring.md",
            "| MEDIUM | 4.0 | 6.9 |",
            "| MEDIUM | 3.9 | 6.9 |",
        )
        self.assertTrue(any("severity bands overlap" in error for error in errors))

    def test_rejects_missing_scoring_dimension(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/risk-scoring.md",
            "### B — Blast Radius (weight 8%)",
            "### Blast Radius criteria removed",
        )
        self.assertTrue(any("missing scoring dimension 'Blast Radius'" in error for error in errors))

    def test_rejects_unknown_dimension_equated_with_zero(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/risk-scoring.md",
            "UNKNOWN / INSUFFICIENT EVIDENCE — no automatic numeric value",
            "UNKNOWN / INSUFFICIENT EVIDENCE — numeric value 0",
        )
        self.assertTrue(
            any("UNKNOWN must not be documented as equivalent to zero" in error for error in errors)
        )

    def test_known_zero_and_not_applicable_legitimately_score_zero(self) -> None:
        text = (self.root / "references/risk-scoring.md").read_text(encoding="utf-8")
        self.assertIn("KNOWN ZERO — numeric value 0", text)
        self.assertIn("NOT APPLICABLE — numeric value 0", text)
        self.assertEqual(0.0, calculate_risk_score((0,) * 12))

    def test_rejects_numbered_exploitability_alias(self) -> None:
        errors = self._errors_after_text_replacement(
            "SKILL.md",
            "for `E = 4 / 3 / 2 / 1`",
            "for `D" + "1 = 4 / 3 / 2 / 1`",
        )
        self.assertTrue(any("stale numbered risk-dimension alias" in error for error in errors))

    def test_risk_component_weight_totals(self) -> None:
        exposure_total = sum(RISK_DIMENSIONS[symbol][2] for symbol in EXPOSURE_SYMBOLS)
        impact_total = sum(RISK_DIMENSIONS[symbol][2] for symbol in IMPACT_SYMBOLS)
        self.assertEqual(40, exposure_total)
        self.assertEqual(60, impact_total)
        self.assertEqual(100, exposure_total + impact_total)
        maximum_weighted_total = sum(
            RISK_DIMENSIONS[symbol][2] * 4 for symbol in RISK_DIMENSIONS
        )
        self.assertEqual(400, maximum_weighted_total)
        self.assertEqual(10.0, calculate_risk_score((4,) * 12))

    def test_rejects_invalid_confidence_value(self) -> None:
        errors = self._errors_after_text_replacement(
            "examples/01-chatbot-prompt.md",
            "| 7.5 | HIGH | MEDIUM | TRIVIAL | Synthetic support token |",
            "| 7.5 | HIGH | CERTAIN | TRIVIAL | Synthetic support token |",
        )
        self.assertTrue(any("invalid confidence value" in error for error in errors))

    def test_rejects_invalid_exploitability_label(self) -> None:
        errors = self._errors_after_text_replacement(
            "examples/01-chatbot-prompt.md",
            "| 7.5 | HIGH | MEDIUM | TRIVIAL | Synthetic support token |",
            "| 7.5 | HIGH | MEDIUM | INSTANT | Synthetic support token |",
        )
        self.assertTrue(any("invalid exploitability label" in error for error in errors))

    def test_rejects_malformed_finding_id(self) -> None:
        errors = self._errors_after_text_replacement(
            "examples/01-chatbot-prompt.md",
            "| `RG-F-001` | `RG-HC-003` Credential or Secret Exposure |",
            "| `RG-F-01` | `RG-HC-003` Credential or Secret Exposure |",
        )
        self.assertTrue(any("malformed finding ID 'RG-F-01'" in error for error in errors))

    def test_rejects_technique_id_where_finding_id_expected(self) -> None:
        errors = self._errors_after_text_replacement(
            "examples/01-chatbot-prompt.md",
            "| `RG-F-001` | `RG-HC-003` Credential or Secret Exposure |",
            "| `RG-HC-003` | `RG-HC-003` Credential or Secret Exposure |",
        )
        self.assertTrue(any("malformed finding ID 'RG-HC-003'" in error for error in errors))

    def test_deterministic_risk_formula_cases(self) -> None:
        cases = (
            ((0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), 0.0, "INFORMATIONAL"),
            ((4, 4, 4, 0, 0, 0, 0, 0, 1, 1, 0, 0), 3.6, "LOW"),
            ((3, 3, 4, 1, 2, 3, 1, 1, 2, 4, 2, 2), 6.0, "MEDIUM"),
            ((3, 3, 4, 3, 3, 3, 3, 2, 3, 4, 3, 4), 7.9, "HIGH"),
            ((4, 4, 4, 4, 4, 3, 4, 4, 4, 4, 3, 4), 9.6, "CRITICAL"),
        )
        scores = []
        for vector, expected_score, expected_severity in cases:
            with self.subTest(expected_score=expected_score):
                score = calculate_risk_score(vector)
                scores.append(score)
                self.assertEqual(expected_score, score)
                self.assertEqual(expected_severity, severity_for_score(score))
        self.assertEqual(scores, sorted(scores))
        self.assertEqual(len(scores), len(set(scores)))


if __name__ == "__main__":
    unittest.main()
