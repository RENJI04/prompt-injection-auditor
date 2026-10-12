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

    def _change_v2_case(self, relative_name: str, index: int, change) -> list[str]:
        data = self._read_json(relative_name)
        change(data["scenarios"][index])
        self._write_json(relative_name, data)
        return validate_repository(self.root).errors

    def _v2_scenario_files(self) -> list[Path]:
        manifest = self._read_json("evals/v2/manifest.json")
        return [self.root / "evals" / "v2" / name for name in manifest["scenario_files"]]

    def test_repository_fixture_is_valid(self) -> None:
        self.assertEqual([], validate_repository(self.root).errors)

    def test_rejects_missing_phase9_runner_entry_point(self) -> None:
        (self.root / "scripts/run_benchmark.py").unlink()
        errors = validate_repository(self.root).errors
        self.assertTrue(any("Phase 9 entry point is missing" in error for error in errors))

    def test_rejects_missing_phase9_module(self) -> None:
        (self.root / "scripts/renguard_benchmark/loader.py").unlink()
        errors = validate_repository(self.root).errors
        self.assertTrue(
            any("loader.py" in error and "required Phase 9 module" in error for error in errors)
        )

    def test_rejects_phase9_version_mutation(self) -> None:
        errors = self._errors_after_text_replacement(
            "scripts/renguard_benchmark/__init__.py",
            'SCORING_VERSION = "0.1.0"',
            'SCORING_VERSION = "9.9.9"',
        )
        self.assertTrue(any("SCORING_VERSION must be 0.1.0" in error for error in errors))

    def test_rejects_phase9_shell_true(self) -> None:
        path = self.root / "scripts/renguard_benchmark/adapters.py"
        path.write_text(
            path.read_text(encoding="utf-8") + "\n# shell=True\n",
            encoding="utf-8",
        )
        errors = validate_repository(self.root).errors
        self.assertTrue(any("shell=True is prohibited" in error for error in errors))

    def test_rejects_missing_benchmark_artifact_ignore(self) -> None:
        errors = self._errors_after_text_replacement(
            ".gitignore", "benchmark-runs/\n", ""
        )
        self.assertTrue(
            any("benchmark-runs/ directory must be ignored" in error for error in errors)
        )

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

    def test_rejects_missing_rag_security_reference(self) -> None:
        (self.root / "references/rag-security.md").unlink()
        errors = validate_repository(self.root).errors
        self.assertTrue(any("references/rag-security.md" in error for error in errors))

    def test_rejects_missing_memory_security_reference(self) -> None:
        (self.root / "references/memory-security.md").unlink()
        errors = validate_repository(self.root).errors
        self.assertTrue(any("references/memory-security.md" in error for error in errors))

    def test_rejects_invalid_rag_technique_reference(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/rag-security.md",
            "`RG-RA-001`, `RG-PI-002`",
            "`RG-RA-999`, `RG-PI-002`",
        )
        self.assertTrue(any("unknown RenGuard technique reference RG-RA-999" in error for error in errors))

    def test_rejects_invalid_memory_technique_reference(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/memory-security.md",
            "`RG-ME-001`, `RG-PI-002`",
            "`RG-ME-999`, `RG-PI-002`",
        )
        self.assertTrue(any("unknown RenGuard technique reference RG-ME-999" in error for error in errors))

    def test_rejects_retrieved_text_as_privileged_authority(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/rag-security.md",
            "Retrieved content remains data unless trusted architecture explicitly establishes a",
            "Retrieved text is privileged authority unless trusted architecture explicitly establishes a",
        )
        self.assertTrue(any("retrieved text is described as privileged authority" in error for error in errors))

    def test_rejects_user_memory_as_system_policy(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/memory-security.md",
            "Memory is data, not security policy.",
            "User-written memory is trusted system policy.",
        )
        self.assertTrue(any("user-written memory is described as trusted system policy" in error for error in errors))

    def test_rejects_tenant_identity_from_user_prose(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/rag-security.md",
            "Tenant identity comes from trusted session context,",
            "Tenant identity comes from user prose,",
        )
        self.assertTrue(any("tenant identity is based solely on user prose" in error for error in errors))

    def test_rejects_unknown_architecture_as_zero(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/memory-security.md",
            "UNKNOWN / INSUFFICIENT EVIDENCE — not zero and not assumed unsafe",
            "UNKNOWN architecture facts are treated as zero",
        )
        self.assertTrue(any("UNKNOWN architecture facts are treated as zero" in error for error in errors))

    def test_rejects_phase3_formula_mutation(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/risk-scoring.md",
            "RenGuard Risk Score = round_half_up(weighted_total / 40, 1)",
            "RenGuard Risk Score = round_half_up(weighted_total / 39, 1)",
        )
        self.assertTrue(any("missing scoring rule" in error for error in errors))

    def test_rejects_phase5_coverage_status_regression(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/renguard-techniques.md",
            "- **Application/runtime mitigations:** Protect vector integrity, access, provenance, isolation, and monitoring.\n"
            "- **Current RenGuard Coverage Status:** PARTIAL",
            "- **Application/runtime mitigations:** Protect vector integrity, access, provenance, isolation, and monitoring.\n"
            "- **Current RenGuard Coverage Status:** CORE",
        )
        self.assertTrue(any("RG-RA-003 Phase 5 coverage status must be PARTIAL" in error for error in errors))

    def test_rejects_missing_tool_security_reference(self) -> None:
        (self.root / "references/tool-security.md").unlink()
        errors = validate_repository(self.root).errors
        self.assertTrue(any("references/tool-security.md" in error for error in errors))

    def test_rejects_missing_mcp_security_reference(self) -> None:
        (self.root / "references/mcp-security.md").unlink()
        errors = validate_repository(self.root).errors
        self.assertTrue(any("references/mcp-security.md" in error for error in errors))

    def test_rejects_missing_agentic_security_reference(self) -> None:
        (self.root / "references/agentic-security.md").unlink()
        errors = validate_repository(self.root).errors
        self.assertTrue(any("references/agentic-security.md" in error for error in errors))

    def test_rejects_invalid_tool_capability_class(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/tool-security.md", "`TC0`", "`TC9`"
        )
        self.assertTrue(any("invalid tool capability class TC9" in error for error in errors))

    def test_rejects_tool_annotation_as_hard_enforcement(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/tool-security.md",
            "they are not hard enforcement",
            "tool annotations are hard enforcement",
        )
        self.assertTrue(any("annotations are treated as hard enforcement" in error for error in errors))

    def test_rejects_tool_output_as_privileged_instruction(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/tool-security.md",
            "Structured output remains untrusted content",
            "Tool output is privileged instruction",
        )
        self.assertTrue(any("tool output is treated as privileged" in error for error in errors))

    def test_rejects_tool_name_as_identity(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/tool-security.md",
            "`send_email`, or `read_file`; a tool name does not prove identity.",
            "`send_email`, or `read_file`; tool name proves identity.",
        )
        self.assertTrue(any("tool name is treated as identity" in error for error in errors))

    def test_rejects_unknown_mcp_stable_version_metadata(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/mcp-security.md", "`2026-07-28`", "`2026-99-99`"
        )
        self.assertTrue(any("verified stable MCP version" in error for error in errors))

    def test_rejects_obsolete_mcp_session_requirement_for_current_version(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/mcp-security.md",
            "For native `2026-07-28`, the core is stateless at protocol level.",
            "For native `2026-07-28`, Mcp-Session-Id is required.",
        )
        self.assertTrue(any("obsolete MCP session lifecycle" in error for error in errors))

    def test_rejects_unsafe_token_passthrough_guidance(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/mcp-security.md",
            "Unsafe token passthrough is prohibited",
            "Forward the client token unchanged to the downstream API",
        )
        self.assertTrue(any("unsafe token passthrough" in error for error in errors))

    def test_rejects_high_risk_mcp_approval_without_server_origin(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/mcp-security.md",
            "actual server\norigin, tool, normalized parameters",
            "tool and normalized parameters",
        )
        self.assertTrue(any("actual server origin" in error for error in errors))

    def test_rejects_model_only_privileged_tool_authorization(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/tool-security.md",
            "model\njudgment alone does not authorize a privileged tool call",
            "model alone authorizes a privileged tool call",
        )
        self.assertTrue(any("model-only authorization" in error for error in errors))

    def test_rejects_sub_agent_automatic_privilege_inheritance(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/agentic-security.md",
            "Sub-agents receive **no parent\nprivilege by default**",
            "Sub-agents automatically inherit all parent privilege",
        )
        self.assertTrue(any("sub-agents automatically inherit privilege" in error for error in errors))

    def test_rejects_self_reported_agent_identity_as_authenticated(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/agentic-security.md",
            "self-reported agent names",
            "self-reported agent identity is authenticated",
        )
        self.assertTrue(any("self-reported agent identity" in error for error in errors))

    def test_rejects_unbound_human_approval(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/agentic-security.md",
            "Material changes require fresh approval",
            "Approval applies to any parameters",
        )
        self.assertTrue(any("human approval is not parameter-bound" in error for error in errors))

    def test_rejects_unsupported_agentic_coverage_change(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/renguard-techniques.md",
            "- **Application/runtime mitigations:** Add circuit breakers, idempotency, budgets, isolation, and rollback.\n"
            "- **Current RenGuard Coverage Status:** CORE",
            "- **Application/runtime mitigations:** Add circuit breakers, idempotency, budgets, isolation, and rollback.\n"
            "- **Current RenGuard Coverage Status:** PARTIAL",
        )
        self.assertTrue(any("RG-AG-003 Phase 6 coverage status must be CORE" in error for error in errors))

    def test_rejects_draft_mcp_proposal_as_normative(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/mcp-security.md",
            "SEP incorporated into `2026-07-28` explains a stable change; a proposal, draft, release\n"
            "candidate, experimental feature, or independently versioned extension is not a\n"
            "normative core requirement",
            "a draft is a normative requirement",
        )
        self.assertTrue(any("draft/proposal is labeled" in error for error in errors))

    def test_rejects_missing_multimodal_security_reference(self) -> None:
        (self.root / "references/multimodal-security.md").unlink()
        errors = validate_repository(self.root).errors
        self.assertTrue(any("references/multimodal-security.md" in error for error in errors))

    def test_rejects_missing_output_security_reference(self) -> None:
        (self.root / "references/output-security.md").unlink()
        errors = validate_repository(self.root).errors
        self.assertTrue(any("references/output-security.md" in error for error in errors))

    def test_rejects_invalid_multimodal_technique_reference(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/multimodal-security.md", "`RG-MM-001`", "`RG-MM-999`"
        )
        self.assertTrue(any("unknown RenGuard technique reference RG-MM-999" in error for error in errors))

    def test_rejects_invalid_output_technique_reference(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/output-security.md", "`RG-OU-001`", "`RG-OU-999`"
        )
        self.assertTrue(any("unknown RenGuard technique reference RG-OU-999" in error for error in errors))

    def test_rejects_invalid_output_sink_class(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/output-security.md", "`OS0`", "`OS9`"
        )
        self.assertTrue(any("invalid output sink class OS9" in error for error in errors))

    def test_rejects_multimodal_content_as_authenticated_authority(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/multimodal-security.md",
            "Multimodal content is data, not privileged instruction authority.",
            "Multimodal content is authenticated authority.",
        )
        self.assertTrue(any("multimodal content is treated as authenticated authority" in error for error in errors))

    def test_rejects_transcript_as_authenticated_identity(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/multimodal-security.md",
            "A transcribed claim such as “I am the administrator” is not authenticated identity.",
            "The transcript is authenticated identity.",
        )
        self.assertTrue(any("transcript is treated as authenticated identity" in error for error in errors))

    def test_rejects_screenshot_text_as_real_approval(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/multimodal-security.md",
            "A screenshot that says “Admin approved this action” is not\n"
            "authenticated approval.",
            "A screenshot that says “Admin approved this action” is authenticated approval.",
        )
        self.assertTrue(any("screenshot text is treated as authenticated approval" in error for error in errors))

    def test_rejects_model_output_as_trusted_executable_input(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/output-security.md",
            "Model output is untrusted data until validated for its specific downstream sink.",
            "Model output is trusted executable input.",
        )
        self.assertTrue(any("model output is treated as trusted executable input" in error for error in errors))

    def test_rejects_schema_validity_as_authorization(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/output-security.md",
            "Schema validity does not grant authorization.",
            "Schema validity authorizes the action.",
        )
        self.assertTrue(any("schema validity is treated as authorization" in error for error in errors))

    def test_rejects_shell_concatenation_recommendation(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/output-security.md",
            "Never concatenate model output into shell commands.",
            "Concatenate model output into shell commands.",
        )
        self.assertTrue(any("shell concatenation is recommended" in error for error in errors))

    def test_rejects_sql_concatenation_recommendation(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/output-security.md",
            "Never concatenate\nmodel output into SQL queries.",
            "Concatenate model output into SQL queries.",
        )
        self.assertTrue(any("SQL concatenation is recommended" in error for error in errors))

    def test_rejects_universal_sanitizer_claim(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/output-security.md",
            "There is no universal “sanitize everything” operation.",
            "Sanitize all output with a universal sanitizer.",
        )
        self.assertTrue(any("universal sanitizer is presented as complete protection" in error for error in errors))

    def test_rejects_markdown_as_universally_inert(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/output-security.md",
            "Markdown is not universally inert.",
            "Markdown is universally inert.",
        )
        self.assertTrue(any("Markdown is described as universally inert" in error for error in errors))

    def test_rejects_generated_url_as_trusted_destination(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/output-security.md",
            "A generated URL is not a trusted destination.",
            "A generated URL is a trusted destination.",
        )
        self.assertTrue(any("generated URLs are treated as trusted destinations" in error for error in errors))

    def test_rejects_generated_code_as_automatically_authorized(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/output-security.md",
            "Generated code does not gain execution authority.",
            "Generated code is automatically authorized for execution.",
        )
        self.assertTrue(any("generated code is automatically authorized" in error for error in errors))

    def test_rejects_unsupported_multimodal_coverage_promotion(self) -> None:
        errors = self._errors_after_text_replacement(
            "references/renguard-techniques.md",
            "- **Application/runtime mitigations:** Preserve source/transformation provenance, separate identity and authority, validate derived parameters, and independently authorize resulting actions.\n"
            "- **Current RenGuard Coverage Status:** PARTIAL",
            "- **Application/runtime mitigations:** Preserve source/transformation provenance, separate identity and authority, validate derived parameters, and independently authorize resulting actions.\n"
            "- **Current RenGuard Coverage Status:** CORE",
        )
        self.assertTrue(any("RG-MM-001 Phase 7 coverage status must be PARTIAL" in error for error in errors))

    def test_rejects_duplicate_v2_eval_id(self) -> None:
        data = self._read_json("evals/v2/direct-authority.json")
        data["scenarios"][1]["id"] = data["scenarios"][0]["id"]
        self._write_json("evals/v2/direct-authority.json", data)
        errors = validate_repository(self.root).errors
        self.assertTrue(any("duplicate v2 eval ID" in error for error in errors))

    def test_rejects_malformed_v2_eval_id(self) -> None:
        errors = self._change_v2_case(
            "evals/v2/direct-authority.json", 0,
            lambda case: case.__setitem__("id", "RG-EVAL-V2-1"),
        )
        self.assertTrue(any("malformed v2 eval ID" in error for error in errors))

    def test_rejects_v2_missing_required_field(self) -> None:
        errors = self._change_v2_case(
            "evals/v2/direct-authority.json", 0,
            lambda case: case.pop("description"),
        )
        self.assertTrue(any("missing required field" in error for error in errors))

    def test_rejects_invalid_v2_scenario_kind(self) -> None:
        errors = self._change_v2_case(
            "evals/v2/direct-authority.json", 0,
            lambda case: case.__setitem__("kind", "SUSPICIOUS"),
        )
        self.assertTrue(any("invalid scenario kind" in error for error in errors))

    def test_rejects_invalid_v2_language_tag(self) -> None:
        errors = self._change_v2_case(
            "evals/v2/direct-authority.json", 0,
            lambda case: case.__setitem__("language", "english"),
        )
        self.assertTrue(any("invalid language tag metadata" in error for error in errors))

    def test_rejects_unknown_v2_technique_id(self) -> None:
        errors = self._change_v2_case(
            "evals/v2/direct-authority.json", 0,
            lambda case: case["expected"]["must_detect"].__setitem__(0, "RG-PI-999"),
        )
        self.assertTrue(any("unknown RenGuard technique ID" in error for error in errors))

    def test_rejects_unknown_v2_hardening_pattern(self) -> None:
        errors = self._change_v2_case(
            "evals/v2/direct-authority.json", 0,
            lambda case: case["expected"].__setitem__(
                "required_hardening_patterns", ["RG-HARD-P-999"]
            ),
        )
        self.assertTrue(any("unknown hardening pattern ID" in error for error in errors))

    def test_rejects_unknown_v2_owasp_llm_mapping(self) -> None:
        errors = self._change_v2_case(
            "evals/v2/direct-authority.json", 0,
            lambda case: case["expected"]["expected_owasp_llm"].__setitem__(0, "LLM99:2026"),
        )
        self.assertTrue(any("unknown OWASP LLM 2026 mapping" in error for error in errors))

    def test_rejects_agentic_mapping_for_non_agentic_v2_case(self) -> None:
        def change(case) -> None:
            case["agentic_applicable"] = False
            case["target_profile"]["agentic"] = False

        errors = self._change_v2_case("evals/v2/mcp.json", 0, change)
        self.assertTrue(any("Agentic mapping used for non-agentic scenario" in error for error in errors))

    def test_rejects_invalid_v2_assertion_group(self) -> None:
        errors = self._change_v2_case(
            "evals/v2/direct-authority.json", 0,
            lambda case: case["expected"]["assertion_groups"].append("KEYWORD_MATCH"),
        )
        self.assertTrue(any("invalid assertion group" in error for error in errors))

    def test_rejects_exact_v2_risk_missing_dimension(self) -> None:
        errors = self._change_v2_case(
            "evals/v2/rag-retrieval.json", 0,
            lambda case: case["expected"]["expected_risk"]["dimensions"].pop("G"),
        )
        self.assertTrue(any("EXACT risk dimensions must contain all 12" in error for error in errors))

    def test_rejects_exact_v2_risk_score_mismatch(self) -> None:
        errors = self._change_v2_case(
            "evals/v2/rag-retrieval.json", 0,
            lambda case: case["expected"]["expected_risk"].__setitem__("score", 1.0),
        )
        self.assertTrue(any("exact risk score mismatch" in error for error in errors))

    def test_rejects_exact_v2_risk_severity_mismatch(self) -> None:
        errors = self._change_v2_case(
            "evals/v2/rag-retrieval.json", 0,
            lambda case: case["expected"]["expected_risk"].__setitem__("severity", "LOW"),
        )
        self.assertTrue(any("exact risk score / severity mismatch" in error for error in errors))

    def test_rejects_clean_v2_case_requiring_detection(self) -> None:
        errors = self._change_v2_case(
            "evals/v2/clean-controls.json", 0,
            lambda case: case["expected"].__setitem__("must_detect", ["RG-PI-001"]),
        )
        self.assertTrue(any("CLEAN case must not require vulnerability detection" in error for error in errors))

    def test_rejects_unknown_v2_mutation_id(self) -> None:
        def change(case) -> None:
            case["mutation_eligible"] = True
            case["mutation_ids"] = ["RG-MUT-999"]

        errors = self._change_v2_case("evals/v2/direct-authority.json", 0, change)
        self.assertTrue(any("unknown mutation ID" in error for error in errors))

    def test_rejects_duplicate_v2_mutation_id(self) -> None:
        data = self._read_json("evals/v2/mutations.json")
        data["mutation_recipes"][1]["id"] = data["mutation_recipes"][0]["id"]
        self._write_json("evals/v2/mutations.json", data)
        errors = validate_repository(self.root).errors
        self.assertTrue(any("duplicate mutation ID" in error for error in errors))

    def test_rejects_v2_manifest_scenario_count_mismatch(self) -> None:
        data = self._read_json("evals/v2/manifest.json")
        data["scenario_count"] += 1
        self._write_json("evals/v2/manifest.json", data)
        errors = validate_repository(self.root).errors
        self.assertTrue(any("scenario_count mismatch" in error for error in errors))

    def test_rejects_v2_manifest_category_count_mismatch(self) -> None:
        data = self._read_json("evals/v2/manifest.json")
        data["category_counts"]["TOOLS"] += 1
        self._write_json("evals/v2/manifest.json", data)
        errors = validate_repository(self.root).errors
        self.assertTrue(any("category_counts mismatch" in error for error in errors))

    def test_rejects_v2_manifest_language_count_mismatch(self) -> None:
        data = self._read_json("evals/v2/manifest.json")
        data["language_counts"]["en"] += 1
        self._write_json("evals/v2/manifest.json", data)
        errors = validate_repository(self.root).errors
        self.assertTrue(any("language_counts mismatch" in error for error in errors))

    def test_rejects_too_few_v2_clean_boundary_controls(self) -> None:
        changed = 0
        for path in self._v2_scenario_files():
            data = json.loads(path.read_text(encoding="utf-8"))
            for case in data["scenarios"]:
                if case["kind"] in {"CLEAN", "BOUNDARY"} and changed < 7:
                    case["kind"] = "ATTACK"
                    changed += 1
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        self.assertEqual(7, changed)
        errors = validate_repository(self.root).errors
        self.assertTrue(any("at least 12 clean/boundary controls required" in error for error in errors))

    def test_rejects_too_few_v2_multilingual_cases(self) -> None:
        changed = 0
        for path in self._v2_scenario_files():
            data = json.loads(path.read_text(encoding="utf-8"))
            for case in data["scenarios"]:
                if case["language"] != "en" and changed < 7:
                    case["language"] = "en"
                    changed += 1
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        self.assertEqual(7, changed)
        errors = validate_repository(self.root).errors
        self.assertTrue(any("at least 16 non-English/mixed-language" in error for error in errors))

    def test_rejects_too_few_v2_multi_turn_cases(self) -> None:
        changed = 0
        for path in self._v2_scenario_files():
            data = json.loads(path.read_text(encoding="utf-8"))
            for case in data["scenarios"]:
                if "turns" in case and changed < 3:
                    case.pop("turns")
                    changed += 1
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        self.assertEqual(3, changed)
        errors = validate_repository(self.root).errors
        self.assertTrue(any("at least 10 multi-turn scenarios required" in error for error in errors))

    def test_rejects_too_few_v2_attack_chain_cases(self) -> None:
        changed = 0
        for path in self._v2_scenario_files():
            data = json.loads(path.read_text(encoding="utf-8"))
            for case in data["scenarios"]:
                if case["kind"] == "CHAIN" and changed < 10:
                    case["kind"] = "ATTACK"
                    changed += 1
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        self.assertEqual(10, changed)
        errors = validate_repository(self.root).errors
        self.assertTrue(any("at least 10 attack-chain scenarios required" in error for error in errors))

    def test_rejects_uncovered_v2_renguard_technique(self) -> None:
        for path in self._v2_scenario_files():
            data = json.loads(path.read_text(encoding="utf-8"))
            for case in data["scenarios"]:
                expected = case["expected"]
                for field in ("must_detect", "may_detect", "must_not_detect"):
                    expected[field] = [
                        "RG-AG-005" if value == "RG-MI-001" else value
                        for value in expected[field]
                    ]
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        errors = validate_repository(self.root).errors
        self.assertTrue(any("uncovered RenGuard technique" in error for error in errors))

    def test_rejects_public_v2_case_labeled_hidden(self) -> None:
        errors = self._change_v2_case(
            "evals/v2/direct-authority.json", 0,
            lambda case: case.__setitem__("public_visibility", "HIDDEN_HOLDOUT"),
        )
        self.assertTrue(any("falsely labeled private/hidden holdout" in error for error in errors))

    def test_rejects_historical_eval_fixture_mutation(self) -> None:
        path = self.root / "evals/files/minimal_prompt.txt"
        path.write_text(path.read_text(encoding="utf-8") + "\nmutation\n", encoding="utf-8")
        errors = validate_repository(self.root).errors
        self.assertTrue(any("provenance-preserved benchmark/eval path changed" in error for error in errors))

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
