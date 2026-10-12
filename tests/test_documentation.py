from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
CORE_DOCS = (
    "README.md",
    "BENCHMARKING.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs/architecture.md",
    "docs/threat-model.md",
    "docs/usage.md",
    "schemas/README.md",
    "evals/v2/README.md",
)
EXAMPLES = tuple(f"examples/{index:02d}-{name}.md" for index, name in (
    (1, "chatbot-prompt"),
    (2, "rag-agent-prompt"),
    (3, "tool-using-agent-prompt"),
    (4, "multimodal-output-agent"),
    (5, "memory-poisoning-agent"),
    (6, "mcp-multi-agent-workflow"),
))


class DocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.documents = [
            *(ROOT / path for path in CORE_DOCS),
            *sorted((ROOT / "references").glob("*.md")),
            *(ROOT / path for path in EXAMPLES),
        ]

    def test_core_documents_and_examples_exist(self) -> None:
        for relative in (*CORE_DOCS, *EXAMPLES):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_repository_relative_markdown_links_resolve_offline(self) -> None:
        pattern = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
        for document in self.documents:
            text = document.read_text(encoding="utf-8")
            for raw_target in pattern.findall(text):
                target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                path_text = unquote(target.split("#", 1)[0].split("?", 1)[0])
                if not path_text:
                    continue
                resolved = (document.parent / path_text).resolve()
                try:
                    resolved.relative_to(ROOT)
                except ValueError:
                    self.fail(f"{document.relative_to(ROOT)}: link escapes repository: {target}")
                self.assertTrue(
                    resolved.exists(),
                    f"{document.relative_to(ROOT)}: missing link target {target}",
                )

    def test_readme_has_reader_oriented_structure(self) -> None:
        for heading in (
            "# RenGuard",
            "## What RenGuard is—and is not",
            "## Capability overview",
            "## Audit workflow",
            "## Quick start",
            "## Examples",
            "## Evaluation and benchmark status",
            "## Documentation",
            "## Limitations",
        ):
            self.assertIn(heading, self.readme)
        self.assertIn("Model-Agnostic Security for AI Systems & Agents", self.readme)

    def test_readme_preserves_current_repository_counts(self) -> None:
        technique_text = (ROOT / "references/renguard-techniques.md").read_text(encoding="utf-8")
        statuses = re.findall(r"Current RenGuard Coverage Status:\*\* (CORE|PARTIAL|PLANNED)", technique_text)
        pattern_text = (ROOT / "references/hardening-patterns.md").read_text(encoding="utf-8")
        hardening = re.findall(r"^### RG-HARD-[A-Z]+-[0-9]{3} —", pattern_text, re.MULTILINE)
        manifest = json.loads((ROOT / "evals/v2/manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(38, len(statuses))
        self.assertEqual({"CORE": 33, "PARTIAL": 5, "PLANNED": 0}, {name: statuses.count(name) for name in {"CORE", "PARTIAL", "PLANNED"}})
        self.assertEqual(27, len(hardening))
        self.assertEqual((72, 38, 15), (manifest["scenario_count"], manifest["technique_coverage_count"], manifest["mutation_count"]))
        for phrase in ("38 stable techniques", "33 `CORE`, 5 `PARTIAL`, and 0 `PLANNED`", "27 stable `RG-HARD-*` patterns", "72 scenarios", "15 mutation recipes"):
            self.assertIn(phrase, self.readme)

    def test_readme_distinguishes_examples_from_evals(self) -> None:
        self.assertIn("Examples are human-readable educational audits", self.readme)
        self.assertIn("they are not benchmark fixtures or\nperformance evidence", self.readme)
        for relative in EXAMPLES:
            self.assertIn(relative, self.readme)

    def test_no_fake_distribution_or_product_interface_is_documented(self) -> None:
        corpus = "\n".join(path.read_text(encoding="utf-8") for path in self.documents)
        for forbidden in (
            "pip install " + "renguard",
            "npm install " + "renguard",
            "docker pull " + "renguard",
            "POST /v1/" + "audit",
        ):
            self.assertNotIn(forbidden, corpus.lower())

    def test_no_unsupported_security_or_release_claims(self) -> None:
        corpus = "\n".join(path.read_text(encoding="utf-8") for path in self.documents)
        for forbidden in (
            "production-ready",
            "fully secure",
            "guarantees security",
            "prevents all prompt injection",
            "detects all attacks",
            "validated on every model",
            "renGuard v2.0.0 released".lower(),
        ):
            self.assertNotIn(forbidden, corpus.lower())
        self.assertIn("No official RenGuard v2 live benchmark or performance percentage exists", self.readme)
        self.assertIn("Historical v1 provenance—not a v2 result", self.readme)

    def test_documented_python_commands_have_repository_entry_points(self) -> None:
        command_pattern = re.compile(r"^python (scripts/[A-Za-z0-9_./-]+)", re.MULTILINE)
        commands = set()
        for document in self.documents:
            commands.update(command_pattern.findall(document.read_text(encoding="utf-8")))
        self.assertTrue(commands)
        for command in commands:
            self.assertTrue((ROOT / command).is_file(), command)

    def test_new_examples_cover_memory_and_mcp_without_eval_leakage(self) -> None:
        memory = (ROOT / EXAMPLES[4]).read_text(encoding="utf-8")
        mcp = (ROOT / EXAMPLES[5]).read_text(encoding="utf-8")
        for text in (memory, mcp):
            for heading in ("## Architecture", "## Assets / Trust Boundaries", "## Vulnerable Design", "## Findings", "## RenGuard Technique Mapping", "## Attack Chain", "## Risk Assessment", "## Hardening", "## Residual Risk", "## Key Takeaways"):
                self.assertIn(heading, text)
            self.assertNotIn("RG-EVAL-V2-", text)
            self.assertIn("Projected residual risk", text)
        self.assertIn("RG-ME-001", memory)
        self.assertIn("RG-AG-002", mcp)

    def test_markdown_fences_are_balanced(self) -> None:
        for document in self.documents:
            fence_count = sum(line.startswith("```") for line in document.read_text(encoding="utf-8").splitlines())
            self.assertEqual(0, fence_count % 2, str(document.relative_to(ROOT)))


if __name__ == "__main__":
    unittest.main()
