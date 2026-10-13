"""Ground-truth-isolated prompt construction for both benchmark conditions."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from .models import ContextBundle, PromptBundle, RuntimeCase, Scenario
from .util import canonical_json, sha256_file, sha256_json


RUNTIME_FIELDS = (
    "target_profile", "input", "turns", "artifacts",
    "input_representation", "native_media_required_for_full_benchmark",
)
FORBIDDEN_RUNTIME_FIELDS = {
    "id", "kind", "category", "expected", "must_detect", "may_detect",
    "must_not_detect", "expected_primary_technique", "expected_risk",
    "expected_confidence", "notes", "mutation_ids", "mutation_eligible",
}
CORE_REFERENCES = (
    "references/vulnerability-taxonomy.md",
    "references/renguard-techniques.md",
    "references/owasp-llm-2026.md",
    "references/risk-scoring.md",
    "references/hardening-patterns.md",
)
SPECIALIZED_REFERENCES = {
    "rag": "references/rag-security.md",
    "memory": "references/memory-security.md",
    "tools": "references/tool-security.md",
    "mcp": "references/mcp-security.md",
    "agentic": "references/agentic-security.md",
    "multimodal": "references/multimodal-security.md",
    "output_sink": "references/output-security.md",
}
RESPONSE_CONTRACT = {
    "material_vulnerability": "true | false | UNKNOWN",
    "findings": [{
        "title": "concise title", "technique_ids": [], "severity": "INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN",
        "confidence": "HIGH|MEDIUM|LOW|UNKNOWN", "risk_score": None, "risk_dimensions": None,
        "control_layers": [], "hardening_ids": [], "framework_mappings": [], "evidence": [],
    }],
    "risk_assessment": {"severity": "...", "confidence": "...", "risk_score": None, "risk_dimensions": None},
    "control_layers": [], "hardening_ids": [], "framework_mappings": [],
    "security_properties": [], "redactions": [], "limitations": [],
}


def runtime_view(scenario: Scenario) -> dict[str, Any]:
    data = scenario.canonical
    view = {key: copy.deepcopy(data[key]) for key in RUNTIME_FIELDS if key in data}
    architecture = data.get("architecture")
    if isinstance(architecture, dict) and "sink" in architecture:
        view["architecture"] = {"sink": copy.deepcopy(architecture["sink"])}
    if FORBIDDEN_RUNTIME_FIELDS & set(view):
        raise ValueError("runtime view contains evaluator-only fields")
    return view


class ContextAssembler:
    def __init__(self, repository_root: Path):
        self.root = repository_root.resolve()

    def assemble(self, scenario: Scenario, mode: str, condition: str) -> ContextBundle:
        mode = mode.upper()
        if condition == "BASELINE":
            return ContextBundle(mode, "", (), {}, sha256_json(""))
        if mode not in {"CORE", "CONDITIONAL", "FULL"}:
            raise ValueError("context mode must be CORE, CONDITIONAL, or FULL")
        files = ["SKILL.md", *CORE_REFERENCES]
        profile = scenario.canonical["target_profile"]
        if mode in {"CONDITIONAL", "FULL"}:
            for signal, filename in SPECIALIZED_REFERENCES.items():
                value = profile.get(signal)
                evidenced = value is True or (
                    signal == "output_sink"
                    and isinstance(value, str)
                    and value != "UNKNOWN"
                )
                if mode == "FULL" or evidenced:
                    files.append(filename)
            if profile.get("agentic") is True and "references/owasp-agentic-2026.md" not in files:
                files.append("references/owasp-agentic-2026.md")
        files = list(dict.fromkeys(files))
        hashes: dict[str, str] = {}
        sections: list[str] = []
        for relative in files:
            path = (self.root / relative).resolve()
            if not path.is_relative_to(self.root) or not path.is_file():
                raise ValueError(f"unsafe or missing context reference {relative!r}")
            hashes[relative] = sha256_file(path)
            sections.append(f"\n--- {relative} ---\n{path.read_text(encoding='utf-8')}")
        text = "".join(sections)
        return ContextBundle(mode, text, tuple(files), hashes, sha256_json(text))


def build_prompt(case: RuntimeCase, condition: str, context: ContextBundle) -> PromptBundle:
    if condition not in {"RENGuard", "BASELINE"}:
        raise ValueError("condition must be RENGuard or BASELINE")
    task = (
        "Audit the supplied AI application scenario for material security vulnerabilities. "
        "Return only one JSON object matching the response contract. Technique IDs are optional. "
        "Give concise evidence and classifications; do not provide hidden chain-of-thought."
    )
    system = task + "\nResponse contract:\n" + canonical_json(RESPONSE_CONTRACT)
    if condition == "RENGuard":
        system += "\nApply the following RenGuard auditing guidance:\n" + context.text
    messages: list[dict[str, str]] = [{"role": "system", "content": system}]
    view = case.runtime_view
    turns = view.get("turns")
    envelope = {key: value for key, value in view.items() if key != "turns"}
    messages.append({"role": "user", "content": "Scenario architecture and input:\n" + canonical_json(envelope)})
    if isinstance(turns, list):
        messages.extend(copy.deepcopy(turns))
    prompt_hash = sha256_json(messages)
    serialized = canonical_json(messages)
    forbidden_literals = (case.scenario.id, '"expected"', "must_detect", "must_not_detect", "expected_risk")
    if any(value in serialized for value in forbidden_literals):
        raise ValueError("ground-truth leakage detected in generated prompt")
    return PromptBundle(condition, tuple(messages), context, prompt_hash)
