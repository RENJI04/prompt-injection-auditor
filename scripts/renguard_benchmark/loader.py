"""Canonical immutable loading and filtering for RenGuard v2 suites."""

from __future__ import annotations

import copy
from collections import Counter
from pathlib import Path
from typing import Iterable

from .models import Scenario, Suite
from .util import read_json, sha256_file, sha256_json


class SuiteError(ValueError):
    pass


REQUIRED_SCENARIO_FIELDS = {
    "id", "title", "category", "kind", "language", "target_profile", "input", "expected"
}
REQUIRED_EXPECTED_FIELDS = {
    "must_detect", "may_detect", "must_not_detect", "expected_risk",
    "expected_confidence", "assertion_groups", "required_security_properties",
}


def _validate_scenario(raw: dict, filename: str) -> None:
    missing = REQUIRED_SCENARIO_FIELDS - set(raw)
    if missing:
        raise SuiteError(f"{filename}: scenario missing {sorted(missing)}")
    if raw["kind"] not in {"ATTACK", "CHAIN", "CLEAN", "BOUNDARY"}:
        raise SuiteError(f"{filename}: invalid scenario kind {raw['kind']!r}")
    if not isinstance(raw["target_profile"], dict) or not isinstance(raw["input"], dict):
        raise SuiteError(f"{filename}: target_profile and input must be objects")
    expected = raw["expected"]
    if not isinstance(expected, dict) or REQUIRED_EXPECTED_FIELDS - set(expected):
        raise SuiteError(f"{filename}: incomplete expected assertion object")
    for key in ("must_detect", "may_detect", "must_not_detect", "assertion_groups", "required_security_properties"):
        if not isinstance(expected[key], list) or not all(isinstance(item, str) for item in expected[key]):
            raise SuiteError(f"{filename}: expected.{key} must be a string list")
    turns = raw.get("turns")
    if turns is not None and (not isinstance(turns, list) or not all(isinstance(turn, dict) and isinstance(turn.get("role"), str) and isinstance(turn.get("content"), str) for turn in turns)):
        raise SuiteError(f"{filename}: turns must preserve role/content objects")


def load_suite(path: Path) -> Suite:
    root = path.resolve()
    manifest_path = root / "manifest.json"
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("scenario_files"), list):
        raise SuiteError("suite manifest must contain scenario_files")
    scenarios: list[Scenario] = []
    ids: set[str] = set()
    file_hashes = {"manifest.json": sha256_file(manifest_path)}
    for filename in manifest["scenario_files"]:
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise SuiteError(f"unsafe scenario filename {filename!r}")
        source = root / filename
        data = read_json(source)
        file_hashes[filename] = sha256_file(source)
        if not isinstance(data, dict) or not isinstance(data.get("scenarios"), list):
            raise SuiteError(f"{filename}: scenarios must be a list")
        for raw in data["scenarios"]:
            if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
                raise SuiteError(f"{filename}: invalid scenario")
            _validate_scenario(raw, filename)
            if raw["id"] in ids:
                raise SuiteError(f"duplicate scenario ID {raw['id']}")
            ids.add(raw["id"])
            scenarios.append(Scenario(copy.deepcopy(raw), filename))
    mutation_name = manifest.get("mutation_file", "mutations.json")
    if not isinstance(mutation_name, str) or Path(mutation_name).name != mutation_name:
        raise SuiteError(f"unsafe mutation filename {mutation_name!r}")
    mutation_path = root / mutation_name
    if mutation_path.is_file():
        file_hashes[mutation_name] = sha256_file(mutation_path)
    if manifest.get("scenario_count") != len(scenarios):
        raise SuiteError("manifest scenario_count does not match loaded scenarios")
    if Counter(s.kind for s in scenarios) != Counter(manifest.get("kind_counts", {})):
        raise SuiteError("manifest kind_counts do not match loaded scenarios")
    scenarios.sort(key=lambda scenario: scenario.id)
    aggregate = sha256_json({"files": dict(sorted(file_hashes.items()))})
    return Suite(root, copy.deepcopy(manifest), tuple(scenarios), aggregate, file_hashes)


def filter_scenarios(
    scenarios: Iterable[Scenario], *, ids: set[str] | None = None,
    categories: set[str] | None = None, kinds: set[str] | None = None,
    languages: set[str] | None = None, techniques: set[str] | None = None,
    multi_turn: bool | None = None, chain: bool | None = None,
    risk_modes: set[str] | None = None,
) -> tuple[Scenario, ...]:
    selected: list[Scenario] = []
    for scenario in scenarios:
        data = scenario.canonical
        language = data["language"]
        language_values = set(language if isinstance(language, list) else [language])
        expected = data["expected"]
        scenario_techniques = set(expected["must_detect"] + expected["may_detect"] + expected["must_not_detect"])
        checks = (
            ids is None or scenario.id in ids,
            categories is None or scenario.category in categories,
            kinds is None or scenario.kind in kinds,
            languages is None or bool(language_values & languages),
            techniques is None or bool(scenario_techniques & techniques),
            multi_turn is None or bool(data.get("turns")) is multi_turn,
            chain is None or (scenario.kind == "CHAIN") is chain,
            risk_modes is None or expected["expected_risk"]["mode"] in risk_modes,
        )
        if all(checks):
            selected.append(scenario)
    return tuple(sorted(selected, key=lambda scenario: scenario.id))
