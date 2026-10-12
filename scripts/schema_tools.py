#!/usr/bin/env python3
"""Offline structural validation for RenGuard's documented JSON contracts.

This module intentionally implements only the JSON Schema keywords used by the
repository.  It is not a general-purpose Draft 2020-12 implementation and never
fetches remote references.  Repository semantics remain in validate_repo.py.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas"
DIALECT = "https://json-schema.org/draft/2020-12/schema"
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
EXPECTED_SCHEMA_KEYS = {
    "eval.scenario",
    "eval.suite_manifest",
    "eval.mutations",
    "benchmark.run_manifest",
    "benchmark.response_record",
    "benchmark.score_record",
    "benchmark.summary",
    "benchmark.review_record",
    "benchmark.pricing",
}


class SchemaContractError(ValueError):
    """Raised when a schema contract or instance is invalid."""


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaContractError(f"{path}: invalid JSON: {exc}") from exc


def _is_type(value: Any, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    if expected == "string":
        return isinstance(value, str)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    raise SchemaContractError(f"unsupported schema type {expected!r}")


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _json_pointer(document: Any, pointer: str, *, source: Path) -> Any:
    if not pointer:
        return document
    if not pointer.startswith("/"):
        raise SchemaContractError(f"{source}: invalid JSON pointer #{pointer}")
    current = document
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            raise SchemaContractError(f"{source}: unresolved JSON pointer #{pointer}")
    return current


def resolve_ref(ref: str, current_schema: Path, schema_root: Path | None = None) -> tuple[dict[str, Any], Path]:
    """Resolve only an approved repository-local schema reference."""
    if not isinstance(ref, str) or not ref:
        raise SchemaContractError(f"{current_schema}: $ref must be a non-empty string")
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", ref) or ref.startswith(("/", "\\")):
        raise SchemaContractError(f"{current_schema}: external or absolute $ref is prohibited: {ref}")
    path_part, marker, fragment = ref.partition("#")
    target_path = current_schema if not path_part else (current_schema.parent / path_part).resolve()
    if schema_root is None:
        schema_root = next(
            (parent for parent in (current_schema.parent, *current_schema.parents) if parent.name == "schemas"),
            SCHEMA_ROOT,
        )
    schema_root = schema_root.resolve()
    if not _inside(schema_root, target_path) or target_path.suffix != ".json":
        raise SchemaContractError(f"{current_schema}: $ref escapes approved schema root: {ref}")
    document = load_json(target_path)
    target = _json_pointer(document, fragment if marker else "", source=target_path)
    if not isinstance(target, dict):
        raise SchemaContractError(f"{current_schema}: $ref target is not a schema object: {ref}")
    return target, target_path


def _schema_branches(value: Any, branches: Iterable[Any], current_schema: Path, path: str) -> list[list[str]]:
    results = []
    for branch in branches:
        if not isinstance(branch, dict):
            raise SchemaContractError(f"{current_schema}: schema branch at {path} is not an object")
        results.append(validate_instance(value, branch, current_schema=current_schema, path=path))
    return results


def validate_instance(value: Any, schema: dict[str, Any], *, current_schema: Path, path: str = "$") -> list[str]:
    """Validate an instance with the repository's documented keyword subset."""
    if not isinstance(schema, dict):
        raise SchemaContractError(f"{current_schema}: schema at {path} is not an object")
    errors: list[str] = []
    if "$ref" in schema:
        target, target_path = resolve_ref(schema["$ref"], current_schema)
        errors.extend(validate_instance(value, target, current_schema=target_path, path=path))
    if "allOf" in schema:
        for branch_errors in _schema_branches(value, schema["allOf"], current_schema, path):
            errors.extend(branch_errors)
    if "anyOf" in schema:
        branch_results = _schema_branches(value, schema["anyOf"], current_schema, path)
        if not any(not result for result in branch_results):
            errors.append(f"{path}: does not match any allowed schema branch")
            return errors
    if "oneOf" in schema:
        branch_results = _schema_branches(value, schema["oneOf"], current_schema, path)
        matches = sum(not result for result in branch_results)
        if matches != 1:
            errors.append(f"{path}: must match exactly one schema branch (matched {matches})")
            return errors
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}, got {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: expected one of {schema['enum']!r}, got {value!r}")

    expected_types = schema.get("type")
    if expected_types is not None:
        expected_types = [expected_types] if isinstance(expected_types, str) else expected_types
        if not isinstance(expected_types, list) or not all(isinstance(item, str) for item in expected_types):
            raise SchemaContractError(f"{current_schema}: invalid type declaration at {path}")
        if not any(_is_type(value, item) for item in expected_types):
            errors.append(f"{path}: expected type {expected_types}, got {type(value).__name__}")
            return errors

    if isinstance(value, dict):
        required = schema.get("required", [])
        if not isinstance(required, list):
            raise SchemaContractError(f"{current_schema}: required must be an array at {path}")
        for key in required:
            if key not in value:
                errors.append(f"{path}: missing required property {key!r}")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise SchemaContractError(f"{current_schema}: properties must be an object at {path}")
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in properties:
                errors.extend(validate_instance(child, properties[key], current_schema=current_schema, path=child_path))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected property {key!r}")
            elif isinstance(schema.get("additionalProperties"), dict):
                errors.extend(validate_instance(child, schema["additionalProperties"], current_schema=current_schema, path=child_path))
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            errors.append(f"{path}: requires at least {schema['minProperties']} properties")
    elif isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: requires at least {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: allows at most {schema['maxItems']} items")
        if schema.get("uniqueItems"):
            serialized = [json.dumps(item, sort_keys=True, ensure_ascii=False) for item in value]
            if len(serialized) != len(set(serialized)):
                errors.append(f"{path}: array items must be unique")
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(value):
                errors.extend(validate_instance(item, schema["items"], current_schema=current_schema, path=f"{path}[{index}]"))
    elif isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: string is shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: string is longer than {schema['maxLength']}")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            errors.append(f"{path}: value {value!r} does not match {schema['pattern']!r}")
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: value {value} is below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: value {value} exceeds maximum {schema['maximum']}")
    return errors


def load_registry(root: Path = ROOT) -> dict[str, Any]:
    registry = load_json(root / "schemas" / "versions.json")
    if not isinstance(registry, dict):
        raise SchemaContractError("schemas/versions.json: registry must be an object")
    return registry


def _walk_refs(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref":
                yield child
            else:
                yield from _walk_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_refs(child)


def validate_schema_documents(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    try:
        registry = load_registry(root)
    except SchemaContractError as exc:
        return [str(exc)]
    if registry.get("json_schema_dialect") != DIALECT:
        errors.append(f"schemas/versions.json: json_schema_dialect must be {DIALECT}")
    if not isinstance(registry.get("registry_version"), str) or not SEMVER.fullmatch(registry["registry_version"]):
        errors.append("schemas/versions.json: registry_version must be semantic versioning")
    entries = registry.get("schemas")
    if not isinstance(entries, dict):
        return errors + ["schemas/versions.json: schemas must be an object"]
    if set(entries) != EXPECTED_SCHEMA_KEYS:
        errors.append(f"schemas/versions.json: schema keys must be {sorted(EXPECTED_SCHEMA_KEYS)}")
    seen_ids: set[str] = set()
    for key, entry in entries.items():
        if not isinstance(entry, dict):
            errors.append(f"schemas/versions.json: entry {key} must be an object")
            continue
        version, schema_id, relative = entry.get("version"), entry.get("id"), entry.get("path")
        if not isinstance(version, str) or not SEMVER.fullmatch(version):
            errors.append(f"schemas/versions.json: {key} version must be semantic versioning")
        if not isinstance(schema_id, str) or not schema_id.startswith("urn:renguard:schema:"):
            errors.append(f"schemas/versions.json: {key} has invalid schema id")
        elif schema_id in seen_ids:
            errors.append(f"schemas/versions.json: duplicate schema id {schema_id}")
        elif isinstance(version, str) and not schema_id.endswith(f":{version}"):
            errors.append(f"schemas/versions.json: {key} schema id does not match version {version}")
        if isinstance(schema_id, str):
            seen_ids.add(schema_id)
        if not isinstance(relative, str):
            errors.append(f"schemas/versions.json: {key} path must be a string")
            continue
        path = (root / "schemas" / relative).resolve()
        if not _inside((root / "schemas").resolve(), path):
            errors.append(f"schemas/versions.json: {key} path escapes schemas directory")
            continue
        try:
            schema = load_json(path)
        except SchemaContractError as exc:
            errors.append(str(exc))
            continue
        if not isinstance(schema, dict):
            errors.append(f"{path}: schema must be an object")
            continue
        if schema.get("$schema") != DIALECT:
            errors.append(f"{path.relative_to(root)}: wrong JSON Schema dialect")
        if schema.get("$id") != schema_id:
            errors.append(f"{path.relative_to(root)}: $id does not match version registry")
        for ref in _walk_refs(schema):
            try:
                resolve_ref(ref, path, root / "schemas")
            except SchemaContractError as exc:
                errors.append(str(exc))
    current_artifact = registry.get("artifact_contract_version")
    if current_artifact != "0.1.0":
        errors.append("schemas/versions.json: artifact_contract_version must remain 0.1.0")
    return errors


def schema_for(key: str, root: Path = ROOT) -> tuple[dict[str, Any], Path]:
    registry = load_registry(root)
    try:
        relative = registry["schemas"][key]["path"]
    except (KeyError, TypeError) as exc:
        raise SchemaContractError(f"unknown schema key {key!r}") from exc
    path = (root / "schemas" / relative).resolve()
    if not _inside((root / "schemas").resolve(), path):
        raise SchemaContractError(f"schema path escapes repository schema root: {relative}")
    schema = load_json(path)
    if not isinstance(schema, dict):
        raise SchemaContractError(f"{path}: schema must be an object")
    return schema, path


def validate_value(value: Any, schema_key: str, root: Path = ROOT) -> list[str]:
    schema, path = schema_for(schema_key, root)
    return validate_instance(value, schema, current_schema=path)


def ensure_compatible_version(actual: Any, current: str, *, label: str) -> None:
    if not isinstance(actual, str) or not SEMVER.fullmatch(actual):
        raise SchemaContractError(f"{label}: version must be semantic versioning")
    actual_parts = tuple(int(item) for item in actual.split("."))
    current_parts = tuple(int(item) for item in current.split("."))
    if actual_parts[0] != current_parts[0]:
        raise SchemaContractError(f"{label}: unsupported major version {actual}; supported version is {current}")
    if current_parts[0] == 0 and actual_parts != current_parts:
        raise SchemaContractError(f"{label}: pre-1.0 artifact version {actual} is not explicitly supported; expected {current}")
    if actual_parts > current_parts:
        raise SchemaContractError(f"{label}: future schema version {actual} is not supported; current is {current}")


def _validate_or_prefix(value: Any, schema_key: str, label: str, root: Path) -> list[str]:
    return [f"{label}: {error}" for error in validate_value(value, schema_key, root)]


def validate_repository_contracts(root: Path = ROOT) -> tuple[list[str], dict[str, int]]:
    errors: list[str] = []
    json_files = [
        path for path in root.rglob("*.json")
        if ".git" not in path.relative_to(root).parts
    ]
    for path in json_files:
        try:
            load_json(path)
        except SchemaContractError as exc:
            errors.append(str(exc))
    errors.extend(validate_schema_documents(root))
    counts = {
        "schemas": len(EXPECTED_SCHEMA_KEYS),
        "scenarios": 0,
        "mutations": 0,
        "json_files": len(json_files),
    }
    try:
        manifest = load_json(root / "evals" / "v2" / "manifest.json")
        errors.extend(_validate_or_prefix(manifest, "eval.suite_manifest", "evals/v2/manifest.json", root))
        mutations = load_json(root / "evals" / "v2" / "mutations.json")
        errors.extend(_validate_or_prefix(mutations, "eval.mutations", "evals/v2/mutations.json", root))
        if isinstance(mutations, dict) and isinstance(mutations.get("mutation_recipes"), list):
            counts["mutations"] = len(mutations["mutation_recipes"])
        scenario_files = manifest.get("scenario_files", []) if isinstance(manifest, dict) else []
        for filename in scenario_files:
            if not isinstance(filename, str) or Path(filename).name != filename:
                errors.append(f"evals/v2/manifest.json: unsafe scenario filename {filename!r}")
                continue
            payload = load_json(root / "evals" / "v2" / filename)
            if not isinstance(payload, dict) or not isinstance(payload.get("scenarios"), list):
                errors.append(f"evals/v2/{filename}: expected an object containing scenarios array")
                continue
            for index, scenario in enumerate(payload["scenarios"]):
                errors.extend(_validate_or_prefix(scenario, "eval.scenario", f"evals/v2/{filename}.scenarios[{index}]", root))
                counts["scenarios"] += 1
    except SchemaContractError as exc:
        errors.append(str(exc))
    return errors, counts


def validate_run_directory(run_dir: Path, root: Path = ROOT) -> list[str]:
    run_dir = run_dir.resolve()
    if not run_dir.is_dir():
        return [f"{run_dir}: run directory does not exist"]
    registry = load_registry(root)
    current = registry["artifact_contract_version"]
    errors: list[str] = []
    try:
        manifest = load_json(run_dir / "run-manifest.json")
        ensure_compatible_version(manifest.get("artifact_schema_version"), current, label="run manifest artifact schema")
        errors.extend(_validate_or_prefix(manifest, "benchmark.run_manifest", "run-manifest.json", root))
        summary = load_json(run_dir / "summary.json")
        ensure_compatible_version(summary.get("schema_version"), current, label="summary artifact schema")
        errors.extend(_validate_or_prefix(summary, "benchmark.summary", "summary.json", root))
        for filename, key in (("responses.jsonl", "benchmark.response_record"), ("scores.jsonl", "benchmark.score_record")):
            path = run_dir / filename
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append(f"{filename}:{line_number}: invalid JSON: {exc}")
                    continue
                errors.extend(_validate_or_prefix(value, key, f"{filename}:{line_number}", root))
        review_path = run_dir / "review_queue.jsonl"
        if review_path.exists():
            for line_number, line in enumerate(review_path.read_text(encoding="utf-8").splitlines(), 1):
                value = json.loads(line)
                errors.extend(_validate_or_prefix(value, "benchmark.review_record", f"review_queue.jsonl:{line_number}", root))
    except (OSError, SchemaContractError, KeyError, TypeError, json.JSONDecodeError) as exc:
        errors.append(str(exc))
    return errors


def _print_result(errors: list[str], success: str) -> int:
    if errors:
        print("Schema validation FAILED", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(success)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check-repository", help="validate schemas and canonical repository JSON contracts")
    run = sub.add_parser("validate-run", help="validate a completed Phase 9 run directory")
    run.add_argument("run_dir", type=Path)
    item = sub.add_parser("validate-file", help="validate one JSON file against a registered schema")
    item.add_argument("schema_key", choices=sorted(EXPECTED_SCHEMA_KEYS))
    item.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    if args.command == "check-repository":
        errors, counts = validate_repository_contracts(ROOT)
        return _print_result(
            errors,
            (
                "Schema/JSON validation PASSED "
                f"({counts['json_files']} JSON files, {counts['schemas']} schemas, "
                f"{counts['scenarios']} scenarios, {counts['mutations']} mutations)"
            ),
        )
    if args.command == "validate-run":
        return _print_result(validate_run_directory(args.run_dir, ROOT), "Benchmark run schema validation PASSED")
    value = load_json(args.path)
    return _print_result(validate_value(value, args.schema_key, ROOT), f"{args.path}: schema validation PASSED")


if __name__ == "__main__":
    raise SystemExit(main())
