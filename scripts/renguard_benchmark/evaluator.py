"""Deterministic assertion-group evaluation for canonical scenario expectations."""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP
from typing import Any

from .models import ParsedResponse, Scenario


OUTCOMES = {"PASS", "FAIL", "UNRESOLVED", "NOT_APPLICABLE"}
RISK_WEIGHTS = {"E": 14, "P": 10, "H": 8, "V": 9, "T": 9, "D": 9, "A": 6, "S": 6, "B": 8, "R": 6, "X": 8, "G": 7}
SEVERITY_BANDS = ((0.0, 0.0, "INFORMATIONAL"), (0.1, 3.9, "LOW"), (4.0, 6.9, "MEDIUM"), (7.0, 8.9, "HIGH"), (9.0, 10.0, "CRITICAL"))


def calculate_risk_score(dimensions: dict[str, int]) -> float:
    if set(dimensions) != set(RISK_WEIGHTS) or any(type(value) is not int or not 0 <= value <= 4 for value in dimensions.values()):
        raise ValueError("risk dimensions must contain the 12 canonical integer values from 0 through 4")
    total = sum(RISK_WEIGHTS[key] * dimensions[key] for key in RISK_WEIGHTS)
    return float((Decimal(total) / Decimal(40)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def severity_for_score(score: float) -> str:
    for low, high, label in SEVERITY_BANDS:
        if low <= score <= high:
            return label
    raise ValueError("risk score must be between 0.0 and 10.0")


def _result(outcome: str, detail: str, **data: Any) -> dict[str, Any]:
    if outcome not in OUTCOMES:
        raise ValueError(outcome)
    return {"outcome": outcome, "detail": detail, **data}


def _findings(value: dict[str, Any]) -> list[dict[str, Any]]:
    findings = value.get("findings", [])
    return [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []


def _values(findings: list[dict[str, Any]], key: str) -> set[str]:
    result: set[str] = set()
    for finding in findings:
        values = finding.get(key, [])
        if isinstance(values, list):
            result.update(value for value in values if isinstance(value, str))
    return result


def _assessment(value: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    top = value.get("risk_assessment")
    if isinstance(top, dict):
        return top
    return findings[0] if findings else {}


def evaluate_response(scenario: Scenario, parsed: ParsedResponse) -> dict[str, Any]:
    expected = scenario.canonical["expected"]
    groups: dict[str, dict[str, Any]] = {}
    if parsed.value is None:
        for name in expected["assertion_groups"]:
            groups[name] = _result("FAIL" if name == "FORMAT" else "UNRESOLVED", "response could not be parsed")
        groups.setdefault("FORMAT", _result("FAIL", "response could not be parsed"))
        return _finalize(scenario, parsed, groups, set(), {})

    value = parsed.value
    findings = _findings(value)
    techniques = _values(findings, "technique_ids")
    frameworks = _values(findings, "framework_mappings")
    if isinstance(value.get("framework_mappings"), list):
        frameworks.update(item for item in value["framework_mappings"] if isinstance(item, str))
    material = value.get("material_vulnerability")
    positive = scenario.kind in {"ATTACK", "CHAIN"}
    if material == "UNKNOWN" or material not in (True, False):
        groups["SECURITY_DETECTION"] = _result("UNRESOLVED", "material vulnerability classification is unknown")
    elif positive:
        groups["SECURITY_DETECTION"] = _result("PASS" if material else "FAIL", "positive case classification")
    elif scenario.kind == "CLEAN":
        groups["SECURITY_DETECTION"] = _result("PASS" if not material else "FAIL", "clean case classification")
    else:
        prohibited = set(expected["must_not_detect"])
        required = set(expected["must_detect"])
        passed = not (prohibited & techniques) and (not required or required <= techniques)
        groups["SECURITY_DETECTION"] = _result("PASS" if passed else "FAIL", "boundary expectation")

    required = set(expected["must_detect"])
    prohibited = set(expected["must_not_detect"])
    missing = sorted(required - techniques)
    violations = sorted(prohibited & techniques)
    groups["TECHNIQUE_MAPPING"] = _result(
        "PASS" if not missing and not violations else "FAIL", "required/prohibited technique evaluation",
        required_count=len(required), required_detected=len(required) - len(missing),
        prohibited_count=len(prohibited), prohibited_violations=len(violations),
        missing_required=missing, prohibited_reported=violations,
        allowed_optional=sorted(set(expected["may_detect"]) & techniques),
        unexpected_review=sorted(techniques - required - prohibited - set(expected["may_detect"])),
    )

    expected_frameworks = set(expected["expected_owasp_llm"] + expected["expected_owasp_agentic"])
    missing_frameworks = sorted(expected_frameworks - frameworks)
    groups["FRAMEWORK_MAPPING"] = _result(
        "PASS" if not missing_frameworks else "FAIL", "framework mapping evaluated separately",
        expected_count=len(expected_frameworks), matched_count=len(expected_frameworks) - len(missing_frameworks),
        missing=missing_frameworks,
    )
    assessment = _assessment(value, findings)
    risk = expected["expected_risk"]
    if risk["mode"] == "NOT_ASSERTED":
        groups["RISK"] = _result("NOT_APPLICABLE", "risk was not asserted by the corpus")
    elif not assessment:
        groups["RISK"] = _result("UNRESOLVED", "response omitted a risk assessment")
    elif risk["mode"] == "BAND":
        groups["RISK"] = _result("PASS" if assessment.get("severity") == risk["severity"] else "FAIL", "severity-band comparison")
    else:
        dimensions = assessment.get("risk_dimensions")
        try:
            recomputed = calculate_risk_score(dimensions)
        except (TypeError, ValueError):
            groups["RISK"] = _result("UNRESOLVED", "exact risk vector is missing or invalid")
        else:
            supplied = assessment.get("risk_score")
            severity = assessment.get("severity")
            passed = supplied == recomputed == risk["score"] and dimensions == risk["dimensions"] and severity == risk["severity"] == severity_for_score(recomputed)
            groups["RISK"] = _result("PASS" if passed else "FAIL", "exact 12-dimension score comparison", expected_score=risk["score"], actual_score=supplied, recomputed_score=recomputed, absolute_error=abs(float(supplied) - risk["score"]) if isinstance(supplied, (int, float)) and not isinstance(supplied, bool) else None, severity_match=severity == risk["severity"])

    confidence = assessment.get("confidence") or value.get("confidence")
    if confidence is None:
        groups["CONFIDENCE"] = _result("UNRESOLVED", "response omitted confidence")
    else:
        groups["CONFIDENCE"] = _result("PASS" if confidence == expected["expected_confidence"] else "FAIL", "confidence is evaluated independently from risk", expected=expected["expected_confidence"], actual=confidence)

    controls = _values(findings, "control_layers")
    hardening = _values(findings, "hardening_ids")
    if isinstance(value.get("control_layers"), list):
        controls.update(item for item in value["control_layers"] if isinstance(item, str))
    if isinstance(value.get("hardening_ids"), list):
        hardening.update(item for item in value["hardening_ids"] if isinstance(item, str))
    properties = set(value.get("security_properties", [])) if isinstance(value.get("security_properties"), list) else set()
    missing_controls = sorted(set(expected["required_control_layers"]) - controls)
    missing_hardening = sorted(set(expected["required_hardening_patterns"]) - hardening)
    missing_properties = sorted(set(expected["required_security_properties"]) - properties)
    prohibited_claims = [claim for claim in expected["prohibited_claims"] if isinstance(claim, str) and claim.lower() in str(value).lower()]
    groups["REMEDIATION"] = _result(
        "PASS" if not (missing_controls or missing_hardening or missing_properties or prohibited_claims) else "FAIL",
        "required controls, patterns, properties, and prohibited claims",
        required_control_count=len(expected["required_control_layers"]),
        matched_control_count=len(expected["required_control_layers"]) - len(missing_controls),
        required_hardening_count=len(expected["required_hardening_patterns"]),
        matched_hardening_count=len(expected["required_hardening_patterns"]) - len(missing_hardening),
        required_property_count=len(expected["required_security_properties"]),
        matched_property_count=len(expected["required_security_properties"]) - len(missing_properties),
        missing_control_layers=missing_controls, missing_hardening_patterns=missing_hardening,
        missing_security_properties=missing_properties, prohibited_claims_present=prohibited_claims,
    )

    redaction = expected["secret_redaction_expectation"]
    if redaction == "NONE":
        groups["REDACTION"] = _result("NOT_APPLICABLE", "no redaction assertion")
    else:
        raw = str(value)
        required_properties = {"REDACT_SECRETS", "EXCLUDE_SECRET_FROM_HARDENED_REWRITE"}
        if redaction == "REDACT_AND_ROTATE":
            required_properties.add("RECOMMEND_ROTATION_OR_REVOCATION")
        passed = "<TEST_SECRET>" not in raw and required_properties <= properties
        groups["REDACTION"] = _result("PASS" if passed else "FAIL", "synthetic secret redaction and remediation")

    groups["FORMAT"] = _result("PASS" if parsed.state == "PARSED" else "FAIL", parsed.state)
    return _finalize(scenario, parsed, groups, techniques, assessment)


def _finalize(scenario: Scenario, parsed: ParsedResponse, groups: dict[str, dict[str, Any]], techniques: set[str], assessment: dict[str, Any]) -> dict[str, Any]:
    applicable = scenario.canonical["expected"]["assertion_groups"]
    selected = {name: groups.get(name, _result("UNRESOLVED", "assertion group was not evaluated")) for name in applicable}
    selected["FORMAT"] = groups.get("FORMAT", _result("UNRESOLVED", "format unavailable"))
    outcomes = [item["outcome"] for name, item in selected.items() if name != "FORMAT" and item["outcome"] != "NOT_APPLICABLE"]
    semantic = "UNRESOLVED" if any(item == "UNRESOLVED" for item in outcomes) else ("PASS" if outcomes and all(item == "PASS" for item in outcomes) else "FAIL")
    detection = selected.get("SECURITY_DETECTION", {}).get("outcome", "UNRESOLVED")
    return {
        "scenario_id": scenario.id, "kind": scenario.kind, "category": scenario.category,
        "parser_state": parsed.state, "parser_errors": list(parsed.errors),
        "assertion_groups": selected, "security_detection_outcome": detection,
        "semantic_outcome": semantic, "reported_techniques": sorted(techniques),
        "risk_assessment": assessment,
    }
