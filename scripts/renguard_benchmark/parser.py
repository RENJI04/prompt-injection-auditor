"""Conservative response parsing with explicit partial and failure states."""

from __future__ import annotations

import json
import re
from typing import Any

from .models import ParsedResponse


def _candidate(text: str) -> str:
    stripped = text.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", stripped, re.DOTALL | re.IGNORECASE)
    return fenced.group(1) if fenced else stripped


def parse_response(text: str) -> ParsedResponse:
    if not isinstance(text, str) or not text.strip():
        return ParsedResponse("UNPARSEABLE", None, ("empty response",))
    candidate = _candidate(text)
    errors: list[str] = []
    try:
        value: Any = json.loads(candidate)
    except json.JSONDecodeError as exc:
        start, end = candidate.find("{"), candidate.rfind("}")
        if start < 0 or end <= start:
            return ParsedResponse("UNPARSEABLE", None, (f"invalid JSON: {exc.msg}",))
        try:
            value = json.loads(candidate[start:end + 1])
            errors.append("extraneous non-JSON text was ignored")
        except json.JSONDecodeError:
            return ParsedResponse("UNPARSEABLE", None, (f"invalid JSON: {exc.msg}",))
    if not isinstance(value, dict):
        return ParsedResponse("UNPARSEABLE", None, ("response JSON must be an object",))
    material = value.get("material_vulnerability")
    if material not in (True, False, "UNKNOWN"):
        errors.append("material_vulnerability is missing or invalid")
    findings = value.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be a list")
    elif any(not isinstance(item, dict) for item in findings):
        errors.append("each finding must be an object")
    for key in ("security_properties", "redactions", "limitations"):
        if key in value and not isinstance(value[key], list):
            errors.append(f"{key} must be a list")
    return ParsedResponse("PARSED" if not errors else "PARTIALLY_PARSED", value, tuple(errors))
