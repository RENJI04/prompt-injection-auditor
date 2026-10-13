"""Dependency-free statistical helpers with explicit denominators."""

from __future__ import annotations

import math
from typing import Iterable


WILSON_Z_95 = 1.959963984540054


def safe_ratio(numerator: int | float, denominator: int | float) -> float | None:
    return None if denominator == 0 else numerator / denominator


def wilson_interval(successes: int, total: int, z: float = WILSON_Z_95) -> dict[str, float | int | None]:
    if total < 0 or successes < 0 or successes > total:
        raise ValueError("Wilson inputs must satisfy 0 <= successes <= total")
    if total == 0:
        return {"successes": successes, "total": total, "confidence": 0.95, "low": None, "high": None}
    proportion = successes / total
    denominator = 1 + z * z / total
    center = (proportion + z * z / (2 * total)) / denominator
    spread = z * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total)) / denominator
    return {"successes": successes, "total": total, "confidence": 0.95, "low": max(0.0, center - spread), "high": min(1.0, center + spread)}


def percentile(values: Iterable[float], fraction: float) -> float | None:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return None
    if not 0 <= fraction <= 1:
        raise ValueError("percentile fraction must be from zero through one")
    position = fraction * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def latency_summary(values: Iterable[float]) -> dict[str, float | int | None]:
    samples = list(values)
    return {
        "count": len(samples), "min": min(samples) if samples else None,
        "median": percentile(samples, 0.5), "p50": percentile(samples, 0.5),
        "p95": percentile(samples, 0.95), "max": max(samples) if samples else None,
        "percentile_method": "linear interpolation over sorted observations",
    }


def stability_label(passes: int, failures: int, unresolved: int) -> str:
    resolved = passes + failures
    if resolved == 0:
        return "UNRESOLVED"
    proportion = passes / resolved
    if unresolved == 0 and proportion == 1:
        return "STABLE_PASS"
    if unresolved == 0 and proportion == 0:
        return "STABLE_FAIL"
    if proportion >= 0.8:
        return "MOSTLY_PASS"
    if proportion <= 0.2:
        return "MOSTLY_FAIL"
    return "UNSTABLE"
