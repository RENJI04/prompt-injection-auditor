#!/usr/bin/env python3
"""Run RenGuard's deterministic, model-offline repository quality gates."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATES = ("repository", "tests", "compile", "schemas", "smoke")


def run(command: list[str], *, env: dict[str, str]) -> None:
    subprocess.run(command, cwd=ROOT, env=env, check=True, shell=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=GATES, help="run one gate (useful for focused development)")
    args = parser.parse_args(argv)
    selected = (args.only,) if args.only else GATES
    with tempfile.TemporaryDirectory(prefix="renguard-quality-") as temporary:
        temporary_root = Path(temporary)
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONPYCACHEPREFIX"] = str(temporary_root / "pycache")
        commands = {
            "repository": [sys.executable, "scripts/validate_repo.py"],
            "tests": [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            "compile": [sys.executable, "-m", "compileall", "-q", "scripts", "tests"],
            "schemas": [sys.executable, "scripts/schema_tools.py", "check-repository"],
        }
        labels = {
            "repository": "Repository validation and diff hygiene",
            "tests": "Unit tests",
            "compile": "Compile",
            "schemas": "Schema and JSON validation",
            "smoke": "Offline benchmark smoke",
        }
        for gate in selected:
            index = GATES.index(gate) + 1
            print(f"[{index}/5] {labels[gate]}", flush=True)
            if gate != "smoke":
                run(commands[gate], env=env)
                if gate == "repository":
                    run(["git", "diff", "--check"], env=env)
                continue
            output = temporary_root / "benchmark-runs"
            run([
                sys.executable, "scripts/run_benchmark.py", "run",
                "--adapter", "fixture", "--fixture-profile", "perfect",
                "--condition", "BOTH", "--runs", "2",
                "--ids", "RG-EVAL-V2-001,RG-EVAL-V2-061",
                "--output-dir", str(output), "--run-id", "quality-gate-smoke",
            ], env=env)
            run([sys.executable, "scripts/schema_tools.py", "validate-run", str(output / "quality-gate-smoke")], env=env)
    print("Repository quality gate PASSED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"quality gate failed with exit code {exc.returncode}: {exc.cmd}", file=sys.stderr)
        raise SystemExit(exc.returncode or 1)
