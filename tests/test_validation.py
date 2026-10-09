from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.validate_repo import validate_repository


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


if __name__ == "__main__":
    unittest.main()
