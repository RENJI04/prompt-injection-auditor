from __future__ import annotations

import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BRANDING = ROOT / "assets/branding"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
EXPECTED_ASSETS = {
    "renguard-icon.png": (1254, 1254),
    "renguard-wordmark.png": (2172, 724),
    "renguard-social-preview.png": (1774, 887),
}


def read_png_dimensions(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    if data[:8] != PNG_SIGNATURE:
        raise AssertionError(f"{path.relative_to(ROOT)} has an invalid PNG signature")
    if data[12:16] != b"IHDR":
        raise AssertionError(f"{path.relative_to(ROOT)} has no leading IHDR chunk")
    return struct.unpack(">II", data[16:24])


class BrandingTests(unittest.TestCase):
    def test_approved_png_assets_are_valid_and_have_expected_dimensions(self) -> None:
        for name, dimensions in EXPECTED_ASSETS.items():
            path = BRANDING / name
            self.assertTrue(path.is_file(), path.relative_to(ROOT))
            self.assertGreater(path.stat().st_size, 0, path.relative_to(ROOT))
            self.assertEqual(dimensions, read_png_dimensions(path), path.relative_to(ROOT))

    def test_readme_uses_accessible_local_social_preview_hero(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn('src="assets/branding/renguard-social-preview.png"', readme)
        self.assertIn('alt="RenGuard — Model-Agnostic Security for AI Systems &amp; Agents"', readme)
        self.assertNotIn("http", readme.split("</p>", 1)[0].lower())
        self.assertEqual(1, readme.count("actions/workflows/ci.yml/badge.svg?branch=main"))
        self.assertIn("actions/workflows/ci.yml?query=branch%3Amain", readme)

    def test_readme_keeps_project_identity_as_live_text(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("# RenGuard", readme)
        self.assertIn("Model-Agnostic Security for AI Systems & Agents", readme)
        self.assertIn("RenGuard is a model-agnostic security auditing Skill and framework", readme)

    def test_branding_readme_documents_assets_and_accessibility(self) -> None:
        branding_readme = (BRANDING / "README.md").read_text(encoding="utf-8")
        for name in EXPECTED_ASSETS:
            self.assertIn(name, branding_readme)
        self.assertIn("RenGuard", branding_readme)
        self.assertIn("Model-Agnostic Security for AI Systems & Agents", branding_readme)
        self.assertIn("alt text", branding_readme.lower())
        self.assertNotIn("registered trademark", branding_readme.lower())

    def test_github_publishing_guide_records_completed_manual_gates(self) -> None:
        guide = (ROOT / "release/GITHUB_PUBLISHING.md").read_text(encoding="utf-8")
        self.assertIn("RENJI04/prompt-injection-auditor", guide)
        self.assertIn("assets/branding/renguard-social-preview.png", guide)
        self.assertIn("MANUALLY_CONFIGURED", guide)
        self.assertIn("v2.0.0", guide)
        self.assertIn("RELEASE_NOTES.md", guide)
        self.assertIn("optional", guide.lower())
        self.assertIn("renguard", guide.lower())
        for gate in (
            "GitHub About description applied",
            "Repository topics applied",
            "Social Preview configured and crop verified",
            "Final metadata change reviewed/merged",
            "`v2.0.0` annotated tag created",
            "GitHub Release published",
        ):
            self.assertIn(f"- [x] {gate}", guide)
        self.assertIn("- [x] Main Python 3.10–3.13 matrix passes", guide)

    def test_release_checklist_tracks_branding_and_github_presentation(self) -> None:
        checklist = (ROOT / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
        self.assertIn("## Branding assets", checklist)
        self.assertIn("## GitHub presentation", checklist)
        self.assertIn("About description prepared | PREPARED", checklist)
        self.assertIn("Repository topics prepared | PREPARED", checklist)
        self.assertIn("Social Preview asset prepared | PREPARED", checklist)
        self.assertIn("Social Preview configuration | MANUALLY_CONFIGURED", checklist)
        self.assertIn("Main hosted CI | PASS", checklist)

    def test_branding_docs_record_publication_without_performance_claims(self) -> None:
        corpus = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                ROOT / "README.md",
                ROOT / "RELEASE_NOTES.md",
                ROOT / "RELEASE_CHECKLIST.md",
                ROOT / "release/GITHUB_PUBLISHING.md",
                BRANDING / "README.md",
            )
            if path.exists()
        ).lower()
        for forbidden in (
            "official v2 performance percentage",
            "production-ready",
        ):
            self.assertNotIn(forbidden, corpus)
        self.assertIn("releases/tag/v2.0.0", corpus)


if __name__ == "__main__":
    unittest.main()
