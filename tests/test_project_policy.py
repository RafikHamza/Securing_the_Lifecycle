from __future__ import annotations

import re
import unittest
from pathlib import Path


class ProjectPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[1]

    def test_runtime_sources_do_not_contain_placeholder_markers(self) -> None:
        banned_patterns = {
            r"\bTODO\b": "TODO",
            r"\bFIXME\b": "FIXME",
            r"\bplaceholder\b": "placeholder",
            r"\bstub\b": "stub",
            r"\bmock\b": "mock",
            r"\bdummy\b": "dummy",
            r"\brolling_xor\b": "rolling_xor",
            r"\bbyte_reverse\b": "byte_reverse",
            r"\btransport_callback\b": "transport_callback",
        }
        scan_paths = list((self.repo_root / "cpd_verifier").rglob("*.py"))
        scan_paths.extend((self.repo_root / "examples").rglob("*.json"))
        scan_paths.extend((self.repo_root / "examples").rglob("*.c"))

        violations: list[str] = []
        for path in scan_paths:
            text = path.read_text(encoding="utf-8")
            relative_path = path.relative_to(self.repo_root).as_posix()
            for pattern, label in banned_patterns.items():
                if re.search(pattern, text, re.IGNORECASE):
                    violations.append(f"{relative_path}: {label}")

        self.assertEqual(violations, [])