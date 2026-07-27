"""Tests for wildcard tool matching precedence (§3).

Verifies:
- Exact match beats wildcard.
- forbidden patterns override allowed patterns on conflict.
- Glob patterns (e.g., 'requests.*') work correctly.
"""
import unittest
from cpd_verifier.verifier import resolve_tool_match, matches_tool_pattern


class TestMatchesToolPattern(unittest.TestCase):

    def test_exact_match(self):
        self.assertTrue(matches_tool_pattern("safe_send", ("safe_send",)))

    def test_exact_no_match(self):
        self.assertFalse(matches_tool_pattern("other", ("safe_send",)))

    def test_wildcard_match(self):
        self.assertTrue(matches_tool_pattern("requests_get", ("requests_*",)))

    def test_wildcard_no_match(self):
        self.assertFalse(matches_tool_pattern("urllib_get", ("requests_*",)))

    def test_glob_dot_star(self):
        """Pattern 'requests.*' should match 'requests.get'."""
        self.assertTrue(matches_tool_pattern("requests.get", ("requests.*",)))

    def test_question_mark_wildcard(self):
        self.assertTrue(matches_tool_pattern("log_a", ("log_?",)))
        self.assertFalse(matches_tool_pattern("log_ab", ("log_?",)))


class TestResolveToolMatch(unittest.TestCase):

    def test_exact_forbidden_beats_wildcard_allowed(self):
        result = resolve_tool_match("log", allowed=("log_*",), forbidden=("log",))
        self.assertEqual(result, "forbidden")

    def test_exact_allowed_when_no_forbidden(self):
        result = resolve_tool_match("safe_send", allowed=("safe_send",), forbidden=())
        self.assertEqual(result, "allowed")

    def test_wildcard_forbidden_overrides_wildcard_allowed(self):
        result = resolve_tool_match("debug_log",
                                     allowed=("debug_*",),
                                     forbidden=("debug_*",))
        self.assertEqual(result, "forbidden")

    def test_no_match_returns_none(self):
        result = resolve_tool_match("unknown", allowed=("safe_send",), forbidden=("log",))
        self.assertIsNone(result)

    def test_exact_forbidden_beats_exact_allowed(self):
        # If a name appears in both (shouldn't per schema), forbidden wins
        result = resolve_tool_match("dual", allowed=("dual",), forbidden=("dual",))
        self.assertEqual(result, "forbidden")

    def test_wildcard_allowed_only(self):
        result = resolve_tool_match("api_call",
                                     allowed=("api_*",),
                                     forbidden=())
        self.assertEqual(result, "allowed")


if __name__ == "__main__":
    unittest.main()
