"""Tests for the C++ verifier's handling of templates and macros (§4).

Verifies that:
- Templates (CLASS_TEMPLATE, FUNCTION_TEMPLATE) are explicitly out-of-scope.
- Plain functions and structs are correctly analyzed.
- The verifier gracefully handles libclang unavailability.
"""
import unittest
from unittest.mock import patch
from cpd_verifier.model import Contract, BufferContract
from cpd_verifier.cpp_verifier import (
    verify_cpp_source, LIBCLANG_AVAILABLE, CppViolation,
)


def _make_contract():
    return Contract(
        module="test",
        buffers=(
            BufferContract(
                name="key",
                element_type="uint8_t",
                sensitive=True,
                must_zeroize=True,
                forbid_post_send_use=True,
                allowed_sinks=("send_encrypted",),
                forbidden_sinks=("printf", "log_debug"),
                transport_sink="",
            ),
        ),
        sources=(),
        sinks=(),
        zeroizers=(),
    )


@unittest.skipUnless(LIBCLANG_AVAILABLE, "libclang not installed")
class TestLibclangMacroTemplateExclusion(unittest.TestCase):

    def test_plain_function_is_analyzed(self):
        """Plain C function should be analyzed."""
        contract = _make_contract()
        source = """
void process_key(unsigned char *key, int len) {
    printf(key);
}
"""
        violations = verify_cpp_source(contract, source)
        self.assertTrue(any(v.code == "forbidden-sink" for v in violations))

    def test_template_function_is_skipped(self):
        """C++ function templates are out-of-scope and should be skipped."""
        contract = _make_contract()
        source = """
template<typename T>
void process(T* key, int len) {
    printf(key);
}
"""
        violations = verify_cpp_source(contract, source, filename="test.cpp")
        # Template functions are out-of-scope: no violations should be reported
        self.assertFalse(any(v.code == "forbidden-sink" for v in violations))

    def test_struct_function_is_analyzed(self):
        """Functions inside structs (typical ESP-IDF pattern) should be analyzed."""
        contract = _make_contract()
        source = """
struct handler {
    int status;
};

void handle_key(unsigned char *key, int len) {
    printf(key);
}
"""
        violations = verify_cpp_source(contract, source)
        self.assertTrue(any(v.code == "forbidden-sink" for v in violations))

    def test_missing_zeroize_at_function_end(self):
        """Detect missing zeroization at function scope exit."""
        contract = _make_contract()
        source = """
void process_key(unsigned char *key, int len) {
    send_encrypted(key, len);
}
"""
        violations = verify_cpp_source(contract, source)
        self.assertTrue(any(v.code == "missing-zeroize" for v in violations))

    def test_proper_zeroize_no_violation(self):
        """No violation when zeroization is performed after use."""
        contract = _make_contract()
        source = """
typedef unsigned long size_t;
void *memset(void *s, int c, size_t n);
void process_key(unsigned char *key, int len) {
    send_encrypted(key, len);
    memset(key, 0, len);
}
"""
        violations = verify_cpp_source(contract, source, filename="test.cpp")
        self.assertFalse(any(v.code == "missing-zeroize" for v in violations))


class TestLibclangUnavailable(unittest.TestCase):
    """Verify graceful degradation when libclang is not installed."""

    def test_returns_empty_when_unavailable(self):
        """When LIBCLANG_AVAILABLE is False, should return empty list."""
        contract = _make_contract()
        with patch('cpd_verifier.cpp_verifier.LIBCLANG_AVAILABLE', False):
            violations = verify_cpp_source(contract, "void f() {}")
            self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
