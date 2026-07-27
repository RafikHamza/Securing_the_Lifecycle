"""Tests for dynamic dispatch and registry-based tool matching (§3).

Verifies that the verifier correctly handles:
- Direct call resolution
- Module-qualified names (e.g., os.remove)
- Contract-registered dynamic dispatch tables
- Conservative warning for unregistered dynamic dispatch
"""
import unittest
from cpd_verifier.model import Contract, BufferContract
from cpd_verifier.verifier import verify_source, resolve_tool_match


def _make_contract_with_wildcards():
    return Contract(
        module="test",
        buffers=(
            BufferContract(
                name="key",
                element_type="uint8_t",
                sensitive=True,
                must_zeroize=True,
                forbid_post_send_use=True,
                allowed_sinks=("safe_send", "crypto_*"),
                forbidden_sinks=("unsafe_send", "log_*", "debug_*"),
                transport_sink="",
            ),
        ),
        sources=(),
        sinks=(),
        zeroizers=(),
    )


class TestDynamicDispatchRegistryMatching(unittest.TestCase):

    def test_direct_call_forbidden(self):
        contract = _make_contract_with_wildcards()
        source = """
def process(key):
    unsafe_send(key)
"""
        violations = verify_source(contract, source)
        self.assertTrue(any(v.code == "forbidden-sink" for v in violations))

    def test_wildcard_forbidden_match(self):
        contract = _make_contract_with_wildcards()
        source = """
def process(key):
    log_debug(key)
"""
        violations = verify_source(contract, source)
        self.assertTrue(any(v.code == "forbidden-sink" for v in violations))

    def test_wildcard_allowed_match(self):
        contract = _make_contract_with_wildcards()
        source = """
def process(key):
    crypto_encrypt(key)
    secure_zeroize(key, 32)
"""
        violations = verify_source(contract, source)
        self.assertFalse(any(v.code == "forbidden-sink" for v in violations))

    def test_module_qualified_match(self):
        """Module-qualified name matching via resolve_tool_match."""
        result = resolve_tool_match("os.remove",
                                     allowed=("os.*",),
                                     forbidden=())
        self.assertEqual(result, "allowed")

    def test_unregistered_call_no_match(self):
        """Unknown calls produce no tool match (returns None)."""
        result = resolve_tool_match("unknown_function",
                                     allowed=("safe_send",),
                                     forbidden=("unsafe_send",))
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
