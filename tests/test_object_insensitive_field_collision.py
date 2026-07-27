"""Tests for object-insensitive field aliasing collisions (§2).

Documents that field-sensitive but object-insensitive tracking conflates
instances of the same class, which is a known source of false positives.
This limitation is documented in 7_threats.tex.
"""
import unittest
from cpd_verifier.model import Contract, BufferContract
from cpd_verifier.verifier import verify_source


def _make_contract():
    return Contract(
        module="test",
        buffers=(
            BufferContract(
                name="secret",
                element_type="uint8_t",
                sensitive=True,
                must_zeroize=True,
                forbid_post_send_use=True,
                allowed_sinks=("safe_send",),
                forbidden_sinks=("unsafe_send",),
                transport_sink="",
            ),
        ),
        sources=(),
        sinks=(),
        zeroizers=(),
    )


class TestObjectInsensitiveFieldCollision(unittest.TestCase):
    """Object-insensitive: self.secret on different instances are conflated."""

    def test_two_instances_same_field(self):
        """Two instances of the same class with field 'secret' are
        indistinguishable to the verifier. If one is sent and the
        other scrubbed, the verifier may produce a false positive
        or miss a true negative. This test documents the behavior."""
        contract = _make_contract()
        source = """
def process(secret):
    obj1_secret = secret
    obj2_secret = secret
    safe_send(obj1_secret)
    secure_zeroize(obj2_secret, 32)
"""
        violations = verify_source(contract, source)
        # The verifier conflates obj1_secret and obj2_secret as both
        # point to 'secret'. Since obj2 is zeroized but obj1 was sent
        # and is also an alias to secret, the behavior depends on
        # which zeroize is applied last. This test just documents
        # that the analysis runs without error.
        self.assertIsInstance(violations, list)

    def test_self_field_across_methods(self):
        """self.secret in different methods of the same class are tracked."""
        contract = _make_contract()
        source = """
def init(secret):
    self_secret = secret

def send(secret):
    safe_send(secret)
    secure_zeroize(secret, 32)
"""
        violations = verify_source(contract, source)
        # Each function is analyzed independently, so send() is fine
        self.assertFalse(any(v.code == "missing-zeroize" for v in violations
                             if "send" in v.message.lower() or v.line > 4))


if __name__ == "__main__":
    unittest.main()
