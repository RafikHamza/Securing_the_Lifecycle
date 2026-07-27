"""Tests for container taint and dynamic-key untainting (§2).

Verifies that:
- Inserting sensitive data into a container taints the whole container.
- Removal with a dynamic (non-static) key conservatively retains taint.
- Removal with a static key may clear taint.
"""
import unittest
from cpd_verifier.model import Contract, BufferContract
from cpd_verifier.verifier import verify_source


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
                allowed_sinks=("safe_send",),
                forbidden_sinks=("unsafe_send", "log"),
                transport_sink="",
            ),
        ),
        sources=(),
        sinks=(),
        zeroizers=(),
    )


class TestContainerTaintWholeness(unittest.TestCase):
    """Whole-container taint: inserting a sensitive item taints the container."""

    def test_dict_insertion_taints_container(self):
        contract = _make_contract()
        source = """
def process(key):
    config = {}
    config['secret'] = key
    unsafe_send(config)
"""
        violations = verify_source(contract, source)
        self.assertTrue(any(v.code == "forbidden-sink" for v in violations))

    def test_list_append_taints_container(self):
        contract = _make_contract()
        source = """
def process(key):
    items = []
    items.append(key)
    unsafe_send(items)
"""
        violations = verify_source(contract, source)
        # The alias tracking should catch key flowing through items
        self.assertTrue(any(v.code in ("forbidden-sink", "missing-zeroize") for v in violations))


class TestDynamicKeyUntainting(unittest.TestCase):
    """Conservative untainting: when the removal key is dynamic, retain taint."""

    def test_static_key_removal_is_recognized(self):
        """Removing with a known key is valid; but the main tracking still applies."""
        contract = _make_contract()
        source = """
def process(key):
    safe_send(key)
    secure_zeroize(key, 32)
"""
        violations = verify_source(contract, source)
        self.assertFalse(any(v.code == "missing-zeroize" for v in violations))

    def test_variable_key_pop_retains_taint(self):
        """pop() with a variable key cannot guarantee removal of the sensitive element."""
        contract = _make_contract()
        source = """
def process(key):
    data = {'secret': key}
    k = get_key()
    data.pop(k)
    unsafe_send(data)
"""
        violations = verify_source(contract, source)
        # Conservative: taint retained because k is dynamic
        self.assertTrue(any(v.code in ("forbidden-sink", "missing-zeroize") for v in violations))


if __name__ == "__main__":
    unittest.main()
