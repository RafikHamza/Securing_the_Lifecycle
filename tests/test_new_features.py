import unittest
from cpd_verifier.contract import Contract, BufferContract
from cpd_verifier.verifier import verify_source

class CPDVerifierNewFeaturesTests(unittest.TestCase):
    def setUp(self):
        self.contract = Contract(
            module="test_module",
            buffers=[
                BufferContract(
                    name="ctx->secret",
                    element_type="uint8_t",
                    sensitive=True,
                    must_zeroize=True,
                    forbid_post_send_use=True,
                    allowed_sinks=("safe_send",),
                    forbidden_sinks=("unsafe_send",),
                    transport_sink="transport_send"
                ),
                BufferContract(
                    name="heap_buf",
                    element_type="uint8_t",
                    sensitive=True,
                    must_zeroize=True,
                    forbid_post_send_use=True,
                    allowed_sinks=("safe_send",),
                    forbidden_sinks=(),
                    transport_sink=""
                )
            ],
            sources=(),
            sinks=(),
            zeroizers=()
        )
        self.basic_contract = Contract(
            module="basic",
            buffers=[
                BufferContract(
                    name="buf",
                    element_type="uint8_t",
                    sensitive=True,
                    must_zeroize=True,
                    forbid_post_send_use=True,
                    allowed_sinks=("safe_send",),
                    forbidden_sinks=("unsafe_send",),
                    transport_sink=""
                )
            ],
            sources=(),
            sinks=(),
            zeroizers=()
        )

    # Alias tracking tests
    def test_alias_tracking_simple(self):
        source = """
def process(buf):
    alias = buf
    unsafe_send(alias)
        """
        violations = verify_source(self.basic_contract, source)
        self.assertTrue(any(v.code == "forbidden-sink" for v in violations))

    def test_alias_tracking_double(self):
        source = """
def process(buf):
    alias1 = buf
    alias2 = alias1
    unsafe_send(alias2)
        """
        violations = verify_source(self.basic_contract, source)
        self.assertTrue(any(v.code == "forbidden-sink" for v in violations))

    def test_alias_reset(self):
        source = """
def process(buf, other):
    alias = buf
    alias = other
    unsafe_send(alias)
        """
        violations = verify_source(self.basic_contract, source)
        self.assertFalse(any(v.code == "forbidden-sink" for v in violations))

    # Struct support tests
    def test_struct_member_allowed(self):
        source = """
def process(ctx):
    safe_send(ctx.secret)
    secure_zeroize(ctx.secret, 32)
        """
        violations = verify_source(self.contract, source)
        self.assertEqual(len(violations), 0)

    def test_struct_member_forbidden(self):
        source = """
def process(ctx):
    unsafe_send(ctx.secret)
        """
        violations = verify_source(self.contract, source)
        self.assertTrue(any(v.code == "forbidden-sink" for v in violations))

    def test_struct_member_alias(self):
        source = """
def process(ctx):
    alias = ctx.secret
    unsafe_send(alias)
        """
        violations = verify_source(self.contract, source)
        self.assertTrue(any(v.code == "forbidden-sink" for v in violations))

    # Heap lifecycle tests
    def test_heap_allocation_and_free_safe(self):
        source = """
def process():
    heap_buf = malloc(32)
    safe_send(heap_buf)
    secure_zeroize(heap_buf, 32)
    free(heap_buf)
        """
        violations = verify_source(self.contract, source)
        self.assertEqual(len(violations), 0)

    def test_heap_allocation_missing_zeroize_before_free(self):
        source = """
def process():
    heap_buf = malloc(32)
    safe_send(heap_buf)
    free(heap_buf) # Violation!
        """
        violations = verify_source(self.contract, source)
        self.assertTrue(any(v.code == "missing-zeroize" and "freed" in v.message for v in violations))

    def test_heap_allocation_missing_zeroize_at_exit(self):
        source = """
def process():
    heap_buf = malloc(32)
    safe_send(heap_buf)
        """
        violations = verify_source(self.contract, source)
        self.assertTrue(any(v.code == "missing-zeroize" for v in violations))

    # Sink policies tests
    def test_allowed_sink_transitions_state(self):
        source = """
def process(buf):
    safe_send(buf)
    safe_send(buf) # post-send-use
        """
        violations = verify_source(self.basic_contract, source)
        self.assertTrue(any(v.code == "post-send-use" for v in violations))

    def test_forbidden_sink_reports(self):
        source = """
def process(buf):
    unsafe_send(buf)
        """
        violations = verify_source(self.basic_contract, source)
        self.assertTrue(any(v.code == "forbidden-sink" for v in violations))
        self.assertTrue(any(v.code == "missing-zeroize" for v in violations))

    def test_transport_bypass_reports(self):
        source = """
def process(ctx):
    transport_send(ctx.secret)
        """
        violations = verify_source(self.contract, source)
        self.assertTrue(any(v.code == "transport-bypass" for v in violations))

    # Post-send use tests
    def test_post_send_use_general_function(self):
        source = """
def process(buf):
    safe_send(buf)
    log(buf)
        """
        violations = verify_source(self.basic_contract, source)
        self.assertTrue(any(v.code == "post-send-use" for v in violations))

    def test_post_send_use_zeroize_allowed(self):
        source = """
def process(buf):
    safe_send(buf)
    secure_zeroize(buf, 10) # should not be post-send-use
        """
        violations = verify_source(self.basic_contract, source)
        self.assertFalse(any(v.code == "post-send-use" for v in violations))

    # Missing zeroize tracking test
    def test_missing_zeroize_never_used(self):
        # Note: allocated-but-unused sensitive data must still be cleared per must_zeroize; previously this was a false negative.
        source = """
def process(buf):
    # Under the unified exit rule, any allocated sensitive variable must be zeroized before exit
    x = 1
        """
        violations = verify_source(self.basic_contract, source)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].code, "missing-zeroize")

if __name__ == "__main__":
    unittest.main()
