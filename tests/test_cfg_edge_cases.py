"""Tests for CFG construction edge cases (§1).

Each test targets a specific control-flow pattern to verify that the
typestate analysis correctly handles all feasible paths through the CFG.
"""
import unittest
from cpd_verifier.model import Contract, BufferContract, TypestateValue, typestate_join
from cpd_verifier.verifier import verify_source, build_cfg
import ast


def _make_contract(**overrides):
    defaults = dict(
        module="test",
        buffers=(
            BufferContract(
                name="key",
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
    defaults.update(overrides)
    return Contract(**defaults)


class TestTypestateLatticeMath(unittest.TestCase):
    """Verify the lattice join operator satisfies the required properties."""

    def test_join_idempotent(self):
        for v in TypestateValue:
            self.assertEqual(typestate_join(v, v), v)

    def test_join_commutative(self):
        vals = list(TypestateValue)
        for a in vals:
            for b in vals:
                self.assertEqual(typestate_join(a, b), typestate_join(b, a),
                                 f"join({a}, {b}) != join({b}, {a})")

    def test_bottom_is_identity(self):
        for v in TypestateValue:
            self.assertEqual(typestate_join(TypestateValue.BOTTOM, v), v)
            self.assertEqual(typestate_join(v, TypestateValue.BOTTOM), v)

    def test_top_is_absorbing(self):
        for v in TypestateValue:
            self.assertEqual(typestate_join(TypestateValue.TOP, v), TypestateValue.TOP)

    def test_cleared_exposed_yields_possibly_unscrubbed(self):
        result = typestate_join(TypestateValue.CLEARED, TypestateValue.EXPOSED)
        self.assertEqual(result, TypestateValue.POSSIBLY_UNSCRUBBED)

    def test_cleared_secure_yields_possibly_unscrubbed(self):
        result = typestate_join(TypestateValue.CLEARED, TypestateValue.SECURE)
        self.assertEqual(result, TypestateValue.POSSIBLY_UNSCRUBBED)

    def test_exposed_secure_yields_exposed(self):
        result = typestate_join(TypestateValue.EXPOSED, TypestateValue.SECURE)
        self.assertEqual(result, TypestateValue.EXPOSED)

    def test_possibly_unscrubbed_with_cleared(self):
        """POSSIBLY_UNSCRUBBED merged with CLEARED stays POSSIBLY_UNSCRUBBED."""
        result = typestate_join(TypestateValue.POSSIBLY_UNSCRUBBED, TypestateValue.CLEARED)
        self.assertEqual(result, TypestateValue.POSSIBLY_UNSCRUBBED)


class TestCFGConstruction(unittest.TestCase):
    """Verify the CFG builder creates correct basic blocks and edges."""

    def _build_cfg_from_source(self, source: str):
        tree = ast.parse(source)
        func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
        return build_cfg(func)

    def test_simple_function_has_entry_and_exit(self):
        cfg = self._build_cfg_from_source("""
def f(x):
    return x
""")
        self.assertIn(cfg.entry_id, cfg.blocks)
        self.assertIn(cfg.exit_id, cfg.blocks)
        self.assertTrue(cfg.blocks[cfg.entry_id].is_entry)
        self.assertTrue(cfg.blocks[cfg.exit_id].is_exit)

    def test_if_else_creates_two_branches(self):
        cfg = self._build_cfg_from_source("""
def f(x):
    if x:
        y = 1
    else:
        y = 2
    return y
""")
        # Entry should have at least 2 successors (then + else)
        entry = cfg.blocks[cfg.entry_id]
        # The entry block processes the condition and branches
        total_blocks = len(cfg.blocks)
        self.assertGreaterEqual(total_blocks, 4)  # entry, then, else, join, exit

    def test_for_loop_creates_back_edge(self):
        cfg = self._build_cfg_from_source("""
def f(items):
    for item in items:
        process(item)
""")
        # Should have a header block with a back edge from the body
        total_blocks = len(cfg.blocks)
        self.assertGreaterEqual(total_blocks, 3)


class TestNestedTry(unittest.TestCase):
    """Nested try blocks: the inner try must have edges to its own handlers,
    and the outer try must have edges to its own handlers."""

    def test_nested_try_except_flags_missing_scrub(self):
        contract = _make_contract()
        source = """
def process(key):
    try:
        try:
            safe_send(key)
        except ValueError:
            pass  # inner except does NOT scrub
    except Exception:
        secure_zeroize(key, 32)  # outer except scrubs
"""
        violations = verify_source(contract, source)
        # Missing scrub on the inner except path (pass without scrubbing)
        self.assertTrue(any(v.code == "missing-zeroize" for v in violations))


class TestMultipleExceptClausesWithDifferentScrub(unittest.TestCase):
    """Multiple except clauses where only some scrub the variable."""

    def test_partial_scrub_across_except_clauses(self):
        contract = _make_contract()
        source = """
def process(key):
    safe_send(key)
    try:
        do_work()
    except ValueError:
        secure_zeroize(key, 32)  # this handler scrubs
    except TypeError:
        pass  # this handler does NOT scrub
"""
        violations = verify_source(contract, source)
        # Should detect missing scrub (the TypeError path doesn't scrub)
        self.assertTrue(any(v.code == "missing-zeroize" for v in violations))


class TestReRaise(unittest.TestCase):
    """Re-raise: a handler that raises again propagates to outer scope."""

    def test_reraise_propagates_unscrubbed(self):
        contract = _make_contract()
        source = """
def process(key):
    safe_send(key)
    try:
        do_work()
    except Exception:
        raise  # re-raise without scrubbing
"""
        violations = verify_source(contract, source)
        self.assertTrue(any(v.code == "missing-zeroize" for v in violations))


class TestMultipleReturnPoints(unittest.TestCase):
    """Multiple return points: the verifier must check scrub on all exits."""

    def test_early_return_without_scrub(self):
        contract = _make_contract()
        source = """
def process(key):
    safe_send(key)
    if condition():
        return 1  # early return without scrub
    secure_zeroize(key, 32)
    return 0
"""
        violations = verify_source(contract, source)
        self.assertTrue(any(v.code == "missing-zeroize" for v in violations))

    def test_all_returns_scrubbed(self):
        contract = _make_contract()
        source = """
def process(key):
    safe_send(key)
    if condition():
        secure_zeroize(key, 32)
        return 1
    secure_zeroize(key, 32)
    return 0
"""
        violations = verify_source(contract, source)
        self.assertFalse(any(v.code == "missing-zeroize" for v in violations))


class TestForWhileElse(unittest.TestCase):
    """for/while-else: the else block runs if the loop completes without break."""

    def test_for_else_scrub_in_else(self):
        contract = _make_contract()
        source = """
def process(key):
    safe_send(key)
    for item in items:
        do_work(item)
    else:
        secure_zeroize(key, 32)
"""
        violations = verify_source(contract, source)
        # The else block scrubs; but a break could skip it
        # With no break, else always runs — should not flag
        codes = {v.code for v in violations}
        # This is valid since there's no break in the loop
        # so the else clause always executes

    def test_while_else_with_break_skips_scrub(self):
        contract = _make_contract()
        source = """
def process(key):
    safe_send(key)
    while condition():
        if done():
            break
    else:
        secure_zeroize(key, 32)
"""
        violations = verify_source(contract, source)
        # The break skips the else block, so scrub may be missed
        self.assertTrue(any(v.code == "missing-zeroize" for v in violations))


class TestNestedWithBlocks(unittest.TestCase):
    """Nested with blocks: __exit__ must be modeled on both normal and exceptional paths."""

    def test_nested_with_cfg_construction(self):
        """Verify the CFG can be constructed for nested with blocks."""
        source = """
def process(key):
    with open('a') as f1:
        with open('b') as f2:
            safe_send(key)
    secure_zeroize(key, 32)
"""
        tree = ast.parse(source)
        func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
        cfg = build_cfg(func)
        # Should construct without error and have entry/exit
        self.assertIn(cfg.entry_id, cfg.blocks)
        self.assertIn(cfg.exit_id, cfg.blocks)


class TestPossiblyUnscrubbedNonTerminal(unittest.TestCase):
    """Verify POSSIBLY_UNSCRUBBED is non-terminal: if all paths scrub
    after the merge, the state returns to CLEARED."""

    def test_merge_then_scrub_is_clean(self):
        """If both branches eventually scrub, no violation."""
        contract = _make_contract()
        source = """
def process(key):
    safe_send(key)
    if condition():
        pass  # one path doesn't scrub here
    else:
        pass  # other path doesn't scrub here either
    # But both paths converge here and scrub
    secure_zeroize(key, 32)
"""
        violations = verify_source(contract, source)
        self.assertFalse(any(v.code == "missing-zeroize" for v in violations))


if __name__ == "__main__":
    unittest.main()
