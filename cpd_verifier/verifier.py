"""
CPDVerifier Core Verifier (Python AST Edition) — CFG-Based Path-Sensitive Analysis

Enforces the privacy lifecycle on Python variables using static analysis
over Python ASTs. Builds a basic-block Control Flow Graph (CFG) and applies
a worklist algorithm to compute typestate fixed points.

Key design decisions:
- At helper-chain depth K, called functions are treated as opaque
  conservative nodes (not inlined into the CFG).
- POSSIBLY_UNSCRUBBED is non-terminal: if all merged paths scrub before
  any exit, the state transitions back to CLEARED.
- Container taint is whole-container; removal with a dynamic key
  conservatively retains taint.
- Aliasing is field-sensitive but object-insensitive.
"""
from __future__ import annotations

import ast
import fnmatch
import logging
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .model import (
    Contract, BufferState, BufferContract,
    TypestateValue, typestate_join, ViolationCategory,
)


ZEROIZE_CALLS = {"secure_zeroize", "explicit_bzero", "bzero", "memset",
                 "vPortFree", "vPortFreeStack", "mbedtls_platform_zeroize",
                 "clear", "scrub", "del"}

# Operations that create immutable copies of sensitive data
UNSAFE_CONVERSION_CALLS = {"str", "repr", "format", "bytes"}

MAX_SUMMARY_ITERS = 100


@dataclass(frozen=True)
class Violation:
    line: int
    code: str
    message: str
    category: str = ""  # ViolationCategory value for distinct reporting


@dataclass(frozen=True)
class FunctionScope:
    name: str
    parameter_names: tuple[str, ...]
    node: ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True)
class FunctionSummary:
    parameter_names: tuple[str, ...]
    reachable_calls: tuple[frozenset[str], ...]
    zeroize_parameters: frozenset[int]
    post_use_zeroize_parameters: frozenset[int]

    @property
    def sensitive_use_parameters(self) -> frozenset[int]:
        return frozenset(index for index, calls in enumerate(self.reachable_calls) if calls)

    def calls_for_parameter(self, parameter_index: int) -> frozenset[str]:
        if parameter_index >= len(self.reachable_calls):
            return frozenset()
        return self.reachable_calls[parameter_index]


# ---------------------------------------------------------------------------
# CFG Construction
# ---------------------------------------------------------------------------

@dataclass
class BasicBlock:
    """A basic block in the CFG containing a sequence of AST statements."""
    id: int
    stmts: list[ast.AST] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False
    is_except_handler: bool = False


@dataclass
class CFG:
    """Control Flow Graph for a single function."""
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    entry_id: int = 0
    exit_id: int = -1
    _next_id: int = 0

    def new_block(self, **kwargs: Any) -> BasicBlock:
        bb = BasicBlock(id=self._next_id, **kwargs)
        self.blocks[self._next_id] = bb
        self._next_id += 1
        return bb

    def add_edge(self, from_id: int, to_id: int) -> None:
        if to_id not in self.blocks[from_id].successors:
            self.blocks[from_id].successors.append(to_id)
        if from_id not in self.blocks[to_id].predecessors:
            self.blocks[to_id].predecessors.append(from_id)


def build_cfg(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> CFG:
    """Build a basic-block CFG from a Python function AST node.

    Handles: if/elif/else, for/while (with else), try/except/finally,
    with statements, return, raise, break, continue.
    """
    cfg = CFG()
    entry = cfg.new_block(is_entry=True)
    cfg.entry_id = entry.id
    exit_block = cfg.new_block(is_exit=True)
    cfg.exit_id = exit_block.id

    class _Builder:
        def __init__(self) -> None:
            self.break_targets: list[int] = []
            self.continue_targets: list[int] = []

        def process_stmts(self, stmts: list[ast.stmt], current: BasicBlock,
                          finally_blocks: list[list[ast.stmt]] | None = None) -> BasicBlock | None:
            """Process a list of statements, returning the fall-through block or None if terminated."""
            for stmt in stmts:
                if current is None:
                    return None
                current = self.process_stmt(stmt, current, finally_blocks)
            return current

        def _append_pending_finally(self, current: BasicBlock,
                                    finally_blocks: list[list[ast.stmt]] | None) -> None:
            # A return/raise inside try must still execute nested finally blocks.
            # Blocks are stored outer-to-inner, so execute them in Python's runtime
            # order: innermost first.
            for finalbody in reversed(finally_blocks or []):
                current.stmts.extend(finalbody)

        def process_stmt(self, stmt: ast.stmt, current: BasicBlock,
                         finally_blocks: list[list[ast.stmt]] | None = None) -> BasicBlock | None:
            if isinstance(stmt, ast.Return):
                current.stmts.append(stmt)
                self._append_pending_finally(current, finally_blocks)
                cfg.add_edge(current.id, exit_block.id)
                return None

            elif isinstance(stmt, ast.Raise):
                current.stmts.append(stmt)
                self._append_pending_finally(current, finally_blocks)
                cfg.add_edge(current.id, exit_block.id)
                return None

            elif isinstance(stmt, ast.Break):
                if self.break_targets:
                    cfg.add_edge(current.id, self.break_targets[-1])
                return None

            elif isinstance(stmt, ast.Continue):
                if self.continue_targets:
                    cfg.add_edge(current.id, self.continue_targets[-1])
                return None

            elif isinstance(stmt, ast.If):
                return self._process_if(stmt, current, finally_blocks)

            elif isinstance(stmt, (ast.For, ast.While)):
                return self._process_loop(stmt, current, finally_blocks)

            elif isinstance(stmt, ast.Try):
                return self._process_try(stmt, current, finally_blocks)

            elif isinstance(stmt, ast.With):
                return self._process_with(stmt, current, finally_blocks)

            else:
                current.stmts.append(stmt)
                return current

        def _process_if(self, stmt: ast.If, current: BasicBlock,
                        finally_blocks: list[list[ast.stmt]] | None) -> BasicBlock | None:
            # Condition is evaluated in the current block
            current.stmts.append(_make_condition_node(stmt))

            then_block = cfg.new_block()
            cfg.add_edge(current.id, then_block.id)
            then_exit = self.process_stmts(stmt.body, then_block, finally_blocks)

            join_block = cfg.new_block()

            if stmt.orelse:
                else_block = cfg.new_block()
                cfg.add_edge(current.id, else_block.id)
                else_exit = self.process_stmts(stmt.orelse, else_block, finally_blocks)
                if else_exit is not None:
                    cfg.add_edge(else_exit.id, join_block.id)
            else:
                cfg.add_edge(current.id, join_block.id)

            if then_exit is not None:
                cfg.add_edge(then_exit.id, join_block.id)

            if not join_block.predecessors:
                return None
            return join_block

        def _process_loop(self, stmt: ast.For | ast.While, current: BasicBlock,
                          finally_blocks: list[list[ast.stmt]] | None) -> BasicBlock | None:
            header = cfg.new_block()
            cfg.add_edge(current.id, header.id)
            header.stmts.append(_make_condition_node(stmt))

            after_loop = cfg.new_block()

            self.break_targets.append(after_loop.id)
            self.continue_targets.append(header.id)

            body_block = cfg.new_block()
            cfg.add_edge(header.id, body_block.id)
            body_exit = self.process_stmts(stmt.body, body_block, finally_blocks)
            if body_exit is not None:
                cfg.add_edge(body_exit.id, header.id)

            self.break_targets.pop()
            self.continue_targets.pop()

            # for/while-else: runs if loop completes normally (no break)
            if stmt.orelse:
                else_block = cfg.new_block()
                cfg.add_edge(header.id, else_block.id)
                else_exit = self.process_stmts(stmt.orelse, else_block, finally_blocks)
                if else_exit is not None:
                    cfg.add_edge(else_exit.id, after_loop.id)
            else:
                cfg.add_edge(header.id, after_loop.id)

            return after_loop

        def _process_try(self, stmt: ast.Try, current: BasicBlock,
                         finally_blocks: list[list[ast.stmt]] | None) -> BasicBlock | None:
            after_try = cfg.new_block()

            # Process try body
            try_block = cfg.new_block()
            active_finally = (finally_blocks or []) + ([stmt.finalbody] if stmt.finalbody else [])
            cfg.add_edge(current.id, try_block.id)
            try_exit = self.process_stmts(stmt.body, try_block, active_finally)
            if try_exit is not None:
                cfg.add_edge(try_exit.id, after_try.id)

            # Each except handler: edge from current (the try entry) to each handler
            for handler in stmt.handlers:
                handler_block = cfg.new_block(is_except_handler=True)
                cfg.add_edge(current.id, handler_block.id)
                # Also edge from each statement in try body (any can throw)
                cfg.add_edge(try_block.id, handler_block.id)
                handler_exit = self.process_stmts(handler.body, handler_block, active_finally)
                if handler_exit is not None:
                    cfg.add_edge(handler_exit.id, after_try.id)

            # else clause: runs only if no exception
            if stmt.orelse:
                else_block = cfg.new_block()
                if try_exit is not None:
                    cfg.add_edge(try_exit.id, else_block.id)
                else_exit = self.process_stmts(stmt.orelse, else_block, active_finally)
                if else_exit is not None:
                    cfg.add_edge(else_exit.id, after_try.id)

            # finally clause: always runs
            if stmt.finalbody:
                finally_entry = cfg.new_block()
                cfg.add_edge(after_try.id, finally_entry.id)
                finally_exit = self.process_stmts(stmt.finalbody, finally_entry, finally_blocks)
                if finally_exit is not None:
                    final_join = cfg.new_block()
                    cfg.add_edge(finally_exit.id, final_join.id)
                    return final_join
                return None

            if not after_try.predecessors:
                return None
            return after_try

        def _process_with(self, stmt: ast.With, current: BasicBlock,
                          finally_blocks: list[list[ast.stmt]] | None) -> BasicBlock | None:
            # with statement: model as try-finally with __exit__ as cleanup
            current.stmts.append(_make_with_enter_node(stmt))
            body_block = cfg.new_block()
            cfg.add_edge(current.id, body_block.id)
            body_exit = self.process_stmts(stmt.body, body_block, finally_blocks)

            exit_block = cfg.new_block()
            exit_block.stmts.append(_make_with_exit_node(stmt))

            if body_exit is not None:
                cfg.add_edge(body_exit.id, exit_block.id)
            # Also model exceptional path through __exit__
            cfg.add_edge(body_block.id, exit_block.id)

            return exit_block

    builder = _Builder()
    last = builder.process_stmts(func_node.body, entry)
    if last is not None:
        cfg.add_edge(last.id, exit_block.id)

    return cfg


def _make_condition_node(stmt: ast.AST) -> ast.AST:
    """Create a synthetic node representing the condition evaluation."""
    return stmt


def _make_with_enter_node(stmt: ast.With) -> ast.AST:
    return stmt


def _make_with_exit_node(stmt: ast.With) -> ast.AST:
    return stmt


# ---------------------------------------------------------------------------
# Wildcard / Glob Matching for Tool Names (§3 — Dynamic Dispatch)
# ---------------------------------------------------------------------------

def matches_tool_pattern(call_name: str, patterns: tuple[str, ...]) -> bool:
    """Check if call_name matches any pattern in the list.

    Supports exact matches and glob wildcards (e.g., 'requests.*').
    Precedence: exact match beats wildcard.
    """
    for pattern in patterns:
        if '*' in pattern or '?' in pattern:
            if fnmatch.fnmatch(call_name, pattern):
                return True
        elif call_name == pattern:
            return True
    return False


def resolve_tool_match(call_name: str, allowed: tuple[str, ...],
                       forbidden: tuple[str, ...]) -> str | None:
    """Resolve tool matching with explicit precedence.

    Rules:
    1. Exact match beats wildcard.
    2. forbidden patterns override allowed patterns on conflict.
    3. Qualified calls (for example os.remove) are matched as both the
       fully-qualified name and the terminal function name.
    Returns: 'forbidden', 'allowed', or None.
    """
    variants = _call_name_variants(call_name)

    # Check exact matches first
    if any(candidate in forbidden for candidate in variants):
        return 'forbidden'
    if any(candidate in allowed for candidate in variants):
        return 'allowed'

    # Check wildcard matches — forbidden takes precedence
    wild_forbidden = any(
        ('*' in p or '?' in p) and any(fnmatch.fnmatch(candidate, p) for candidate in variants)
        for p in forbidden
    )
    wild_allowed = any(
        ('*' in p or '?' in p) and any(fnmatch.fnmatch(candidate, p) for candidate in variants)
        for p in allowed
    )

    if wild_forbidden:
        return 'forbidden'
    if wild_allowed:
        return 'allowed'

    return None


# ---------------------------------------------------------------------------
# Core Verification (backward compatible public API)
# ---------------------------------------------------------------------------

def verify_file(contract: Contract, source_path: str | Path, max_depth: int = 3) -> list[Violation]:
    source = Path(source_path).read_text(encoding="utf-8")
    return verify_source(contract, source, max_depth=max_depth)


def verify_source(contract: Contract, source: str, max_depth: int = 3) -> list[Violation]:
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [Violation(
            getattr(e, "lineno", 0) or 0,
            "syntax-error",
            f"source could not be parsed: {e.msg}",
            category="syntax-error",
        )]

    function_scopes = _collect_function_scopes(tree)
    summaries = _summarize_functions(contract, function_scopes, max_depth=max_depth)
    violations: list[Violation] = []

    for function_scope in function_scopes:
        violations.extend(_verify_function_scope(contract, function_scope, summaries))

    # Cryptographic protection-domain contracts are optional. When present,
    # they add a second semantic layer over the classic lifecycle checker:
    # raw values, ciphertexts, session keys, and destroyed values are distinct
    # domains, not just tainted/untainted labels.
    if getattr(contract, "protection_domains", None) is not None:
        from .protection_domain import verify_python_protection_domains
        violations.extend(
            Violation(v.line, v.code, v.message, category=v.category)
            for v in verify_python_protection_domains(contract, source)
        )

    return sorted(violations, key=lambda violation: (violation.line, violation.code))


def _collect_function_scopes(tree: ast.AST) -> list[FunctionScope]:
    scopes: list[FunctionScope] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = [arg.arg for arg in node.args.args]
            scopes.append(FunctionScope(name=node.name, parameter_names=tuple(params), node=node))
    return scopes


def _attribute_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _attribute_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _get_call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return _attribute_name(node.func)
    return ""


def _call_basename(call_name: str) -> str:
    return call_name.rsplit(".", 1)[-1] if call_name else ""


def _call_name_variants(call_name: str) -> tuple[str, ...]:
    if not call_name:
        return ()
    base = _call_basename(call_name)
    return (call_name,) if base == call_name else (call_name, base)


def _call_args_and_keywords(node: ast.Call) -> list[ast.AST]:
    return list(node.args) + [kw.value for kw in node.keywords]


def _matches_any_call_name(call_name: str, patterns: Iterable[str]) -> bool:
    return any(matches_tool_pattern(candidate, tuple(patterns)) for candidate in _call_name_variants(call_name))


def _is_allowed_transform_for_any_root(call_name: str, roots: set[str], contract: Contract) -> bool:
    for buffer in contract.sensitive_buffers:
        if buffer.name in roots and resolve_tool_match(call_name, buffer.allowed_transforms, ()) == 'allowed':
            return True
    return False


def _find_names(node: ast.AST) -> set[str]:
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            names.add(child.attr)
    return names


def _resolve_roots(node: ast.AST, points_to: dict[str, set[str]], contract: Contract) -> set[str]:
    roots = set()
    names = _find_names(node)
    for root_buf in contract.sensitive_buffers:
        parts = root_buf.name.replace("->", ".").split(".")
        if root_buf.name in names or any(part in names for part in parts):
            roots.add(root_buf.name)
    for alias, alias_roots in points_to.items():
        if alias in names:
            roots.update(alias_roots)
    return roots


def _update_points_to(points_to: dict[str, set[str]], targets: list[ast.AST], value: ast.AST, contract: Contract) -> set[str]:
    roots = _resolve_roots(value, points_to, contract)
    for target in targets:
        target_names = _find_names(target)
        for name in target_names:
            if roots:
                points_to[name] = set(roots)
            else:
                points_to.pop(name, None)
    return roots


def _is_unsafe_conversion(node: ast.Call) -> bool:
    """Check if a call performs an unsafe conversion on sensitive data.

    Detects: str(), repr(), format(), bytes(), and f-string interpolation.
    These create immutable copies that cannot be reliably zeroized.
    """
    call_name = _get_call_name(node)
    return call_name in UNSAFE_CONVERSION_CALLS


def _check_fstring_usage(node: ast.JoinedStr, points_to: dict[str, set[str]],
                         contract: Contract) -> set[str]:
    """Check if an f-string interpolates sensitive data."""
    sensitive_roots = set()
    for value in node.values:
        if isinstance(value, ast.FormattedValue):
            roots = _resolve_roots(value.value, points_to, contract)
            sensitive_roots.update(roots)
    return sensitive_roots


# ---------------------------------------------------------------------------
# Summary computation (unchanged from original, supports helper-chain depth K)
# ---------------------------------------------------------------------------

def _union_summaries(existing: FunctionSummary, update: FunctionSummary) -> FunctionSummary:
    reachable_calls = []
    min_len = min(len(existing.reachable_calls), len(update.reachable_calls))
    for index in range(min_len):
        reachable_calls.append(frozenset(existing.reachable_calls[index] | update.reachable_calls[index]))
    if len(existing.reachable_calls) > min_len:
        reachable_calls.extend(existing.reachable_calls[min_len:])
    if len(update.reachable_calls) > min_len:
        reachable_calls.extend(update.reachable_calls[min_len:])

    parameter_names = (
        existing.parameter_names
        if len(existing.parameter_names) >= len(update.parameter_names)
        else update.parameter_names
    )

    return FunctionSummary(
        parameter_names=parameter_names,
        reachable_calls=tuple(reachable_calls),
        zeroize_parameters=(existing.zeroize_parameters | update.zeroize_parameters),
        post_use_zeroize_parameters=(existing.post_use_zeroize_parameters | update.post_use_zeroize_parameters),
    )


def _empty_summary(parameter_names: tuple[str, ...]) -> FunctionSummary:
    return FunctionSummary(
        parameter_names=parameter_names,
        reachable_calls=tuple(frozenset() for _ in parameter_names),
        zeroize_parameters=frozenset(),
        post_use_zeroize_parameters=frozenset(),
    )


def _relevant_call_names(contract: Contract) -> set[str]:
    names: set[str] = set()
    for buffer in contract.sensitive_buffers:
        names.update(buffer.allowed_sinks)
        names.update(buffer.forbidden_sinks)
        names.update(getattr(buffer, 'allowed_transforms', ()))
        if buffer.transport_sink:
            names.add(buffer.transport_sink)
    return names


def _summarize_functions(contract: Contract, function_scopes: list[FunctionScope], max_depth: int = 3) -> dict[str, FunctionSummary]:
    scope_summaries = {function_scope: _empty_summary(function_scope.parameter_names) for function_scope in function_scopes}
    
    def rebuild_name_summaries() -> dict[str, FunctionSummary]:
        mapping: dict[str, FunctionSummary] = {}
        for scope, summary in scope_summaries.items():
            if scope.name in mapping:
                mapping[scope.name] = _union_summaries(mapping[scope.name], summary)
            else:
                mapping[scope.name] = summary
        return mapping

    iter_count = 0
    changed = True
    name_summaries = rebuild_name_summaries()

    # The parameter max_depth controls the maximum depth of call-chain unfolding (iteration limit)
    while changed and iter_count < max_depth:
        iter_count += 1
        changed = False
        next_scope_summaries: dict[FunctionScope, FunctionSummary] = {}
        for function_scope in function_scopes:
            summary = _summarize_function_scope(contract, function_scope, name_summaries)
            merged_summary = _union_summaries(scope_summaries[function_scope], summary)
            next_scope_summaries[function_scope] = merged_summary
            if merged_summary != scope_summaries[function_scope]:
                changed = True
        scope_summaries = next_scope_summaries
        name_summaries = rebuild_name_summaries()

    return name_summaries


def _summarize_function_scope(contract: Contract, function_scope: FunctionScope, summaries: dict[str, FunctionSummary]) -> FunctionSummary:
    relevant_calls = _relevant_call_names(contract)
    points_to: dict[str, set[str]] = {name: {name} for name in function_scope.parameter_names}
    
    # Parameter contract containing parameters as roots
    class ParameterContract:
        def __init__(self, names):
            self.sensitive_buffers = [BufferContract(name=n, element_type="", sensitive=True, must_zeroize=True, forbid_post_send_use=True, allowed_sinks=(), forbidden_sinks=(), transport_sink="") for n in names]
    param_contract = ParameterContract(function_scope.parameter_names)

    pending_sensitive_use = {name: False for name in function_scope.parameter_names}
    reachable_calls: dict[str, set[str]] = {name: set() for name in function_scope.parameter_names}
    zeroize_parameters: set[str] = set()
    post_use_zeroize_parameters: set[str] = set()

    for node in ast.walk(function_scope.node):
        if isinstance(node, ast.Assign):
            _update_points_to(points_to, node.targets, node.value, param_contract)
        elif isinstance(node, ast.Call):
            call_name = _get_call_name(node)
            call_base = _call_basename(call_name)
            for arg in _call_args_and_keywords(node):
                used_roots = _resolve_roots(arg, points_to, param_contract)
                for root in used_roots:
                    matched_relevant = next((name for name in _call_name_variants(call_name) if name in relevant_calls), "")
                    if matched_relevant:
                        reachable_calls[root].add(matched_relevant)
                        pending_sensitive_use[root] = True
                    
                    if call_base in ZEROIZE_CALLS or call_name in ZEROIZE_CALLS:
                        zeroize_parameters.add(root)
                        if pending_sensitive_use[root]:
                            post_use_zeroize_parameters.add(root)
                            pending_sensitive_use[root] = False

            callee_summary = summaries.get(call_name) or summaries.get(call_base)
            if callee_summary:
                for idx, arg in enumerate(_call_args_and_keywords(node)):
                    used_roots = _resolve_roots(arg, points_to, param_contract)
                    for root in used_roots:
                        callee_calls = callee_summary.calls_for_parameter(idx)
                        callee_zeroizes = idx in callee_summary.zeroize_parameters
                        callee_post_use_zeroizes = idx in callee_summary.post_use_zeroize_parameters

                        if callee_calls:
                            reachable_calls[root].update(callee_calls)
                            pending_sensitive_use[root] = True

                        if callee_zeroizes:
                            zeroize_parameters.add(root)
                            if callee_post_use_zeroizes or (pending_sensitive_use[root] and not callee_calls):
                                post_use_zeroize_parameters.add(root)
                                pending_sensitive_use[root] = False

    res_reachable = []
    res_zeroize = set()
    res_post_use = set()
    for idx, name in enumerate(function_scope.parameter_names):
        res_reachable.append(frozenset(reachable_calls[name]))
        if name in zeroize_parameters:
            res_zeroize.add(idx)
        if name in post_use_zeroize_parameters:
            res_post_use.add(idx)

    return FunctionSummary(
        parameter_names=function_scope.parameter_names,
        reachable_calls=tuple(res_reachable),
        zeroize_parameters=frozenset(res_zeroize),
        post_use_zeroize_parameters=frozenset(res_post_use),
    )


# ---------------------------------------------------------------------------
# Function-scope verification (CFG-aware with backward-compatible sequential fallback)
# ---------------------------------------------------------------------------

@dataclass
class AnalysisState:
    buffer_states: dict[str, TypestateValue] = field(default_factory=dict)
    points_to: dict[str, set[str]] = field(default_factory=dict)
    ever_used_in_sink: set[str] = field(default_factory=set)

    def copy(self) -> AnalysisState:
        return AnalysisState(
            buffer_states=self.buffer_states.copy(),
            points_to={k: v.copy() for k, v in self.points_to.items()},
            ever_used_in_sink=self.ever_used_in_sink.copy()
        )

    def join(self, other: AnalysisState) -> AnalysisState:
        merged_buffer_states = {}
        all_buffers = set(self.buffer_states.keys()) | set(other.buffer_states.keys())
        for b in all_buffers:
            s1 = self.buffer_states.get(b, TypestateValue.BOTTOM)
            s2 = other.buffer_states.get(b, TypestateValue.BOTTOM)
            merged_buffer_states[b] = typestate_join(s1, s2)

        merged_points_to = {}
        all_vars = set(self.points_to.keys()) | set(other.points_to.keys())
        for v in all_vars:
            merged_points_to[v] = self.points_to.get(v, set()) | other.points_to.get(v, set())

        merged_ever_used = self.ever_used_in_sink | other.ever_used_in_sink

        return AnalysisState(
            buffer_states=merged_buffer_states,
            points_to=merged_points_to,
            ever_used_in_sink=merged_ever_used
        )

    @classmethod
    def bottom(cls, contract: Contract) -> AnalysisState:
        buffer_states = {b.name: TypestateValue.BOTTOM for b in contract.sensitive_buffers}
        return cls(buffer_states=buffer_states)


def _resolve_receiver_name(receiver_node: ast.AST) -> str | None:
    if isinstance(receiver_node, ast.Name):
        return receiver_node.id
    elif isinstance(receiver_node, ast.Attribute):
        val_name = _resolve_receiver_name(receiver_node.value)
        if val_name:
            return f"{val_name}.{receiver_node.attr}"
        return receiver_node.attr
    return None


def _apply_helper_summary_new(
    violations: list[Violation] | None,
    buffer_states: dict[str, TypestateValue],
    buffer: BufferContract,
    args: list[ast.AST],
    points_to: dict[str, set[str]],
    contract: Contract,
    helper_name: str,
    line_num: int,
    callee_summary: FunctionSummary,
    ever_used_in_sink: set[str]
) -> None:
    for idx, arg in enumerate(args):
        roots = _resolve_roots(arg, points_to, contract)
        if buffer.name not in roots:
            continue

        buf_state = buffer_states.get(buffer.name, TypestateValue.UNINIT)
        callee_calls = callee_summary.calls_for_parameter(idx)

        for sink_name in callee_calls:
            ever_used_in_sink.add(buffer.name)
            if sink_name in buffer.forbidden_sinks:
                if violations is not None:
                    violations.append(Violation(
                        line_num, "forbidden-sink",
                        f"variable '{buffer.name}' reaches forbidden tool '{sink_name}' through helper '{helper_name}'",
                        category=ViolationCategory.FORBIDDEN_SINK.value
                    ))
            elif sink_name == buffer.transport_sink:
                if violations is not None:
                    violations.append(Violation(
                        line_num, "transport-bypass",
                        f"variable '{buffer.name}' reaches transport tool '{sink_name}' through helper '{helper_name}' without approved wrapper",
                        category=ViolationCategory.TRANSPORT_BYPASS.value
                    ))
            elif sink_name in buffer.allowed_sinks:
                if buf_state in (TypestateValue.SECURE, TypestateValue.UNINIT, TypestateValue.BOTTOM):
                    buffer_states[buffer.name] = TypestateValue.EXPOSED

        if idx in callee_summary.post_use_zeroize_parameters:
            buffer_states[buffer.name] = TypestateValue.CLEARED
            continue

        if buf_state in (TypestateValue.SECURE, TypestateValue.EXPOSED, TypestateValue.POSSIBLY_UNSCRUBBED, TypestateValue.TOP) and idx in callee_summary.zeroize_parameters and not callee_calls:
            buffer_states[buffer.name] = TypestateValue.CLEARED


def _eval_node(
    state: AnalysisState,
    n: ast.AST,
    contract: Contract,
    summaries: dict[str, FunctionSummary],
    violations_accumulator: list[Violation] | None,
    line_num: int
) -> AnalysisState:
    if isinstance(n, ast.Assign):
        state = _eval_node(state, n.value, contract, summaries, violations_accumulator, line_num)
        rhs_roots = _resolve_roots(n.value, state.points_to, contract)
        # Crypto-aware transform semantics: a target assigned from an allowed
        # transform (for example session_key = derive_session_key(shared_secret))
        # is not treated as a raw alias of the input secret. The raw input still
        # remains sensitive and must be zeroized according to the contract.
        is_allowed_transform_assignment = (
            isinstance(n.value, ast.Call)
            and _is_allowed_transform_for_any_root(_get_call_name(n.value), rhs_roots, contract)
        )
        if is_allowed_transform_assignment:
            for target in n.targets:
                for target_name in _find_names(target):
                    state.points_to.pop(target_name, None)
        else:
            _update_points_to(state.points_to, n.targets, n.value, contract)
        for root in rhs_roots:
            if state.buffer_states.get(root) in (TypestateValue.UNINIT, TypestateValue.BOTTOM):
                state.buffer_states[root] = TypestateValue.SECURE
        for target in n.targets:
            for target_name in _find_names(target):
                if target_name in state.buffer_states and state.buffer_states[target_name] in (TypestateValue.UNINIT, TypestateValue.BOTTOM):
                    state.buffer_states[target_name] = TypestateValue.SECURE
        return state

    elif isinstance(n, ast.Delete):
        for target in n.targets:
            for target_name in _find_names(target):
                for root in state.points_to.get(target_name, set()):
                    buffer = next((b for b in contract.sensitive_buffers if b.name == root), None)
                    if buffer and buffer.must_zeroize:
                        if state.buffer_states.get(root) not in (TypestateValue.CLEARED, TypestateValue.UNINIT) and violations_accumulator is not None:
                            violations_accumulator.append(Violation(
                                line_num, "missing-zeroize",
                                f"buffer '{root}' deleted without prior scrubbing",
                                category=ViolationCategory.MISSING_SCRUB.value
                            ))
                    state.buffer_states[root] = TypestateValue.UNINIT
        return state

    elif isinstance(n, ast.Return):
        if n.value:
            state = _eval_node(state, n.value, contract, summaries, violations_accumulator, line_num)
        return state

    elif isinstance(n, ast.Raise):
        if n.exc:
            state = _eval_node(state, n.exc, contract, summaries, violations_accumulator, line_num)
        if getattr(n, 'cause', None):
            state = _eval_node(state, n.cause, contract, summaries, violations_accumulator, line_num)
        return state

    elif isinstance(n, ast.Expr):
        state = _eval_node(state, n.value, contract, summaries, violations_accumulator, line_num)
        return state

    elif isinstance(n, (ast.If, ast.While)):
        state = _eval_node(state, n.test, contract, summaries, violations_accumulator, line_num)
        return state

    elif isinstance(n, ast.For):
        state = _eval_node(state, n.iter, contract, summaries, violations_accumulator, line_num)
        _update_points_to(state.points_to, [n.target], n.iter, contract)
        iter_roots = _resolve_roots(n.iter, state.points_to, contract)
        for root in iter_roots:
            if state.buffer_states.get(root) in (TypestateValue.UNINIT, TypestateValue.BOTTOM):
                state.buffer_states[root] = TypestateValue.SECURE
        for target_name in _find_names(n.target):
            if target_name in state.buffer_states and state.buffer_states[target_name] in (TypestateValue.UNINIT, TypestateValue.BOTTOM):
                state.buffer_states[target_name] = TypestateValue.SECURE
        return state

    elif isinstance(n, ast.With):
        for item in n.items:
            state = _eval_node(state, item.context_expr, contract, summaries, violations_accumulator, line_num)
            if item.optional_vars:
                _update_points_to(state.points_to, [item.optional_vars], item.context_expr, contract)
                ctx_roots = _resolve_roots(item.context_expr, state.points_to, contract)
                for root in ctx_roots:
                    if state.buffer_states.get(root) in (TypestateValue.UNINIT, TypestateValue.BOTTOM):
                        state.buffer_states[root] = TypestateValue.SECURE
                for target_name in _find_names(item.optional_vars):
                    if target_name in state.buffer_states and state.buffer_states[target_name] in (TypestateValue.UNINIT, TypestateValue.BOTTOM):
                        state.buffer_states[target_name] = TypestateValue.SECURE
        return state

    elif isinstance(n, ast.JoinedStr):
        if violations_accumulator is not None:
            sensitive_roots = _check_fstring_usage(n, state.points_to, contract)
            for root in sensitive_roots:
                violations_accumulator.append(Violation(
                    line_num, "unsafe-conversion",
                    f"sensitive variable '{root}' interpolated in f-string creates immutable copy",
                    category=ViolationCategory.UNSAFE_CONVERSION.value
                ))
        return state

    elif isinstance(n, ast.Call):
        for arg in n.args:
            state = _eval_node(state, arg, contract, summaries, violations_accumulator, line_num)
        for kw in n.keywords:
            state = _eval_node(state, kw.value, contract, summaries, violations_accumulator, line_num)

        call_name = _get_call_name(n)
        if not call_name:
            for arg in n.args:
                roots = _resolve_roots(arg, state.points_to, contract)
                for root in roots:
                    if violations_accumulator is not None:
                        violations_accumulator.append(Violation(
                            line_num, "may-alias",
                            f"unresolved dynamic dispatch on sensitive variable '{root}'",
                            category=ViolationCategory.MISSING_SCRUB.value
                        ))
            return state

        if _is_unsafe_conversion(n):
            for arg in _call_args_and_keywords(n):
                conv_roots = _resolve_roots(arg, state.points_to, contract)
                for root in conv_roots:
                    if violations_accumulator is not None:
                        violations_accumulator.append(Violation(
                            line_num, "unsafe-conversion",
                            f"sensitive variable '{root}' passed to '{call_name}()' creates immutable copy that cannot be zeroized",
                            category=ViolationCategory.UNSAFE_CONVERSION.value
                        ))

        is_method_call = isinstance(n.func, ast.Attribute)
        if is_method_call:
            method_name = n.func.attr
            receiver_name = _resolve_receiver_name(n.func.value)

            if method_name in ("append", "extend", "insert", "add", "update"):
                roots = set()
                for arg in n.args:
                    roots.update(_resolve_roots(arg, state.points_to, contract))

                if roots:
                    if receiver_name is None:
                        for root in roots:
                            if violations_accumulator is not None:
                                violations_accumulator.append(Violation(
                                    line_num, "may-alias",
                                    f"unresolvable mutation receiver on sensitive variable '{root}'",
                                    category=ViolationCategory.MISSING_SCRUB.value
                                ))
                    else:
                        if receiver_name not in state.points_to:
                            state.points_to[receiver_name] = set()
                        state.points_to[receiver_name].update(roots)
                return state

            elif method_name in ("pop", "popitem", "remove", "discard", "clear"):
                if receiver_name is not None:
                    roots = state.points_to.get(receiver_name, set())
                    if roots:
                        if method_name == "clear":
                            state.points_to.pop(receiver_name, None)
                        else:
                            is_static = False
                            if method_name == "pop" and len(n.args) == 1:
                                arg = n.args[0]
                                is_static = isinstance(arg, ast.Constant)
                            elif method_name in ("remove", "discard") and len(n.args) == 1:
                                arg = n.args[0]
                                is_static = isinstance(arg, ast.Constant)

                            if is_static:
                                state.points_to.pop(receiver_name, None)
                            else:
                                for root in roots:
                                    if violations_accumulator is not None:
                                        violations_accumulator.append(Violation(
                                            line_num, "may-alias",
                                            f"unresolvable container key for sensitive variable '{root}'",
                                            category=ViolationCategory.MISSING_SCRUB.value
                                        ))

        is_zeroize = False
        zeroizer_by_name = {z.function: z for z in getattr(contract, 'zeroizers', ())}
        zeroizer_key = next((name for name in _call_name_variants(call_name) if name in zeroizer_by_name), "")
        if zeroizer_key:
            z = zeroizer_by_name[zeroizer_key]
            if z.target_argument_index < len(n.args):
                zeroized_roots = _resolve_roots(n.args[z.target_argument_index], state.points_to, contract)
                for root in zeroized_roots:
                    is_zeroize = True
                    state.buffer_states[root] = TypestateValue.CLEARED

        if not is_zeroize and (call_name in ZEROIZE_CALLS or _call_basename(call_name) in ZEROIZE_CALLS):
            for arg in _call_args_and_keywords(n):
                zeroized_roots = _resolve_roots(arg, state.points_to, contract)
                for root in zeroized_roots:
                    is_zeroize = True
                    state.buffer_states[root] = TypestateValue.CLEARED

        if is_zeroize:
            return state

        if call_name == "free" or _call_basename(call_name) == "free":
            for arg in _call_args_and_keywords(n):
                roots = _resolve_roots(arg, state.points_to, contract)
                for root in roots:
                    buffer = next((b for b in contract.sensitive_buffers if b.name == root), None)
                    if buffer and buffer.must_zeroize:
                        if state.buffer_states.get(root) not in (TypestateValue.CLEARED, TypestateValue.UNINIT) and violations_accumulator is not None:
                            violations_accumulator.append(Violation(
                                line_num, "missing-zeroize",
                                f"buffer '{root}' freed without prior scrubbing",
                                category=ViolationCategory.MISSING_SCRUB.value
                            ))
                    state.buffer_states[root] = TypestateValue.UNINIT
            return state

        source_by_name = {s.function: s for s in getattr(contract, 'sources', ())}
        source_key = next((name for name in _call_name_variants(call_name) if name in source_by_name), "")
        if source_key:
            src = source_by_name[source_key]
            if src.argument_index < len(n.args):
                used_roots = _resolve_roots(n.args[src.argument_index], state.points_to, contract)
                for root in used_roots:
                    if state.buffer_states.get(root) in (TypestateValue.UNINIT, TypestateValue.BOTTOM):
                        state.buffer_states[root] = TypestateValue.SECURE

        used_roots = set()
        for arg in _call_args_and_keywords(n):
            used_roots.update(_resolve_roots(arg, state.points_to, contract))

        # Detect use-after-zeroize before classifying the call as a sink. This
        # gives USENIX evaluation cases a distinct lifecycle category rather than
        # folding them into generic post-exposure use.
        for buffer in contract.sensitive_buffers:
            if buffer.name in used_roots:
                buf_state = state.buffer_states.get(buffer.name, TypestateValue.UNINIT)
                # A zeroized buffer may later be reused for public data. Flag
                # use-after-zeroize only when the zeroized secret is consumed by
                # a security-critical operation that the contract names as a
                # transform or approved secret sink. Generic/public reuse is not
                # itself a violation unless the program re-taints the buffer.
                critical_after_zeroize = (
                    resolve_tool_match(call_name, getattr(buffer, 'allowed_transforms', ()), ()) == 'allowed'
                    or resolve_tool_match(call_name, buffer.allowed_sinks, ()) == 'allowed'
                )
                if (buf_state == TypestateValue.CLEARED and
                        getattr(buffer, 'forbid_use_after_zeroize', True) and
                        critical_after_zeroize):
                    if violations_accumulator is not None:
                        violations_accumulator.append(Violation(
                            line_num, "use-after-zeroize",
                            f"variable '{buffer.name}' is used after zeroization",
                            category=ViolationCategory.USE_AFTER_ZEROIZE.value
                        ))
                    state.buffer_states[buffer.name] = TypestateValue.TOP

        sink_by_name = {s.function: s for s in getattr(contract, 'sinks', ())}
        for buffer in contract.sensitive_buffers:
            if buffer.name not in used_roots:
                continue

            buf_state = state.buffer_states.get(buffer.name, TypestateValue.UNINIT)

            match_result = resolve_tool_match(call_name, buffer.allowed_sinks, buffer.forbidden_sinks)
            is_transport = any(candidate == buffer.transport_sink for candidate in _call_name_variants(call_name))
            sink_key = next((name for name in _call_name_variants(call_name) if name in sink_by_name), "")
            is_forbidden = (match_result == 'forbidden' or
                           (sink_key and sink_by_name[sink_key].forbidden_taints))
            is_allowed = (match_result == 'allowed')

            if is_forbidden or is_transport or is_allowed:
                state.ever_used_in_sink.add(buffer.name)

                if is_forbidden:
                    if buf_state in (TypestateValue.SECURE, TypestateValue.EXPOSED, TypestateValue.POSSIBLY_UNSCRUBBED, TypestateValue.TOP):
                        if violations_accumulator is not None:
                            violations_accumulator.append(Violation(
                                line_num, "forbidden-sink",
                                f"variable '{buffer.name}' reaches forbidden tool '{call_name}'",
                                category=ViolationCategory.FORBIDDEN_SINK.value
                            ))
                    if buf_state in (TypestateValue.SECURE, TypestateValue.UNINIT, TypestateValue.BOTTOM):
                        state.buffer_states[buffer.name] = TypestateValue.EXPOSED
                elif is_transport:
                    if buf_state in (TypestateValue.SECURE, TypestateValue.UNINIT, TypestateValue.BOTTOM):
                        if violations_accumulator is not None:
                            violations_accumulator.append(Violation(
                                line_num, "transport-bypass",
                                f"variable '{buffer.name}' reaches transport tool '{call_name}' without its approved wrapper",
                                category=ViolationCategory.TRANSPORT_BYPASS.value
                            ))
                        state.buffer_states[buffer.name] = TypestateValue.EXPOSED
                elif is_allowed:
                    if buf_state in (TypestateValue.SECURE, TypestateValue.UNINIT, TypestateValue.BOTTOM):
                        state.buffer_states[buffer.name] = TypestateValue.EXPOSED

            if buf_state == TypestateValue.EXPOSED and buffer.forbid_post_send_use:
                if violations_accumulator is not None:
                    violations_accumulator.append(Violation(
                        line_num, "post-send-use",
                        f"variable '{buffer.name}' is used again after tool exposure",
                        category=ViolationCategory.POST_EXPOSURE_USE.value
                    ))

            callee_summary = summaries.get(call_name) or summaries.get(_call_basename(call_name))
            if callee_summary:
                _apply_helper_summary_new(
                    violations_accumulator,
                    state.buffer_states,
                    buffer,
                    _call_args_and_keywords(n),
                    state.points_to,
                    contract,
                    call_name,
                    line_num,
                    callee_summary,
                    state.ever_used_in_sink
                )

        return state

    else:
        for name, value in ast.iter_fields(n):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        state = _eval_node(state, item, contract, summaries, violations_accumulator, line_num)
            elif isinstance(value, ast.AST):
                state = _eval_node(state, value, contract, summaries, violations_accumulator, line_num)
        return state


def _apply_transfer(
    state: AnalysisState,
    node: ast.AST,
    contract: Contract,
    summaries: dict[str, FunctionSummary],
    violations_accumulator: list[Violation] | None,
    line_num: int
) -> AnalysisState:
    return _eval_node(state.copy(), node, contract, summaries, violations_accumulator, line_num)


def _verify_function_scope(contract: Contract, function_scope: FunctionScope, summaries: dict[str, FunctionSummary]) -> list[Violation]:
    cfg = build_cfg(function_scope.node)

    initial_buffer_states = {}
    for buffer in contract.sensitive_buffers:
        parts = buffer.name.replace("->", ".").split(".")
        if buffer.name in function_scope.parameter_names or any(part in function_scope.parameter_names for part in parts):
            initial_buffer_states[buffer.name] = TypestateValue.SECURE
        else:
            initial_buffer_states[buffer.name] = TypestateValue.UNINIT

    initial_points_to = {}
    for buffer in contract.sensitive_buffers:
        initial_points_to[buffer.name] = {buffer.name}

    entry_state = AnalysisState(
        buffer_states=initial_buffer_states,
        points_to=initial_points_to,
        ever_used_in_sink=set()
    )

    in_states = {block_id: AnalysisState.bottom(contract) for block_id in cfg.blocks}
    out_states = {block_id: AnalysisState.bottom(contract) for block_id in cfg.blocks}
    in_states[cfg.entry_id] = entry_state

    worklist = deque([cfg.entry_id])
    iters = 0
    while worklist and iters < 1000:
        iters += 1
        block_id = worklist.popleft()
        block = cfg.blocks[block_id]

        if block_id != cfg.entry_id:
            curr_state = AnalysisState.bottom(contract)
            for pred_id in block.predecessors:
                curr_state = curr_state.join(out_states[pred_id])
            in_states[block_id] = curr_state

        curr_state = in_states[block_id].copy()
        last_line = function_scope.node.lineno
        for stmt in block.stmts:
            last_line = stmt.lineno if hasattr(stmt, 'lineno') else last_line
            curr_state = _apply_transfer(curr_state, stmt, contract, summaries, None, last_line)

        if (out_states[block_id].buffer_states != curr_state.buffer_states or
            out_states[block_id].points_to != curr_state.points_to or
            out_states[block_id].ever_used_in_sink != curr_state.ever_used_in_sink):
            
            out_states[block_id] = curr_state
            for succ_id in block.successors:
                if succ_id not in worklist:
                    worklist.append(succ_id)

    if worklist:
        raise RuntimeError("CFG typestate worklist failed to converge within 1000 iterations")

    violations: list[Violation] = []
    for block_id, block in cfg.blocks.items():
        curr_state = in_states[block_id].copy()
        last_line = function_scope.node.lineno
        for stmt in block.stmts:
            last_line = stmt.lineno if hasattr(stmt, 'lineno') else last_line
            curr_state = _apply_transfer(curr_state, stmt, contract, summaries, violations, last_line)

    exit_state = in_states[cfg.exit_id]
    last_line = function_scope.node.lineno
    for block in cfg.blocks.values():
        for stmt in block.stmts:
            if hasattr(stmt, 'lineno'):
                last_line = max(last_line, stmt.lineno)

    for buffer in contract.sensitive_buffers:
        if buffer.must_zeroize:
            final_val = exit_state.buffer_states.get(buffer.name, TypestateValue.UNINIT)
            if final_val not in (TypestateValue.CLEARED, TypestateValue.UNINIT):
                violations.append(Violation(
                    last_line, "missing-zeroize",
                    f"variable '{buffer.name}' is not scrubbed after its last sensitive tool use",
                    category=ViolationCategory.MISSING_SCRUB.value
                ))

    return violations

