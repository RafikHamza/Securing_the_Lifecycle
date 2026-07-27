from __future__ import annotations

import ast
import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

from .model import Contract, ProtectionDomainPolicy, ProtectionTransition, ViolationCategory


@dataclass(frozen=True)
class ProtectionDomainViolation:
    line: int
    code: str
    message: str
    category: str = ViolationCategory.PROTECTION_DOMAIN.value


def has_protection_domains(contract: Contract) -> bool:
    return getattr(contract, "protection_domains", None) is not None


def verify_python_protection_domains(contract: Contract, source: str) -> list[ProtectionDomainViolation]:
    """Verify cryptographic protection-domain transitions in Python source.

    This checker is intentionally separate from the classic lifecycle analysis.
    The classic analysis asks whether a value is secret, exposed, or zeroized.
    This checker asks which cryptographic domain a value occupies, e.g. ``raw``,
    ``ckks_ciphertext[pk_A]``, ``mlkem_shared_secret``, or ``session_key``.
    """
    policy = contract.protection_domains
    if policy is None:
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [ProtectionDomainViolation(
            getattr(exc, "lineno", 0) or 0,
            "syntax-error",
            f"source could not be parsed for protection-domain checking: {exc.msg}",
            category="syntax-error",
        )]

    env = _initial_domain_env(contract, policy)
    violations: list[ProtectionDomainViolation] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            assigned_domain = _domain_from_expr(node.value, env, policy, violations, getattr(node, "lineno", 0))
            if assigned_domain:
                for target in node.targets:
                    for name in _names_in_ast(target):
                        env[name] = assigned_domain
            else:
                # Plain aliasing: y = x preserves x's protection domain.
                src_names = _names_in_ast(node.value)
                src_domain = next((env[name] for name in src_names if name in env), None)
                if src_domain:
                    for target in node.targets:
                        for name in _names_in_ast(target):
                            env[name] = src_domain
        elif isinstance(node, ast.AnnAssign):
            if node.value is None:
                continue
            assigned_domain = _domain_from_expr(node.value, env, policy, violations, getattr(node, "lineno", 0))
            if assigned_domain:
                for name in _names_in_ast(node.target):
                    env[name] = assigned_domain
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            _check_call_domains(node.value, env, policy, violations, getattr(node, "lineno", 0))
        elif isinstance(node, ast.Return) and node.value is not None:
            _domain_from_expr(node.value, env, policy, violations, getattr(node, "lineno", 0))

    return violations


def _initial_domain_env(contract: Contract, policy: ProtectionDomainPolicy) -> dict[str, str]:
    env = dict(policy.variables)
    for buf in contract.sensitive_buffers:
        env.setdefault(buf.name, policy.variables.get(buf.name, "raw"))
    return env


def _domain_from_expr(
    expr: ast.AST,
    env: dict[str, str],
    policy: ProtectionDomainPolicy,
    violations: list[ProtectionDomainViolation],
    line: int,
) -> str | None:
    if isinstance(expr, ast.Name):
        return env.get(expr.id)
    if isinstance(expr, ast.Attribute):
        return env.get(_attribute_name(expr)) or env.get(expr.attr)
    if isinstance(expr, ast.Call):
        return _check_call_domains(expr, env, policy, violations, line)
    return None


def _check_call_domains(
    call: ast.Call,
    env: dict[str, str],
    policy: ProtectionDomainPolicy,
    violations: list[ProtectionDomainViolation],
    line: int,
) -> str | None:
    call_name = _call_name(call)
    if not call_name:
        return None

    args = list(call.args) + [kw.value for kw in call.keywords]
    arg_domains: list[tuple[int, str, str]] = []
    for idx, arg in enumerate(args):
        for name in _names_in_ast(arg):
            if name in env:
                arg_domains.append((idx, name, env[name]))

    # Transition relation: if a function is declared as a transition, the input
    # must currently inhabit the declared source domain. The assignment target
    # receives the target domain through the return value.
    matching_transitions = _matching_transitions(policy, call_name)
    if matching_transitions:
        selected: str | None = None
        has_valid = False
        for transition in matching_transitions:
            actual_domain = _domain_for_transition_input(args, env, transition)
            if actual_domain is not None and actual_domain == transition.from_domain:
                has_valid = True
                if transition.output == "return":
                    selected = transition.to_domain
                elif transition.output in ("argument", "input", "inout"):
                    if transition.input_argument_index < len(args):
                        for name in _names_in_ast(args[transition.input_argument_index]):
                            if name in env:
                                env[name] = transition.to_domain
                else:
                    selected = transition.to_domain
                break

        if not has_valid:
            first_trans = matching_transitions[0]
            actual_domain = _domain_for_transition_input(args, env, first_trans)
            if actual_domain is not None:
                violations.append(ProtectionDomainViolation(
                    line,
                    "unauthorized-domain-transition",
                    f"call '{call_name}' expects domain '{first_trans.from_domain}' but receives '{actual_domain}'",
                ))
        return selected

    # Sink relation: a domain may have permitted and forbidden observation
    # functions. Forbidden policies override allowed policies.
    for _idx, name, domain in arg_domains:
        forbidden = policy.domain_forbidden_sinks(domain)
        allowed = policy.domain_allowed_sinks(domain)
        if _matches(call_name, forbidden):
            violations.append(ProtectionDomainViolation(
                line,
                "forbidden-domain-sink",
                f"value '{name}' in domain '{domain}' reaches forbidden sink '{call_name}'",
            ))
        elif allowed and _looks_like_observation(call_name, policy) and not _matches(call_name, allowed):
            violations.append(ProtectionDomainViolation(
                line,
                "unauthorized-domain-sink",
                f"value '{name}' in domain '{domain}' reaches unauthorized sink '{call_name}'",
            ))
    return None


def _domain_for_transition_input(args: list[ast.AST], env: dict[str, str], transition: ProtectionTransition) -> str | None:
    if transition.input_argument_index >= len(args):
        return None
    for name in _names_in_ast(args[transition.input_argument_index]):
        if name in env:
            return env[name]
    return None


def _matching_transitions(policy: ProtectionDomainPolicy, call_name: str) -> tuple[ProtectionTransition, ...]:
    variants = _call_variants(call_name)
    return tuple(t for t in policy.transitions if any(_matches(v, (t.function,)) for v in variants))


def _looks_like_observation(call_name: str, policy: ProtectionDomainPolicy) -> bool:
    variants = _call_variants(call_name)
    patterns: list[str] = []
    for sink_policy in policy.allowed_sinks + policy.forbidden_sinks:
        patterns.extend(sink_policy.functions)
    return any(_matches(v, tuple(patterns)) for v in variants)


def _matches(call_name: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        for variant in _call_variants(call_name):
            if fnmatch.fnmatch(variant, pattern):
                return True
    return False


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return _attribute_name(node.func)
    return ""


def _attribute_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _attribute_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _call_variants(call_name: str) -> tuple[str, ...]:
    if not call_name:
        return ()
    base = call_name.rsplit('.', 1)[-1]
    return (call_name,) if base == call_name else (call_name, base)


def _names_in_ast(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            full = _attribute_name(child)
            if full:
                names.add(full)
            names.add(child.attr)
    return names


# ---------------------------------------------------------------------------
# Dependency-free C scanner for protection domains
# ---------------------------------------------------------------------------

_C_ASSIGN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:(?:\.|->)[A-Za-z_][A-Za-z0-9_]*)?)\s*=\s*(.+?)\s*;")
_C_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:(?:\.|->)[A-Za-z_][A-Za-z0-9_]*)?)\s*\((.*)\)\s*;?")
_C_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|->)[A-Za-z_][A-Za-z0-9_]*)?")


def verify_c_protection_domains(contract: Contract, source: str, filename: str = "<memory>.c") -> list[ProtectionDomainViolation]:
    policy = contract.protection_domains
    if policy is None:
        return []
    env = _initial_domain_env(contract, policy)
    violations: list[ProtectionDomainViolation] = []
    clean_source = _strip_c_comments(source)

    for lineno, line in enumerate(clean_source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        assign = _C_ASSIGN_RE.search(stripped)
        if assign:
            lhs, rhs = assign.group(1), assign.group(2)
            call = _C_CALL_RE.search(rhs.strip())
            if call:
                call_name = call.group(1)
                args = _split_args(call.group(2))
                domain = _check_c_call(call_name, args, env, policy, violations, lineno)
                if domain:
                    env[lhs] = domain
            else:
                rhs_domain = next((env[t] for t in _tokens(rhs) if t in env), None)
                if rhs_domain:
                    env[lhs] = rhs_domain
            continue

        call = _C_CALL_RE.search(stripped)
        if call:
            _check_c_call(call.group(1), _split_args(call.group(2)), env, policy, violations, lineno)

    return violations


def _check_c_call(
    call_name: str,
    args: list[str],
    env: dict[str, str],
    policy: ProtectionDomainPolicy,
    violations: list[ProtectionDomainViolation],
    line: int,
) -> str | None:
    transitions = _matching_transitions(policy, call_name)
    if transitions:
        selected: str | None = None
        for transition in transitions:
            if transition.input_argument_index >= len(args):
                continue
            arg_domain = next((env[t] for t in _tokens(args[transition.input_argument_index]) if t in env), None)
            if arg_domain is None:
                continue
            if arg_domain != transition.from_domain:
                violations.append(ProtectionDomainViolation(
                    line,
                    "unauthorized-domain-transition",
                    f"call '{call_name}' expects domain '{transition.from_domain}' but receives '{arg_domain}'",
                ))
                continue

            if transition.output == "return":
                selected = transition.to_domain
            elif transition.output in ("argument", "input", "inout"):
                for name in _tokens(args[transition.input_argument_index]):
                    if name in env:
                        env[name] = transition.to_domain
            else:
                selected = transition.to_domain
        return selected

    for arg in args:
        for name in _tokens(arg):
            domain = env.get(name)
            if not domain:
                continue
            if _matches(call_name, policy.domain_forbidden_sinks(domain)):
                violations.append(ProtectionDomainViolation(
                    line,
                    "forbidden-domain-sink",
                    f"value '{name}' in domain '{domain}' reaches forbidden sink '{call_name}'",
                ))
            elif _looks_like_observation(call_name, policy) and not _matches(call_name, policy.domain_allowed_sinks(domain)):
                violations.append(ProtectionDomainViolation(
                    line,
                    "unauthorized-domain-sink",
                    f"value '{name}' in domain '{domain}' reaches unauthorized sink '{call_name}'",
                ))
    return None


def _tokens(text: str) -> set[str]:
    raw = set(_C_TOKEN_RE.findall(text))
    out: set[str] = set()
    for token in raw:
        out.add(token)
        normalized = token.replace('->', '.')
        out.add(normalized)
        out.update(normalized.split('.'))
    return out


def _split_args(text: str) -> list[str]:
    # Good enough for the small artifact examples; not a full C parser.
    return [item.strip() for item in text.split(',') if item.strip()]


def _strip_c_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    source = re.sub(r"//.*", "", source)
    return source
