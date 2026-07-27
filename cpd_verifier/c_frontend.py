from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .model import Contract, ViolationCategory
from .sinks import matches_pattern


@dataclass(frozen=True)
class CViolation:
    file: str
    line: int
    code: str
    message: str
    category: str = ""


_DECL_RE = re.compile(r"\b(?:uint8_t|unsigned\s+char|char|void|size_t|int|const\s+uint8_t)\s*(?:\*+\s*)?([A-Za-z_][A-Za-z0-9_]*)\b")
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:(?:\.|->)[A-Za-z_][A-Za-z0-9_]*)?)\s*\((.*)\)\s*;?")
_ASSIGN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:(?:\.|->)[A-Za-z_][A-Za-z0-9_]*)?)\s*=\s*(.+?)\s*;")
_FUNC_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)")


def verify_c_file(contract: Contract, source_path: str | Path) -> list[CViolation]:
    path = Path(source_path)
    return verify_c_source(contract, path.read_text(encoding="utf-8"), filename=str(path))


def verify_c_source(contract: Contract, source: str, filename: str = "<memory>.c") -> list[CViolation]:
    """A small dependency-free C lifecycle scanner for artifact examples.

    This does not claim full C soundness. It gives the default artifact path a
    reproducible C/embedded checker even when libclang is unavailable, while the
    optional libclang path remains available for richer parsing.
    """
    clean_source = _strip_comments(source)
    aliases: dict[str, set[str]] = {b.name: {b.name} for b in contract.sensitive_buffers}
    states: dict[str, str] = {b.name: "secret" for b in contract.sensitive_buffers}
    ever_used: set[str] = set()
    violations: list[CViolation] = []

    for lineno, line in enumerate(clean_source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Variable declarations for contract roots allocate/introduce sensitive buffers.
        for name in _declared_names(stripped):
            for buf in contract.sensitive_buffers:
                if _name_matches_buffer(name, buf.name):
                    aliases.setdefault(name, set()).add(buf.name)
                    states[buf.name] = "secret"
                    ever_used.add(buf.name)

        # Simple assignment aliases: p = shared_secret; ctx.shared_secret = shared_secret;
        assign = _ASSIGN_RE.search(stripped)
        if assign:
            lhs, rhs = assign.group(1), assign.group(2)
            roots = _roots_in_text(rhs, aliases, contract)
            # If assigning result of allowed transform, do not alias target to raw input.
            call = _CALL_RE.search(rhs.strip())
            is_transform = False
            if call:
                call_name = call.group(1)
                is_transform = _is_allowed_transform(call_name, roots, contract)
            if roots and not is_transform:
                aliases[lhs] = set(roots)

        call = _CALL_RE.search(stripped)
        if not call:
            continue
        call_name = call.group(1)
        args_text = call.group(2)
        arg_roots = _roots_in_text(args_text, aliases, contract)

        # Function declarations can look like calls; ignore common definition lines.
        if "{" in stripped and _FUNC_RE.search(stripped):
            continue

        for buf in contract.sensitive_buffers:
            if buf.name not in arg_roots:
                continue
            state = states.get(buf.name, "secret")
            is_zeroize = _call_matches(call_name, _zeroizers(contract))
            if is_zeroize:
                states[buf.name] = "zeroized"
                continue

            critical_after_zeroize = (
                _is_allowed_transform(call_name, {buf.name}, contract)
                or _call_matches(call_name, buf.allowed_sinks)
            )
            if state == "zeroized" and getattr(buf, "forbid_use_after_zeroize", True) and critical_after_zeroize:
                violations.append(CViolation(
                    filename, lineno, "use-after-zeroize",
                    f"variable '{buf.name}' is used after zeroization in call '{call_name}'",
                    ViolationCategory.USE_AFTER_ZEROIZE.value,
                ))
                states[buf.name] = "unknown"
                continue

            if _is_allowed_transform(call_name, {buf.name}, contract):
                ever_used.add(buf.name)
                continue

            if _call_matches(call_name, buf.forbidden_sinks):
                ever_used.add(buf.name)
                violations.append(CViolation(
                    filename, lineno, "forbidden-sink",
                    f"variable '{buf.name}' reaches forbidden sink '{call_name}'",
                    ViolationCategory.FORBIDDEN_SINK.value,
                ))
                states[buf.name] = "exposed"
                continue

            if buf.transport_sink and _call_matches(call_name, (buf.transport_sink,)):
                ever_used.add(buf.name)
                violations.append(CViolation(
                    filename, lineno, "transport-bypass",
                    f"variable '{buf.name}' reaches raw transport '{call_name}'",
                    ViolationCategory.TRANSPORT_BYPASS.value,
                ))
                states[buf.name] = "exposed"
                continue

            if _call_matches(call_name, buf.allowed_sinks):
                ever_used.add(buf.name)
                states[buf.name] = "exposed"
                continue

            if state == "exposed" and buf.forbid_post_send_use:
                violations.append(CViolation(
                    filename, lineno, "post-send-use",
                    f"variable '{buf.name}' is used after exposure in call '{call_name}'",
                    ViolationCategory.POST_EXPOSURE_USE.value,
                ))

    if getattr(contract, "protection_domains", None) is not None:
        from .protection_domain import verify_c_protection_domains
        for v in verify_c_protection_domains(contract, source, filename=filename):
            violations.append(CViolation(filename, v.line, v.code, v.message, v.category))

    last_line = len(clean_source.splitlines()) or 1
    for buf in contract.sensitive_buffers:
        if buf.must_zeroize and states.get(buf.name) not in ("zeroized", "uninit"):
            # Report only roots that were introduced/used. This keeps clean negative
            # files with unused contract roots from being noisy.
            if buf.name in ever_used:
                violations.append(CViolation(
                    filename, last_line, "missing-zeroize",
                    f"variable '{buf.name}' is not zeroized before function exit",
                    ViolationCategory.MISSING_SCRUB.value,
                ))
    return violations


def _strip_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    source = re.sub(r"//.*", "", source)
    return source


def _declared_names(line: str) -> list[str]:
    return [m.group(1) for m in _DECL_RE.finditer(line)]


def _name_matches_buffer(name: str, buffer_name: str) -> bool:
    parts = buffer_name.replace("->", ".").split(".")
    return name == buffer_name or name in parts


def _roots_in_text(text: str, aliases: dict[str, set[str]], contract: Contract) -> set[str]:
    roots: set[str] = set()
    raw_tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|->)[A-Za-z_][A-Za-z0-9_]*)?", text))
    tokens: set[str] = set()
    for token in raw_tokens:
        tokens.add(token)
        tokens.add(token.replace("->", "."))
        for part in token.replace("->", ".").split("."):
            tokens.add(part)

    for token in tokens:
        roots.update(aliases.get(token, set()))
        roots.update(aliases.get(token.replace(".", "->"), set()))

    for buf in contract.sensitive_buffers:
        canonical = buf.name.replace("->", ".")
        parts = canonical.split(".")
        if buf.name in tokens or canonical in tokens or any(part in tokens for part in parts):
            roots.add(buf.name)
    return roots


def _call_matches(call_name: str, patterns: tuple[str, ...]) -> bool:
    return matches_pattern(call_name, patterns)


def _is_allowed_transform(call_name: str, roots: set[str], contract: Contract) -> bool:
    for buf in contract.sensitive_buffers:
        if buf.name in roots and _call_matches(call_name, getattr(buf, "allowed_transforms", ())):
            return True
    return False


def _zeroizers(contract: Contract) -> tuple[str, ...]:
    defaults = ("secure_zeroize", "explicit_bzero", "mbedtls_platform_zeroize", "bzero")
    configured = tuple(z.function for z in getattr(contract, "zeroizers", ()))
    return tuple(dict.fromkeys(configured + defaults))
