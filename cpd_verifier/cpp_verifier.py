"""
CPDVerifier C/C++ Verifier — libclang-based AST analysis for ESP-IDF edge stacks.

Uses Python bindings for libclang to parse C/C++ source files and verify
privacy lifecycle compliance against JSON contracts.

Design decisions (§4):
- Optional dependency: Python clang bindings plus a native libclang installation.
- In-scope: Plain functions, structs, and variable declarations typical of
  ESP-IDF drivers and firmware handlers.
- Out-of-scope: C++ templates, heavy macro expansion, and constexpr
  metaprogramming. These are documented as limitations.
- Path-sensitivity: This verifier is a simpler intraprocedural traversal
  over the AST without the full path-sensitive CFG typestate tracking of
  the Python verifier. This asymmetry is documented in 5_implementation.tex.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import os
import platform
import shutil
import glob

try:
    from clang.cindex import (
        Index, TranslationUnit, CursorKind, Cursor, TokenKind, Config,
        LibclangError,
    )
    _CLANG_BINDINGS_AVAILABLE = True
except ImportError:
    Index = TranslationUnit = CursorKind = Cursor = TokenKind = Config = None  # type: ignore
    LibclangError = Exception  # type: ignore
    _CLANG_BINDINGS_AVAILABLE = False


def _candidate_libclang_files() -> list[str]:
    """Return likely native libclang locations across Linux/macOS/Windows.

    The Python ``clang`` package provides bindings only. On Linux/RPi4 a native
    ``libclang`` shared library is usually installed by ``libclang-dev`` or a
    versioned LLVM package. This helper makes the artifact less fragile by
    discovering common native library locations automatically.
    """
    candidates: list[str] = []
    env_file = os.environ.get("LIBCLANG_LIBRARY_FILE")
    if env_file:
        candidates.append(env_file)

    # pip package may bundle libclang on Windows.
    try:
        import clang  # type: ignore
        clang_path = Path(clang.__file__).parent
        candidates.extend(str(p) for p in [
            clang_path / "native" / "libclang.dll",
            clang_path / "native" / "libclang.so",
            clang_path / "native" / "libclang.dylib",
        ])
    except Exception:
        pass

    # Common Debian/Ubuntu/Raspberry Pi OS package locations.
    candidates.extend(glob.glob("/usr/lib/llvm-*/lib/libclang.so*"))
    candidates.extend(glob.glob("/usr/lib/*/libclang.so*"))
    candidates.extend(glob.glob("/usr/local/opt/llvm/lib/libclang.dylib"))
    candidates.extend(glob.glob("/opt/homebrew/opt/llvm/lib/libclang.dylib"))

    # Common Windows LLVM install locations.
    candidates.extend(glob.glob(r"C:\Program Files\LLVM\bin\libclang.dll"))
    candidates.extend(glob.glob(r"C:\Program Files (x86)\LLVM\bin\libclang.dll"))

    seen: set[str] = set()
    out: list[str] = []
    for item in candidates:
        if item and item not in seen and Path(item).exists():
            seen.add(item)
            out.append(item)
    # Prefer latest versioned LLVM path when several are installed.
    return sorted(out, reverse=True)


def _configure_native_libclang() -> str | None:
    if not _CLANG_BINDINGS_AVAILABLE or Config is None:
        return None
    # Respect an explicit configuration first.
    for candidate in _candidate_libclang_files():
        try:
            Config.set_library_file(candidate)
            return candidate
        except Exception:
            continue
    env_path = os.environ.get("LIBCLANG_LIBRARY_PATH")
    if env_path:
        try:
            Config.set_library_path(env_path)
            return env_path
        except Exception:
            pass
    return None


_CONFIGURED_LIBCLANG = _configure_native_libclang()


def _probe_libclang() -> tuple[bool, str]:
    if not _CLANG_BINDINGS_AVAILABLE or Index is None:
        return False, "python clang bindings are not installed"
    try:
        idx = Index.create()
        # Accessing repr is enough to keep linters quiet and ensure object exists.
        repr(idx)
        return True, "ok"
    except Exception as exc:
        return False, f"native libclang is not loadable: {exc}"


LIBCLANG_AVAILABLE, _LIBCLANG_REASON = _probe_libclang()
_WARNED_FALLBACK = False


def libclang_status() -> dict[str, object]:
    """Return machine-readable status for artifact scripts and README checks."""
    return {
        "bindings_available": _CLANG_BINDINGS_AVAILABLE,
        "native_available": LIBCLANG_AVAILABLE,
        "configured_library": _CONFIGURED_LIBCLANG or "",
        "reason": _LIBCLANG_REASON,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "clang_binary": shutil.which("clang") or "",
        "require_env": os.environ.get("CPD_VERIFIER_REQUIRE_LIBCLANG", ""),
    }


def _require_libclang() -> bool:
    return os.environ.get("CPD_VERIFIER_REQUIRE_LIBCLANG", "").lower() in {"1", "true", "yes", "on"}


def _fallback_or_raise(reason: str):
    global _WARNED_FALLBACK
    if _require_libclang():
        raise RuntimeError(
            "libclang was required for this run, but it is unavailable or failed: "
            f"{reason}. Run scripts/check_libclang.py and install native libclang "
            "plus Python clang bindings before retrying."
        )
    if not _WARNED_FALLBACK:
        logger.warning("libclang not available; using dependency-free C scanner fallback (%s)", reason)
        _WARNED_FALLBACK = True

from .model import Contract, BufferState, BufferContract, ViolationCategory
from .c_frontend import CViolation, verify_c_file, verify_c_source
from .sinks import matches_pattern


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CppViolation:
    """A violation found in C/C++ source code."""
    file: str
    line: int
    code: str
    message: str
    category: str = ""


# Constructs that are explicitly out-of-scope
OUT_OF_SCOPE_KINDS = set()
if LIBCLANG_AVAILABLE:
    OUT_OF_SCOPE_KINDS = {
        CursorKind.CLASS_TEMPLATE,
        CursorKind.CLASS_TEMPLATE_PARTIAL_SPECIALIZATION,
        CursorKind.FUNCTION_TEMPLATE,
    }


ZEROIZE_CALLS_C = {
    # Defaults only. Contract-specific zeroizers are added by _zeroizer_names().
    # Deliberately keep memset out of the default trusted set: it may be
    # optimized away in security-sensitive code unless wrapped by a preserved
    # primitive that the contract explicitly names.
    "secure_zeroize", "explicit_bzero", "bzero", "SecureZeroMemory",
    "mbedtls_platform_zeroize", "cpd_verifier_zeroize",
}


def verify_cpp_file(contract: Contract, source_path: str | Path,
                    extra_args: list[str] | None = None) -> list[CppViolation]:
    """Verify a C/C++ source file against a privacy contract.

    Args:
        contract: The privacy contract to verify against.
        source_path: Path to the C/C++ source file.
        extra_args: Optional extra compiler arguments (e.g., include paths).

    Returns:
        List of violations found.
    """
    if not LIBCLANG_AVAILABLE:
        _fallback_or_raise(_LIBCLANG_REASON)
        return verify_c_file(contract, source_path)

    source_path = Path(source_path)
    if not source_path.exists():
        return []

    args = extra_args or []
    # Add common ESP-IDF include path patterns
    args.extend(["-std=c11", "-DESP_PLATFORM"])

    index = Index.create()
    try:
        tu = index.parse(
            str(source_path),
            args=args,
            options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
        )
    except Exception as e:
        _fallback_or_raise(f"failed to parse {source_path}: {e}")
        return verify_c_file(contract, source_path)

    violations: list[CppViolation] = []
    _walk_translation_unit(tu.cursor, contract, str(source_path), violations)
    return violations


def verify_cpp_source(contract: Contract, source: str,
                      filename: str = "test.c") -> list[CppViolation]:
    """Verify C/C++ source code string against a privacy contract.

    Useful for unit testing without actual files.
    """
    if not LIBCLANG_AVAILABLE:
        _fallback_or_raise(_LIBCLANG_REASON)
        return verify_c_source(contract, source, filename=filename)

    lang_args = ["-x", "c++", "-std=c++17"] if filename.endswith((".cpp", ".hpp", ".cc", ".cxx")) else ["-std=c11"]
    index = Index.create()
    try:
        tu = index.parse(
            filename,
            args=lang_args,
            unsaved_files=[(filename, source)],
            options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
        )
    except Exception as e:
        _fallback_or_raise(f"failed to parse source with libclang: {e}")
        return verify_c_source(contract, source, filename=filename)

    violations: list[CppViolation] = []
    _walk_translation_unit(tu.cursor, contract, filename, violations)
    return violations


def _walk_translation_unit(cursor: Any, contract: Contract,
                           source_file: str,
                           violations: list[CppViolation]) -> None:
    """Walk the AST and verify each function definition."""
    if not LIBCLANG_AVAILABLE:
        return

    for child in cursor.get_children():
        # Skip out-of-scope constructs (templates, macros)
        if child.kind in OUT_OF_SCOPE_KINDS:
            loc = child.location
            logger.info(
                f"Skipping out-of-scope {child.kind.name} "
                f"'{child.spelling}' at {loc.file}:{loc.line}"
            )
            continue

        if child.kind == CursorKind.FUNCTION_DECL and child.is_definition():
            # Only analyze functions in the target file
            if child.location.file and str(child.location.file) == source_file:
                _verify_function(child, contract, source_file, violations)

        # Recurse into namespaces and structs (but not templates)
        elif child.kind in (CursorKind.NAMESPACE, CursorKind.STRUCT_DECL,
                            CursorKind.TRANSLATION_UNIT):
            _walk_translation_unit(child, contract, source_file, violations)


def _verify_function(func_cursor: Any, contract: Contract,
                     source_file: str,
                     violations: list[CppViolation]) -> None:
    """Verify a single C/C++ function against the contract.

    This is a simpler intraprocedural analysis: sequential traversal
    of statements, tracking variable state without full CFG construction.
    """
    if not LIBCLANG_AVAILABLE:
        return

    # Build variable state tracking
    buffer_states: dict[str, BufferState] = {}
    aliases: dict[str, set[str]] = {}  # var_name -> set of buffer roots
    ever_used: set[str] = set()

    # Map contract buffer names
    param_names = []
    for arg in func_cursor.get_arguments():
        param_names.append(arg.spelling)

    for buffer in contract.sensitive_buffers:
        parts = buffer.name.replace("->", ".").split(".")
        if buffer.name in param_names or any(p in param_names for p in parts):
            buffer_states[buffer.name] = BufferState.ALLOCATED
        else:
            buffer_states[buffer.name] = BufferState.UNALLOCATED
        aliases[buffer.name] = {buffer.name}

    # Walk the function body
    _walk_function_body(func_cursor, contract, source_file, violations,
                        buffer_states, aliases, ever_used)

    # Check for missing zeroization at scope exit
    for buffer in contract.sensitive_buffers:
        if (buffer.must_zeroize and
                buffer.name in ever_used and
                buffer_states.get(buffer.name) in (BufferState.ALLOCATED, BufferState.SENT)):
            violations.append(CppViolation(
                file=source_file,
                line=func_cursor.extent.end.line,
                code="missing-zeroize",
                message=f"variable '{buffer.name}' not scrubbed at end of '{func_cursor.spelling}'",
                category=ViolationCategory.MISSING_SCRUB.value,
            ))


def _walk_function_body(cursor: Any, contract: Contract,
                        source_file: str,
                        violations: list[CppViolation],
                        buffer_states: dict[str, BufferState],
                        aliases: dict[str, set[str]],
                        ever_used: set[str]) -> None:
    """Recursively walk function body, tracking state."""
    if not LIBCLANG_AVAILABLE:
        return

    for child in cursor.get_children():
        if child.kind == CursorKind.CALL_EXPR:
            call_name = child.spelling or _extract_call_name(child)

            # Check for configured zeroization calls before any post-exposure
            # logic.  This is essential for good patterns such as
            # tls_send_encrypted(session_key, ...); secure_zeroize(session_key, ...).
            if _matches_any(call_name, _zeroizer_names(contract)):
                for arg_cursor in child.get_arguments():
                    arg_name = _extract_var_name(arg_cursor)
                    roots = _resolve_c_roots(arg_name, aliases, contract)
                    for root in roots:
                        ever_used.add(root)
                        buffer_states[root] = BufferState.ZEROIZED
                continue

            # Check for free() calls
            if call_name == "free":
                for arg_cursor in child.get_arguments():
                    arg_name = _extract_var_name(arg_cursor)
                    roots = _resolve_c_roots(arg_name, aliases, contract)
                    for root in roots:
                        buf = next((b for b in contract.sensitive_buffers if b.name == root), None)
                        if buf and buffer_states.get(root) in (BufferState.ALLOCATED, BufferState.SENT) and buf.must_zeroize:
                            violations.append(CppViolation(
                                file=source_file,
                                line=child.location.line,
                                code="missing-zeroize",
                                message=f"buffer '{root}' freed without prior scrubbing",
                                category=ViolationCategory.MISSING_SCRUB.value,
                            ))
                        buffer_states[root] = BufferState.UNALLOCATED
                continue

            # Check against contract transforms and sinks.  The C/C++ path is
            # intentionally conservative, but it must distinguish three cases:
            # (1) allowed cryptographic transforms (e.g., shared_secret -> KDF),
            # (2) allowed exposure/use wrappers (e.g., encrypted send), and
            # (3) forbidden raw sinks (e.g., logging, UART, file, raw socket).
            for arg_cursor in child.get_arguments():
                arg_name = _extract_var_name(arg_cursor)
                roots = _resolve_c_roots(arg_name, aliases, contract)

                for root in roots:
                    buf = next((b for b in contract.sensitive_buffers if b.name == root), None)
                    if not buf:
                        continue

                    state = buffer_states.get(root)
                    is_transform = _matches_any(call_name, getattr(buf, "allowed_transforms", ()))
                    is_forbidden = _matches_any(call_name, buf.forbidden_sinks)
                    is_allowed = _matches_any(call_name, buf.allowed_sinks)

                    if is_transform or is_forbidden or is_allowed:
                        ever_used.add(root)

                    if state == BufferState.ZEROIZED and getattr(buf, "forbid_use_after_zeroize", True):
                        if is_transform or is_forbidden or is_allowed:
                            violations.append(CppViolation(
                                file=source_file,
                                line=child.location.line,
                                code="use-after-zeroize",
                                message=f"variable '{root}' used after zeroization in call '{call_name}'",
                                category=ViolationCategory.USE_AFTER_ZEROIZE.value,
                            ))
                            continue

                    if is_transform:
                        # A transform consumes the raw secret but does not count as
                        # public exposure. The destination variable is tracked by
                        # its own contract entry when present.
                        if state == BufferState.UNALLOCATED:
                            buffer_states[root] = BufferState.ALLOCATED
                        continue

                    if is_forbidden and state in (BufferState.ALLOCATED, BufferState.SENT):
                        violations.append(CppViolation(
                            file=source_file,
                            line=child.location.line,
                            code="forbidden-sink",
                            message=f"variable '{root}' reaches forbidden tool '{call_name}'",
                            category=ViolationCategory.FORBIDDEN_SINK.value,
                        ))
                        buffer_states[root] = BufferState.SENT
                        continue

                    if is_allowed and state == BufferState.ALLOCATED:
                        buffer_states[root] = BufferState.SENT
                        continue

                    if state == BufferState.SENT and buf.forbid_post_send_use:
                        violations.append(CppViolation(
                            file=source_file,
                            line=child.location.line,
                            code="post-send-use",
                            message=f"variable '{root}' used after tool exposure",
                            category=ViolationCategory.POST_EXPOSURE_USE.value,
                        ))

        elif child.kind == CursorKind.VAR_DECL:
            # Track variable assignments
            var_name = child.spelling
            for buffer in contract.sensitive_buffers:
                parts = buffer.name.replace("->", ".").split(".")
                if var_name == buffer.name or var_name in parts:
                    buffer_states[buffer.name] = BufferState.ALLOCATED
                    ever_used.add(buffer.name)
            for init_child in child.get_children():
                ref_name = _extract_var_name(init_child)
                roots = _resolve_c_roots(ref_name, aliases, contract)
                if roots:
                    aliases[var_name] = roots

        # Recurse into compound statements, if/else, etc.
        _walk_function_body(child, contract, source_file, violations,
                            buffer_states, aliases, ever_used)


def _extract_call_name(cursor: Any) -> str:
    """Extract the function name from a CALL_EXPR cursor."""
    if not LIBCLANG_AVAILABLE:
        return ""
    for child in cursor.get_children():
        if child.kind == CursorKind.DECL_REF_EXPR:
            return child.spelling
    return cursor.spelling or ""


def _extract_var_name(cursor: Any) -> str:
    """Extract the variable name from an expression cursor."""
    if not LIBCLANG_AVAILABLE:
        return ""
    if cursor.kind == CursorKind.DECL_REF_EXPR:
        return cursor.spelling
    # Walk children for nested references
    for child in cursor.get_children():
        name = _extract_var_name(child)
        if name:
            return name
    return cursor.spelling or ""


def _resolve_c_roots(var_name: str, aliases: dict[str, set[str]],
                     contract: Contract) -> set[str]:
    """Resolve a variable name to its contract buffer roots."""
    roots = set()
    for buf in contract.sensitive_buffers:
        parts = buf.name.replace("->", ".").split(".")
        if var_name == buf.name or var_name in parts:
            roots.add(buf.name)
    if var_name in aliases:
        roots.update(aliases[var_name])
    return roots


def _matches_any(call_name: str, patterns: tuple[str, ...] | set[str]) -> bool:
    return matches_pattern(call_name, tuple(patterns))


def _zeroizer_names(contract: Contract) -> tuple[str, ...]:
    configured = tuple(z.function for z in getattr(contract, "zeroizers", ()))
    return tuple(dict.fromkeys(configured + tuple(ZEROIZE_CALLS_C)))
