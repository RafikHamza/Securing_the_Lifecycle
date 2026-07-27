from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import (
    BufferContract, Contract, SourceSpec, SinkSpec, ZeroizerSpec,
    ProtectionDomainPolicy, ProtectionTransition, DomainSinkPolicy,
)
from .sinks import expand_sink_patterns


class ContractError(ValueError):
    """Raised when a contract file is malformed."""


def load_contract(contract_path: str | Path) -> Contract:
    path = Path(contract_path)
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    return parse_contract(raw)


def parse_contract(raw: dict[str, Any]) -> Contract:
    """Parse v1 or v2 CPDVerifier contracts.

    v1 uses ``buffers``. v2 uses ``secrets`` and adds crypto-lifecycle terms
    such as ``allowed_transforms`` and grouped forbidden sinks (``@logging``).
    The internal representation is normalized to ``Contract`` so older code and
    tests remain valid.
    """
    if not isinstance(raw, dict):
        raise ContractError("contract must be a JSON object")
    if str(raw.get("schema_version", "1.0")).startswith("2") or "secrets" in raw:
        return _parse_contract_v2(raw)
    return _parse_contract_v1(raw)


def _parse_contract_v1(raw: dict[str, Any]) -> Contract:
    module = _require_non_empty_string(raw, "module")
    buffers_raw = raw.get("buffers")
    if not isinstance(buffers_raw, list) or not buffers_raw:
        raise ContractError("contract must define a non-empty 'buffers' list")

    if "backend" in raw:
        raise ContractError(
            "'backend' is no longer supported; declare only real wrapper and transport sinks"
        )

    buffers = tuple(_parse_buffer(buffer_raw) for buffer_raw in buffers_raw)
    sources = tuple(_read_sources(raw.get("sources", [])))
    sinks = tuple(_read_sinks(raw.get("sinks", [])))
    zeroizers = tuple(_read_zeroizers(raw.get("zeroizers", [])))
    protection_domains = _parse_protection_domains(raw.get("protection_domains"))
    return Contract(module=module, buffers=buffers, sources=sources, sinks=sinks, zeroizers=zeroizers, protection_domains=protection_domains)


def _parse_contract_v2(raw: dict[str, Any]) -> Contract:
    module = _string_or_default(raw, "module", "cpd_verifier_v2")
    secrets_raw = raw.get("secrets")
    if not isinstance(secrets_raw, list) or not secrets_raw:
        raise ContractError("v2 contract must define a non-empty 'secrets' list")

    buffers = tuple(_parse_secret_v2(secret_raw) for secret_raw in secrets_raw)

    # Contract-level zeroizers apply to all secrets unless overridden by a secret.
    zeroizer_names: list[str] = []
    for name in _read_string_list(raw, "zeroizers"):
        zeroizer_names.append(name)
    for secret in secrets_raw:
        if isinstance(secret, dict):
            zeroizer_names.extend(_read_string_list(secret, "zeroizers"))
    if not zeroizer_names:
        zeroizer_names = ["secure_zeroize", "explicit_bzero", "mbedtls_platform_zeroize"]
    zeroizers = tuple(ZeroizerSpec(function=name, target_argument_index=0)
                      for name in dict.fromkeys(zeroizer_names))

    sources = tuple(_read_sources(raw.get("sources", [])))
    sinks = tuple(_read_sinks(raw.get("sinks", [])))
    protection_domains = _parse_protection_domains(raw.get("protection_domains"))
    return Contract(module=module, buffers=buffers, sources=sources, sinks=sinks, zeroizers=zeroizers, protection_domains=protection_domains)


def _parse_secret_v2(raw: Any) -> BufferContract:
    if not isinstance(raw, dict):
        raise ContractError("each secret entry must be an object")
    name = _require_non_empty_string(raw, "name")
    element_type = _string_or_default(raw, "element_type", "uint8_t")
    kind = _string_or_default(raw, "kind", "generic_secret")
    must_zeroize = bool(raw.get("must_zeroize", True))
    forbid_post_exposure_use = bool(raw.get("forbid_post_exposure_use", raw.get("forbid_post_send_use", True)))
    forbid_use_after_zeroize = bool(raw.get("forbid_use_after_zeroize", True))
    allowed_sinks = expand_sink_patterns(_read_string_list(raw, "allowed_sinks"))
    forbidden_sinks = expand_sink_patterns(_read_string_list(raw, "forbidden_sinks"))
    allowed_transforms = tuple(_read_string_list(raw, "allowed_transforms"))
    overlap = set(allowed_sinks).intersection(forbidden_sinks)
    if overlap:
        joined = ", ".join(sorted(overlap))
        raise ContractError(f"secret '{name}' declares sinks that are both allowed and forbidden: {joined}")
    return BufferContract(
        name=name,
        element_type=element_type,
        sensitive=bool(raw.get("sensitive", True)),
        must_zeroize=must_zeroize,
        forbid_post_send_use=forbid_post_exposure_use,
        allowed_sinks=allowed_sinks,
        forbidden_sinks=forbidden_sinks,
        transport_sink=str(raw.get("transport_sink", "")).strip(),
        kind=kind,
        allowed_transforms=allowed_transforms,
        forbid_use_after_zeroize=forbid_use_after_zeroize,
    )


def _parse_buffer(raw: Any) -> BufferContract:
    if not isinstance(raw, dict):
        raise ContractError("each buffer entry must be an object")

    name = _require_non_empty_string(raw, "name")
    element_type = _string_or_default(raw, "element_type", "uint8_t")
    sensitive = bool(raw.get("sensitive", True))
    must_zeroize = bool(raw.get("must_zeroize", True))
    forbid_post_send_use = bool(raw.get("forbid_post_send_use", True))
    allowed_sinks = expand_sink_patterns(_read_string_list(raw, "allowed_sinks"))
    forbidden_sinks = expand_sink_patterns(_read_string_list(raw, "forbidden_sinks"))
    allowed_transforms = tuple(_read_string_list(raw, "allowed_transforms"))
    overlap = set(allowed_sinks).intersection(forbidden_sinks)
    if overlap:
        joined = ", ".join(sorted(overlap))
        raise ContractError(
            f"buffer '{name}' declares sinks that are both allowed and forbidden: {joined}"
        )

    return BufferContract(
        name=name,
        element_type=element_type,
        sensitive=sensitive,
        must_zeroize=must_zeroize,
        forbid_post_send_use=forbid_post_send_use,
        allowed_sinks=allowed_sinks,
        forbidden_sinks=forbidden_sinks,
        transport_sink=_string_or_default(raw, "transport_sink", "net_send_encrypted"),
        kind=_string_or_default(raw, "kind", "generic_secret"),
        allowed_transforms=allowed_transforms,
        forbid_use_after_zeroize=bool(raw.get("forbid_use_after_zeroize", True)),
    )


def _parse_protection_domains(raw: Any) -> ProtectionDomainPolicy | None:
    """Parse optional cryptographic protection-domain policy.

    This extension is intentionally contract-level. It tracks how values move
    between domains such as ``raw``, ``ckks_ciphertext[pk_A]``,
    ``mlkem_shared_secret``, and ``session_key``. It is not a sanitizer list;
    it is an explicit transition relation over cryptographic representations.
    """
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ContractError("'protection_domains' must be an object")

    variables_raw = raw.get("variables", [])
    if not isinstance(variables_raw, list):
        raise ContractError("'protection_domains.variables' must be a list")
    variables: dict[str, str] = {}
    for entry in variables_raw:
        if not isinstance(entry, dict):
            raise ContractError("each protection-domain variable must be an object")
        name = _require_non_empty_string(entry, "name")
        domain = _require_non_empty_string(entry, "domain")
        variables[name] = domain

    transitions_raw = raw.get("transitions", [])
    if not isinstance(transitions_raw, list):
        raise ContractError("'protection_domains.transitions' must be a list")
    transitions: list[ProtectionTransition] = []
    for entry in transitions_raw:
        if not isinstance(entry, dict):
            raise ContractError("each protection-domain transition must be an object")
        transitions.append(ProtectionTransition(
            function=_require_non_empty_string(entry, "function"),
            from_domain=_require_non_empty_string(entry, "from"),
            to_domain=_require_non_empty_string(entry, "to"),
            input_argument_index=int(entry.get("input_argument_index", 0)),
            output=str(entry.get("output", "return")).strip() or "return",
        ))

    allowed_sinks = _parse_domain_sink_policies(raw.get("allowed_sinks", []), "allowed_sinks")
    forbidden_sinks = _parse_domain_sink_policies(raw.get("forbidden_sinks", []), "forbidden_sinks")
    destroyed_domain = _string_or_default(raw, "destroyed_domain", "destroyed")

    if not variables and not transitions and not allowed_sinks and not forbidden_sinks:
        raise ContractError("'protection_domains' must define variables, transitions, or sink policies")

    return ProtectionDomainPolicy(
        variables=variables,
        transitions=tuple(transitions),
        allowed_sinks=tuple(allowed_sinks),
        forbidden_sinks=tuple(forbidden_sinks),
        destroyed_domain=destroyed_domain,
    )


def _parse_domain_sink_policies(raw: Any, field_name: str) -> list[DomainSinkPolicy]:
    if not isinstance(raw, list):
        raise ContractError(f"'protection_domains.{field_name}' must be a list")
    parsed: list[DomainSinkPolicy] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ContractError(f"each protection-domain {field_name} entry must be an object")
        domain = _require_non_empty_string(entry, "domain")
        functions = _read_string_list(entry, "functions")
        parsed.append(DomainSinkPolicy(domain=domain, functions=functions))
    return parsed


def _read_sources(raw: Any) -> list[SourceSpec]:
    if not isinstance(raw, list):
        raise ContractError("'sources' must be a list")
    parsed: list[SourceSpec] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ContractError("each source entry must be an object")
        func = _require_non_empty_string(entry, "function")
        arg_idx = int(entry.get("argument_index", 0))
        label = entry.get("taint_label")
        if label is not None and (not isinstance(label, str) or not label.strip()):
            raise ContractError("'taint_label' must be a non-empty string if provided")
        parsed.append(SourceSpec(function=func, argument_index=arg_idx, taint_label=(label.strip() if label else None)))
    return parsed


def _read_sinks(raw: Any) -> list[SinkSpec]:
    if not isinstance(raw, list):
        raise ContractError("'sinks' must be a list")
    parsed: list[SinkSpec] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ContractError("each sink entry must be an object")
        func = _require_non_empty_string(entry, "function")
        arg_idx = int(entry.get("argument_index", 0))
        forbidden = entry.get("forbidden_taints", [])
        if not isinstance(forbidden, list):
            raise ContractError("'forbidden_taints' must be a list")
        parsed.append(SinkSpec(function=func, argument_index=arg_idx, forbidden_taints=tuple(str(x).strip() for x in forbidden)))
    return parsed


def _read_zeroizers(raw: Any) -> list[ZeroizerSpec]:
    if not isinstance(raw, list):
        raise ContractError("'zeroizers' must be a list")
    parsed: list[ZeroizerSpec] = []
    for entry in raw:
        if isinstance(entry, str):
            parsed.append(ZeroizerSpec(function=entry.strip(), target_argument_index=0))
            continue
        if not isinstance(entry, dict):
            raise ContractError("each zeroizer entry must be an object or string")
        func = _require_non_empty_string(entry, "function")
        idx = int(entry.get("target_argument_index", entry.get("argument_index", 0)))
        parsed.append(ZeroizerSpec(function=func, target_argument_index=idx))
    return parsed


def _require_non_empty_string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"'{key}' must be a non-empty string")
    return value.strip()


def _string_or_default(raw: dict[str, Any], key: str, default: str) -> str:
    value = raw.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"'{key}' must be a non-empty string")
    return value.strip()


def _read_string_list(raw: dict[str, Any], key: str) -> tuple[str, ...]:
    values = raw.get(key, [])
    if not isinstance(values, list):
        raise ContractError(f"'{key}' must be a list")
    parsed: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ContractError(f"'{key}' entries must be non-empty strings")
        parsed.append(value.strip())
    return tuple(parsed)
