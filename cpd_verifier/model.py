from __future__ import annotations

from enum import Enum, auto
from dataclasses import dataclass


class BufferState(Enum):
    UNALLOCATED = auto()
    ALLOCATED = auto()
    SENT = auto()
    ZEROIZED = auto()


class TypestateValue(Enum):
    """Lattice values for CFG-based typestate analysis.

    Partial order (Hasse diagram):
        TOP
       / | \\
    POSSIBLY_UNSCRUBBED  EXPOSED  CLEARED
       \\ | /
       SECURE
        |
      UNINIT
        |
      BOTTOM

    BOTTOM ⊑ UNINIT ⊑ SECURE ⊑ {EXPOSED, CLEARED, POSSIBLY_UNSCRUBBED} ⊑ TOP

    POSSIBLY_UNSCRUBBED is NOT terminal: if both merged paths
    subsequently scrub before any scope exit, the state transitions
    back to CLEARED.
    """
    BOTTOM = auto()            # unreachable / no information
    UNINIT = auto()            # variable declared but not yet initialized
    SECURE = auto()            # initialized, holding sensitive data
    EXPOSED = auto()           # passed to an allowed tool
    CLEARED = auto()           # scrubbed / zeroized
    POSSIBLY_UNSCRUBBED = auto()  # merge of scrubbed + unscrubbed paths
    TOP = auto()               # conflicting / unknown


# Partial-order rank for lattice comparison
_LATTICE_RANK: dict[TypestateValue, int] = {
    TypestateValue.BOTTOM: 0,
    TypestateValue.UNINIT: 1,
    TypestateValue.SECURE: 2,
    TypestateValue.EXPOSED: 3,
    TypestateValue.CLEARED: 3,
    TypestateValue.POSSIBLY_UNSCRUBBED: 3,
    TypestateValue.TOP: 4,
}


def typestate_join(a: TypestateValue, b: TypestateValue) -> TypestateValue:
    """Compute the join (least upper bound) of two typestate values.

    Key rules:
    - join(x, x) = x  (idempotent)
    - join(BOTTOM, x) = x  (BOTTOM is identity)
    - join(CLEARED, EXPOSED) = POSSIBLY_UNSCRUBBED
    - join(CLEARED, SECURE) = POSSIBLY_UNSCRUBBED
    - join(EXPOSED, SECURE) = EXPOSED  (conservative: may have been exposed)
    - join(anything, TOP) = TOP
    - POSSIBLY_UNSCRUBBED joined with CLEARED => POSSIBLY_UNSCRUBBED
      (conservative: one path may still be unscrubbed)
    - POSSIBLY_UNSCRUBBED joined with SECURE => POSSIBLY_UNSCRUBBED
    """
    if a == b:
        return a
    if a == TypestateValue.BOTTOM:
        return b
    if b == TypestateValue.BOTTOM:
        return a
    if a == TypestateValue.TOP or b == TypestateValue.TOP:
        return TypestateValue.TOP

    pair = frozenset({a, b})

    # CLEARED + anything-not-cleared at same rank => POSSIBLY_UNSCRUBBED
    if TypestateValue.CLEARED in pair:
        other = a if b == TypestateValue.CLEARED else b
        if other in (TypestateValue.SECURE, TypestateValue.EXPOSED,
                     TypestateValue.POSSIBLY_UNSCRUBBED):
            return TypestateValue.POSSIBLY_UNSCRUBBED

    # POSSIBLY_UNSCRUBBED + SECURE/EXPOSED => POSSIBLY_UNSCRUBBED
    if TypestateValue.POSSIBLY_UNSCRUBBED in pair:
        other = a if b == TypestateValue.POSSIBLY_UNSCRUBBED else b
        if other in (TypestateValue.SECURE, TypestateValue.EXPOSED):
            return TypestateValue.POSSIBLY_UNSCRUBBED

    # EXPOSED + SECURE => EXPOSED (conservative)
    if pair == frozenset({TypestateValue.EXPOSED, TypestateValue.SECURE}):
        return TypestateValue.EXPOSED

    # Cross-rank: lower ⊑ higher
    if _LATTICE_RANK[a] < _LATTICE_RANK[b]:
        return b
    if _LATTICE_RANK[b] < _LATTICE_RANK[a]:
        return a

    return TypestateValue.TOP


class ViolationCategory(Enum):
    """Distinct violation categories for reporting."""
    MISSING_SCRUB = "missing-zeroize"
    POST_EXPOSURE_USE = "post-send-use"
    FORBIDDEN_SINK = "forbidden-sink"
    TRANSPORT_BYPASS = "transport-bypass"
    UNSAFE_CONVERSION = "unsafe-conversion"
    USE_AFTER_ZEROIZE = "use-after-zeroize"
    UNAUTHORIZED_TRANSFORM = "unauthorized-transform"
    SECRET_ESCAPE = "secret-escape"
    PROTECTION_DOMAIN = "protection-domain"


@dataclass(frozen=True)
class BufferContract:
    name: str
    element_type: str
    sensitive: bool
    must_zeroize: bool
    forbid_post_send_use: bool
    allowed_sinks: tuple[str, ...]
    forbidden_sinks: tuple[str, ...]
    transport_sink: str
    kind: str = "generic_secret"
    allowed_transforms: tuple[str, ...] = ()
    forbid_use_after_zeroize: bool = True


@dataclass(frozen=True)
class SourceSpec:
    function: str
    argument_index: int
    taint_label: str | None


@dataclass(frozen=True)
class SinkSpec:
    function: str
    argument_index: int
    forbidden_taints: tuple[str, ...]


@dataclass(frozen=True)
class ZeroizerSpec:
    function: str
    target_argument_index: int


@dataclass(frozen=True)
class ProtectionTransition:
    """Authorized cryptographic protection-domain transition.

    A transition says that a call named ``function`` may move a value from
    ``from_domain`` to ``to_domain``. The value normally appears in
    ``input_argument_index`` and, for assignment expressions, the returned
    value receives ``to_domain``.
    """
    function: str
    from_domain: str
    to_domain: str
    input_argument_index: int = 0
    output: str = "return"


@dataclass(frozen=True)
class DomainSinkPolicy:
    domain: str
    functions: tuple[str, ...]


@dataclass(frozen=True)
class ProtectionDomainPolicy:
    """Contract-level policy for cryptographic protection domains."""
    variables: dict[str, str]
    transitions: tuple[ProtectionTransition, ...]
    allowed_sinks: tuple[DomainSinkPolicy, ...]
    forbidden_sinks: tuple[DomainSinkPolicy, ...]
    destroyed_domain: str = "destroyed"

    def domain_allowed_sinks(self, domain: str) -> tuple[str, ...]:
        out: list[str] = []
        for policy in self.allowed_sinks:
            if policy.domain == domain or policy.domain == "*":
                out.extend(policy.functions)
        return tuple(out)

    def domain_forbidden_sinks(self, domain: str) -> tuple[str, ...]:
        out: list[str] = []
        for policy in self.forbidden_sinks:
            if policy.domain == domain or policy.domain == "*":
                out.extend(policy.functions)
        return tuple(out)

    def transitions_for(self, function: str) -> tuple[ProtectionTransition, ...]:
        return tuple(t for t in self.transitions if t.function == function)


@dataclass(frozen=True)
class Contract:
    module: str
    buffers: tuple[BufferContract, ...]
    sources: tuple[SourceSpec, ...]
    sinks: tuple[SinkSpec, ...]
    zeroizers: tuple[ZeroizerSpec, ...]
    protection_domains: ProtectionDomainPolicy | None = None

    @property
    def sensitive_buffers(self) -> tuple[BufferContract, ...]:
        return tuple(buffer for buffer in self.buffers if buffer.sensitive)