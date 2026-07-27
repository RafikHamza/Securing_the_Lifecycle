from __future__ import annotations

from enum import Enum
from dataclasses import dataclass


class SecretState(str, Enum):
    UNINIT = "uninit"
    SECRET = "secret"
    TRANSFORMED = "transformed"
    EXPOSED = "exposed"
    ZEROIZED = "zeroized"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class EventKind(str, Enum):
    SOURCE = "source"
    TRANSFORM = "transform"
    ALLOWED_SINK = "allowed_sink"
    FORBIDDEN_SINK = "forbidden_sink"
    ZEROIZE = "zeroize"
    USE = "use"
    RETURN = "return"


@dataclass(frozen=True)
class LifecycleRule:
    secret: str
    state: SecretState
    event: EventKind
    allowed: bool
    violation: str | None = None
