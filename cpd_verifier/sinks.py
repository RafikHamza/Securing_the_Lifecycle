from __future__ import annotations

import fnmatch
from collections.abc import Iterable

# Built-in sink groups used by the USENIX artifact path. These are intentionally
# conservative developer-facing defaults rather than a complete model of every
# runtime API.
SINK_GROUPS: dict[str, tuple[str, ...]] = {
    "logging": (
        "print", "printf", "fprintf", "sprintf", "snprintf", "syslog",
        "logging.*", "logger.*", "ESP_LOG*", "esp_log_write",
    ),
    "network": (
        "send", "write", "socket.send", "requests.*", "urllib.*",
        "mbedtls_ssl_write", "tls_send_raw", "net_send_raw",
    ),
    "uart_debug": (
        "uart_write_bytes", "Serial.print", "Serial.write", "console_write",
    ),
    "flash_storage": (
        "fwrite", "open", "write_file", "nvs_set_blob", "esp_partition_write",
        "littlefs_write", "fatfs_write",
    ),
    "rtos_queue": (
        "xQueueSend", "xQueueSendToBack", "xMessageBufferSend",
    ),
    "unsafe_conversion": (
        "str", "repr", "format", "bytes",
    ),
}


def expand_sink_patterns(values: Iterable[str]) -> tuple[str, ...]:
    """Expand entries such as '@logging' into concrete sink patterns."""
    expanded: list[str] = []
    for value in values:
        item = str(value).strip()
        if not item:
            continue
        if item.startswith("@"):
            group = item[1:]
            if group not in SINK_GROUPS:
                known = ", ".join(sorted(SINK_GROUPS))
                raise ValueError(f"unknown sink group '@{group}' (known groups: {known})")
            expanded.extend(SINK_GROUPS[group])
        else:
            expanded.append(item)
    # preserve order while deduplicating
    return tuple(dict.fromkeys(expanded))


def matches_pattern(name: str, patterns: Iterable[str]) -> bool:
    variants = [name]
    if "." in name:
        variants.append(name.rsplit(".", 1)[-1])
    for pattern in patterns:
        if any(fnmatch.fnmatch(candidate, pattern) for candidate in variants):
            return True
    return False
