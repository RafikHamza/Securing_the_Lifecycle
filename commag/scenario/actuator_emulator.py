"""ESP32-S3 Physical / Emulated Actuator Interface.

Verifies HMAC signature, canonical serialization, freshness, non-replay,
and policy version of authenticated control messages prior to actuation.
"""
from __future__ import annotations
import hmac
import hashlib
import time
from commag.scenario.edge_gateway import canonical_serialize_command

EXPECTED_ACTUATOR_ID = "esp32s3_relay_01"
SUPPORTED_POLICY_VERSION = "v1.0"
SUPPORTED_PROTOCOL_VERSION = "v1.0"

_SEEN_NONCES: set[str] = set()


def reset_seen_nonces() -> None:
    """Helper to clear seen nonces state between test runs."""
    global _SEEN_NONCES
    _SEEN_NONCES.clear()


def verify_hmac_tag(authenticated_control: dict, session_key: dict) -> dict:
    """Verify HMAC signature and validate all critical command security fields.
    
    Rejects:
    - Invalid tags (via hmac.compare_digest)
    - Expired commands (issue_time / expiry_time)
    - Duplicate nonces (anti-replay)
    - Unsupported policy / protocol versions
    - Target actuator mismatches
    - Missing or malformed fields
    """
    if authenticated_control.get("domain") != "authenticated_control":
        raise ValueError("HMAC verification requires authenticated_control domain")

    provided_sig = authenticated_control.get("hmac_signature")
    if not provided_sig:
        raise ValueError("Missing HMAC signature in control payload")

    # 1. Target actuator check
    if authenticated_control.get("target_actuator") != EXPECTED_ACTUATOR_ID:
        raise ValueError(f"Target actuator mismatch: expected {EXPECTED_ACTUATOR_ID}, got {authenticated_control.get('target_actuator')}")

    # 2. Version check
    if authenticated_control.get("policy_version") != SUPPORTED_POLICY_VERSION:
        raise ValueError(f"Unsupported policy version: {authenticated_control.get('policy_version')}")
    if authenticated_control.get("protocol_version") != SUPPORTED_PROTOCOL_VERSION:
        raise ValueError(f"Unsupported protocol version: {authenticated_control.get('protocol_version')}")

    # 3. Nonce anti-replay check
    nonce = authenticated_control.get("nonce")
    if not nonce or not isinstance(nonce, str):
        raise ValueError("Missing or invalid nonce in control payload")
    if nonce in _SEEN_NONCES:
        raise ValueError(f"Replayed nonce detected: {nonce}")

    # 4. Expiry check
    now = time.time()
    expiry_time = authenticated_control.get("expiry_time", 0.0)
    if now > expiry_time:
        raise ValueError(f"Expired control command: current time {now} exceeds expiry {expiry_time}")

    # 5. Canonical HMAC signature verification
    msg_bytes = canonical_serialize_command(authenticated_control)
    key_bytes = session_key.get("key_bytes")
    if not key_bytes:
        if "key_hex" in session_key:
            key_bytes = bytes.fromhex(session_key["key_hex"])
        else:
            raise ValueError("Session key missing key bytes")

    expected_sig = hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(provided_sig, expected_sig):
        raise ValueError("HMAC tag verification FAILED: control message tag mismatch")

    # Record nonce after successful verification
    _SEEN_NONCES.add(nonce)

    verified_msg = dict(authenticated_control)
    verified_msg["hmac_verified"] = True
    return verified_msg


def verify_control_freshness(authenticated_control: dict, max_age_sec: float = 5.0) -> dict:
    """Transform authenticated_control domain to fresh_control domain."""
    if authenticated_control.get("domain") != "authenticated_control":
        raise ValueError("Freshness check requires authenticated_control domain")
    if not authenticated_control.get("hmac_verified", False):
        raise ValueError("Freshness check requires HMAC-verified payload")

    now = time.time()
    msg_time = authenticated_control.get("issue_time", authenticated_control.get("timestamp", now))
    if (now - msg_time) > max_age_sec:
        raise ValueError(f"Stale control command: age {now - msg_time:.2f}s exceeds max age {max_age_sec}s")

    fresh_msg = dict(authenticated_control)
    fresh_msg["domain"] = "fresh_control"
    fresh_msg["verified_at"] = now
    return fresh_msg


def esp32s3_actuate(fresh_control: dict) -> bool:
    """Permitted sink for fresh_control domain to execute physical actuation."""
    if fresh_control.get("domain") != "fresh_control":
        raise ValueError("Actuation requires fresh_control domain")
    return True
