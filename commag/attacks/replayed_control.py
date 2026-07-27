"""Misuse Case 5: Freshness / Replay Check Bypass Before Actuation.

Passes an authenticated control message (auth_msg) directly
to the actuator endpoint (esp32s3_actuate) without calling verify_control_freshness().
Contract Rule Broken: authenticated_control domain is forbidden from actuation sinks.
Expected Warning Code: forbidden-domain-sink
"""
from commag.scenario.edge_gateway import derive_session_key, authenticate_control_message, destroy_sensitive_buffer
from commag.scenario.actuator_emulator import esp32s3_actuate

def execute_replayed_control(control_msg, shared_secret):
    session_key = derive_session_key(shared_secret)
    auth_msg = authenticate_control_message(control_msg, session_key)

    # VIOLATION: Executing actuation on auth_msg without verifying freshness
    esp32s3_actuate(auth_msg)

    destroy_sensitive_buffer(shared_secret)
    destroy_sensitive_buffer(session_key)

if __name__ == "__main__":
    execute_replayed_control({"cmd": 1}, {"sec": 1})
