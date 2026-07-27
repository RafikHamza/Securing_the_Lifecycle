"""Misuse Case 4: Authentication Bypass Before Actuation.

Passes an unauthenticated control command (control_msg) directly
to the actuator endpoint (esp32s3_actuate) without calling authenticate_control_message().
Contract Rule Broken: network_control domain is forbidden from actuation sinks.
Expected Warning Code: forbidden-domain-sink
"""
from commag.scenario.actuator_emulator import esp32s3_actuate
from commag.scenario.edge_gateway import destroy_sensitive_buffer

def execute_unauthenticated_control(control_msg, shared_secret):
    # VIOLATION: Executing actuation directly using unauthenticated network_control payload
    esp32s3_actuate(control_msg)

    destroy_sensitive_buffer(shared_secret)

if __name__ == "__main__":
    execute_unauthenticated_control({"cmd": 1}, {"sec": 1})
