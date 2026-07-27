"""Misuse Case 3: Direct Transmission of ML-KEM Shared Secret.

Transmits raw ML-KEM shared secret (shared_secret) directly over
the network transmit sink (cloud_transmit) before derive_session_key().
Contract Rule Broken: mlkem_shared_secret is forbidden from network transmit sinks.
Expected Warning Code: forbidden-domain-sink
"""
from commag.scenario.edge_gateway import cloud_transmit, destroy_sensitive_buffer

def send_raw_shared_secret(shared_secret):
    # VIOLATION: Transmitting raw ML-KEM shared secret over network sink
    cloud_transmit(shared_secret)

    destroy_sensitive_buffer(shared_secret)

if __name__ == "__main__":
    send_raw_shared_secret({"sec": 1})
