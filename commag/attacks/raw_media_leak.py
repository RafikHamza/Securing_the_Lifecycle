"""Misuse Case 1: Raw Media Leakage.

Transmits raw camera video stream directly to an unencrypted network cloud sink
without performing local visual feature extraction or homomorphic encryption.
Contract Rule Broken: raw_video domain is forbidden from reaching cloud_transmit sink.
Expected Warning Code: forbidden-domain-sink
"""
from commag.scenario.edge_gateway import cloud_transmit, destroy_sensitive_buffer

def leak_raw_media(raw_video, raw_audio):
    # VIOLATION: Transmitting raw_video directly to cloud transmission sink
    cloud_transmit(raw_video)

    destroy_sensitive_buffer(raw_video)
    destroy_sensitive_buffer(raw_audio)

if __name__ == "__main__":
    leak_raw_media({"raw": 1}, {"raw": 2})
