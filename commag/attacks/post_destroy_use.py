"""Misuse Case 6: Use After Destruction.

Attempts to pass a zeroized/destroyed shared secret buffer (shared_secret)
to key derivation (derive_session_key) after calling destroy_sensitive_buffer().
Contract Rule Broken: destroyed domain is forbidden from key derivation / sinks.
Expected Warning Code: forbidden-domain-sink
"""
from commag.scenario.edge_gateway import derive_session_key, destroy_sensitive_buffer

def execute_post_destroy_use(shared_secret):
    destroy_sensitive_buffer(shared_secret)

    # VIOLATION: Accessing / key derivation on destroyed shared_secret
    session_key = derive_session_key(shared_secret)

if __name__ == "__main__":
    execute_post_destroy_use({"sec": 1})
