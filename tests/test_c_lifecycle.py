from cpd_verifier.contract import load_contract, parse_contract
from cpd_verifier.cpp_verifier import verify_cpp_file, verify_cpp_source


def mlkem_contract():
    return load_contract("examples/mlkem_lifecycle/mlkem.contract.json")


def test_c_pointer_alias_to_shared_secret_reaches_logging_sink():
    c = mlkem_contract()
    src = """
#include <stdint.h>
#include <stdio.h>
void f(void) {
    uint8_t shared_secret[32];
    uint8_t *p = shared_secret;
    printf("%02x", p[0]);
    secure_zeroize(shared_secret, sizeof shared_secret);
}
"""
    codes = [v.code for v in verify_cpp_source(c, src)]
    assert "forbidden-sink" in codes


def test_c_struct_arrow_field_alias_reaches_uart_sink():
    c = parse_contract({
        "schema_version": "2.0",
        "module": "struct_ctx",
        "secrets": [{
            "name": "ctx->shared_secret",
            "must_zeroize": True,
            "allowed_sinks": ["tls_send_encrypted"],
            "forbidden_sinks": ["@uart_debug"],
            "zeroizers": ["secure_zeroize"]
        }]
    })
    src = """
#include <stdint.h>
struct ctx_t { uint8_t shared_secret[32]; };
void f(struct ctx_t *ctx) {
    uart_write_bytes(0, ctx->shared_secret, 32);
    secure_zeroize(ctx->shared_secret, 32);
}
"""
    codes = [v.code for v in verify_cpp_source(c, src)]
    assert "forbidden-sink" in codes


def test_c_session_key_missing_zeroize_is_reported():
    c = mlkem_contract()
    codes = [v.code for v in verify_cpp_file(c, "examples/mlkem_lifecycle/bug_missing_zeroize_session_key.c")]
    assert "missing-zeroize" in codes


def test_c_good_example_tracks_session_key_and_passes():
    c = mlkem_contract()
    assert [v.code for v in verify_cpp_file(c, "examples/mlkem_lifecycle/mlkem_good.c")] == []
