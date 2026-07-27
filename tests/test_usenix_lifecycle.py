from pathlib import Path

from cpd_verifier.contract import parse_contract, load_contract
from cpd_verifier.verifier import verify_source
from cpd_verifier.cpp_verifier import verify_cpp_source, verify_cpp_file
from cpd_verifier.sinks import expand_sink_patterns


def v2_contract():
    return parse_contract({
        "schema_version": "2.0",
        "module": "unit",
        "secrets": [{
            "name": "secret",
            "kind": "session_secret",
            "must_zeroize": True,
            "forbid_post_exposure_use": True,
            "forbid_use_after_zeroize": True,
            "allowed_transforms": ["derive_session_key"],
            "allowed_sinks": ["tls_send_encrypted"],
            "forbidden_sinks": ["@logging", "unsafe_send", "uart_write_bytes"],
            "zeroizers": ["secure_zeroize"]
        }]
    })


def codes(src: str):
    return [v.code for v in verify_source(v2_contract(), src)]


def test_contract_v2_parses_grouped_sinks():
    c = v2_contract()
    assert c.buffers[0].kind == "session_secret"
    assert "printf" in c.buffers[0].forbidden_sinks
    assert "derive_session_key" in c.buffers[0].allowed_transforms


def test_expand_sink_group_unknown_fails():
    try:
        expand_sink_patterns(["@does_not_exist"])
    except ValueError as e:
        assert "unknown sink group" in str(e)
    else:
        raise AssertionError("expected unknown sink group failure")


def test_python_use_after_zeroize_category():
    assert "use-after-zeroize" in codes("""
def f(secret):
    secure_zeroize(secret)
    derive_session_key(secret)
""")


def test_python_transform_target_is_not_raw_alias():
    assert codes("""
def f(secret):
    session_key = derive_session_key(secret)
    tls_send_encrypted(session_key, b'ok')
    secure_zeroize(secret)
""") == []


def test_python_grouped_logging_sink():
    assert "forbidden-sink" in codes("""
def f(secret):
    printf(secret)
    secure_zeroize(secret)
""")


def test_c_good_mlkem_example_passes():
    c = load_contract("examples/mlkem_lifecycle/mlkem.contract.json")
    vs = verify_cpp_file(c, "examples/mlkem_lifecycle/mlkem_good.c")
    assert [v.code for v in vs] == []


def test_c_log_shared_secret_fails():
    c = load_contract("examples/mlkem_lifecycle/mlkem.contract.json")
    codes = [v.code for v in verify_cpp_file(c, "examples/mlkem_lifecycle/bug_log_shared_secret.c")]
    assert "forbidden-sink" in codes


def test_c_use_after_zeroize_fails():
    c = load_contract("examples/mlkem_lifecycle/mlkem.contract.json")
    codes = [v.code for v in verify_cpp_file(c, "examples/mlkem_lifecycle/bug_reuse_after_zeroize.c")]
    assert "use-after-zeroize" in codes
