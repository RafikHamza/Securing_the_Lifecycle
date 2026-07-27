from cpd_verifier.contract import parse_contract
from cpd_verifier.verifier import verify_source


def _contract():
    return parse_contract({
        "module": "regression",
        "buffers": [{
            "name": "key",
            "element_type": "bytes",
            "sensitive": True,
            "must_zeroize": True,
            "forbid_post_send_use": True,
            "allowed_sinks": ["safe_send"],
            "forbidden_sinks": ["unsafe_send", "os.*"],
            "transport_sink": "transport_send",
        }],
    })


def _codes(src: str) -> list[str]:
    return [v.code for v in verify_source(_contract(), src)]


def test_qualified_forbidden_sink_matches_glob():
    codes = _codes("""
def f(key):
    os.remove(key)
    secure_zeroize(key)
""")
    assert "forbidden-sink" in codes


def test_keyword_argument_sink_is_checked():
    codes = _codes("""
def f(key):
    unsafe_send(data=key)
    secure_zeroize(key)
""")
    assert "forbidden-sink" in codes


def test_async_function_is_verified():
    codes = _codes("""
async def f(key):
    unsafe_send(key)
    secure_zeroize(key)
""")
    assert "forbidden-sink" in codes


def test_syntax_error_is_not_silent_pass():
    codes = _codes("""
def f(:
    pass
""")
    assert codes == ["syntax-error"]


def test_return_inside_try_runs_finally_before_exit():
    codes = _codes("""
def f(key):
    try:
        safe_send(key)
        return 1
    finally:
        secure_zeroize(key)
""")
    assert "missing-zeroize" not in codes
