from pathlib import Path

from cpd_verifier.contract import load_contract, parse_contract
from cpd_verifier.verifier import verify_file
from cpd_verifier.c_frontend import verify_c_file

ROOT = Path(__file__).resolve().parents[1]


def _codes(violations):
    return {v.code for v in violations}


def test_parse_protection_domain_contract():
    contract = load_contract(ROOT / "examples/protection_domains/he_pipeline.contract.json")
    assert contract.protection_domains is not None
    assert contract.protection_domains.variables["features"] == "raw"
    transitions = contract.protection_domains.transitions_for("ckks_encrypt")
    assert transitions[0].from_domain == "raw"
    assert transitions[0].to_domain == "ckks_ciphertext[pk_A]"
    zeroize = contract.protection_domains.transitions_for("secure_zeroize")
    assert zeroize[0].to_domain == "destroyed"
    assert zeroize[0].output == "argument"


def test_he_protection_domain_good_pipeline_passes():
    contract = load_contract(ROOT / "examples/protection_domains/he_pipeline.contract.json")
    violations = verify_file(contract, ROOT / "examples/protection_domains/he_pipeline_good.py")
    assert not violations


def test_he_protection_domain_raw_leak_is_reported():
    contract = load_contract(ROOT / "examples/protection_domains/he_pipeline.contract.json")
    violations = verify_file(contract, ROOT / "examples/protection_domains/he_pipeline_bad_raw_leak.py")
    codes = _codes(violations)
    assert "forbidden-domain-sink" in codes


def test_he_protection_domain_wrong_transition_is_reported():
    contract = load_contract(ROOT / "examples/protection_domains/he_pipeline.contract.json")
    violations = verify_file(contract, ROOT / "examples/protection_domains/he_pipeline_bad_domain_transition.py")
    codes = _codes(violations)
    assert "unauthorized-domain-transition" in codes


def test_he_protection_domain_decrypt_downgrade_to_raw_is_reported():
    contract = load_contract(ROOT / "examples/protection_domains/he_pipeline.contract.json")
    violations = verify_file(contract, ROOT / "examples/protection_domains/he_pipeline_bad_downgrade.py")
    codes = _codes(violations)
    assert "forbidden-domain-sink" in codes


def test_c_protection_domain_mlkem_good_and_bad():
    contract = load_contract(ROOT / "examples/protection_domains/mlkem_session.contract.json")
    good = verify_c_file(contract, ROOT / "examples/protection_domains/mlkem_session_good.c")
    bad = verify_c_file(contract, ROOT / "examples/protection_domains/mlkem_session_bad.c")
    assert not good
    assert "forbidden-domain-sink" in _codes(bad)


def test_he_protection_domain_post_destroy_use_is_reported():
    contract = load_contract(ROOT / "examples/protection_domains/he_pipeline.contract.json")
    violations = verify_file(contract, ROOT / "examples/protection_domains/he_pipeline_bad_after_destroy.py")
    assert "forbidden-domain-sink" in _codes(violations)


def test_c_protection_domain_post_destroy_use_is_reported():
    contract = load_contract(ROOT / "examples/protection_domains/mlkem_session.contract.json")
    violations = verify_c_file(contract, ROOT / "examples/protection_domains/mlkem_session_bad_after_destroy.c")
    assert "forbidden-domain-sink" in _codes(violations)
