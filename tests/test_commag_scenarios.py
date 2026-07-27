"""CPDVerifier ComMag Embodied-IoT Scenario Tests."""
from __future__ import annotations
from pathlib import Path
import pytest
from cpd_verifier.contract import load_contract
from cpd_verifier.verifier import verify_file

ROOT = Path(__file__).resolve().parents[1]
COMMAG_DIR = ROOT / "commag"
CONTRACT_PATH = COMMAG_DIR / "contracts" / "industrial_safety.contract.json"


@pytest.fixture
def contract():
    return load_contract(CONTRACT_PATH)


def test_clean_safety_loop_verifies_clean(contract):
    src = COMMAG_DIR / "scenario" / "clean_scenario.py"
    violations = verify_file(contract, src)
    assert len(violations) == 0


def test_raw_media_leak_detected(contract):
    src = COMMAG_DIR / "attacks" / "raw_media_leak.py"
    violations = verify_file(contract, src)
    codes = {v.code for v in violations}
    assert "forbidden-domain-sink" in codes


def test_wrong_he_transition_detected(contract):
    src = COMMAG_DIR / "attacks" / "wrong_he_transition.py"
    violations = verify_file(contract, src)
    codes = {v.code for v in violations}
    assert "unauthorized-domain-transition" in codes


def test_unauthenticated_control_detected(contract):
    src = COMMAG_DIR / "attacks" / "unauthenticated_control.py"
    violations = verify_file(contract, src)
    codes = {v.code for v in violations}
    assert "forbidden-domain-sink" in codes


def test_post_destroy_use_detected(contract):
    src = COMMAG_DIR / "attacks" / "post_destroy_use.py"
    violations = verify_file(contract, src)
    codes = {v.code for v in violations}
    assert "use-after-zeroize" in codes
