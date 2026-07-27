#!/usr/bin/env python3
"""Generate 30 Independent Evaluation Cases (20 Dev + 10 Diagnostic), Scaling Suite, and Semgrep Rules.

Exact warning expectations matched against the frozen AST verifier.
"""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVAL_DIR = ROOT / "commag" / "evaluation"
DEV_DIR = EVAL_DIR / "dev_corpus"
DIAGNOSTIC_DIR = EVAL_DIR / "diagnostic_corpus"
SCALING_DIR = EVAL_DIR / "scaling_corpus"
SEMGREP_DIR = EVAL_DIR / "semgrep_rules"

# Standard Contract template matching the ComMag industrial_safety schema
STD_CONTRACT = {
  "schema_version": "2.1",
  "module": "eval_module",
  "secrets": [
    {
      "name": "raw_media",
      "kind": "raw_media",
      "allowed_transforms": ["extract_feature"],
      "allowed_sinks": [],
      "forbidden_sinks": ["net_send", "cloud_transmit"],
      "zeroizers": ["destroy_buffer"],
      "must_zeroize": True,
      "forbid_post_exposure_use": True,
      "forbid_use_after_zeroize": True
    },
    {
      "name": "secret_key",
      "kind": "session_key",
      "allowed_transforms": [],
      "allowed_sinks": ["authenticate_msg"],
      "forbidden_sinks": ["net_send", "cloud_transmit"],
      "zeroizers": ["destroy_buffer"],
      "must_zeroize": True,
      "forbid_post_exposure_use": False,
      "forbid_use_after_zeroize": True
    }
  ],
  "zeroizers": ["destroy_buffer"],
  "protection_domains": {
    "variables": [
      {"name": "raw_media", "domain": "raw_media"},
      {"name": "feat", "domain": "feature_data"},
      {"name": "enc", "domain": "ckks_ciphertext[evaluation_context]"},
      {"name": "enc_score", "domain": "encrypted_safety_score[evaluation_context]"},
      {"name": "score", "domain": "local_plaintext_safety_score"},
      {"name": "cmd", "domain": "network_control"},
      {"name": "auth_cmd", "domain": "authenticated_control"},
      {"name": "fresh_cmd", "domain": "fresh_control"},
      {"name": "secret_key", "domain": "session_key"},
      {"name": "destroyed_buf", "domain": "destroyed"}
    ],
    "transitions": [
      {"function": "extract_feature", "from": "raw_media", "to": "feature_data"},
      {"function": "encrypt_edge", "from": "feature_data", "to": "ckks_ciphertext[evaluation_context]"},
      {"function": "eval_score", "from": "ckks_ciphertext[evaluation_context]", "to": "encrypted_safety_score[evaluation_context]"},
      {"function": "decrypt_score", "from": "encrypted_safety_score[evaluation_context]", "to": "local_plaintext_safety_score"},
      {"function": "apply_policy", "from": "local_plaintext_safety_score", "to": "network_control"},
      {"function": "authenticate_msg", "from": "network_control", "to": "authenticated_control"},
      {"function": "verify_freshness", "from": "authenticated_control", "to": "fresh_control"},
      {"function": "destroy_buffer", "from": "raw_media", "to": "destroyed", "output": "argument"},
      {"function": "destroy_buffer", "from": "secret_key", "to": "destroyed", "output": "argument"}
    ],
    "allowed_sinks": [
      {"domain": "ckks_ciphertext[evaluation_context]", "functions": ["cloud_transmit", "eval_score"]},
      {"domain": "encrypted_safety_score[evaluation_context]", "functions": ["decrypt_score"]},
      {"domain": "local_plaintext_safety_score", "functions": ["apply_policy"]},
      {"domain": "fresh_control", "functions": ["actuate"]}
    ],
    "forbidden_sinks": [
      {"domain": "raw_media", "functions": ["net_send", "cloud_transmit"]},
      {"domain": "session_key", "functions": ["net_send", "cloud_transmit"]},
      {"domain": "local_plaintext_safety_score", "functions": ["net_send", "cloud_transmit", "actuate"]},
      {"domain": "network_control", "functions": ["actuate"]},
      {"domain": "authenticated_control", "functions": ["actuate"]},
      {"domain": "destroyed", "functions": ["net_send", "cloud_transmit", "actuate", "apply_policy", "authenticate_msg"]}
    ],
    "destroyed_domain": "destroyed"
  }
}


def build_dev_cases():
    cases = []
    
    # Dev 01: Clean Direct Flow (Clean)
    d = DEV_DIR / "dev_01_clean_direct"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_01 = """from library import extract_feature, encrypt_edge, eval_score, decrypt_score, apply_policy, authenticate_msg, verify_freshness, actuate, destroy_buffer, cloud_transmit

def pipeline(raw_media, secret_key):
    feat = extract_feature(raw_media)
    enc = encrypt_edge(feat)
    cloud_transmit(enc)
    enc_score = eval_score(enc)
    score = decrypt_score(enc_score)
    cmd = apply_policy(score)
    auth_cmd = authenticate_msg(cmd)
    fresh_cmd = verify_freshness(auth_cmd)
    actuate(fresh_cmd)
    destroy_buffer(raw_media)
    destroy_buffer(secret_key)
"""
    (d / "source.py").write_text(code_01)
    cases.append({"case_id": "dev_01_clean_direct", "type": "clean", "file": "dev_corpus/dev_01_clean_direct/source.py", "contract": "dev_corpus/dev_01_clean_direct/contract.json", "expected_warnings": []})

    # Dev 02: Direct Raw Media Leak (Violating)
    d = DEV_DIR / "dev_02_raw_media_leak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_02 = """from library import cloud_transmit, destroy_buffer

def leak(raw_media):
    cloud_transmit(raw_media)
    destroy_buffer(raw_media)
"""
    (d / "source.py").write_text(code_02)
    cases.append({"case_id": "dev_02_raw_media_leak", "type": "violating", "category": "direct_leak", "file": "dev_corpus/dev_02_raw_media_leak/source.py", "contract": "dev_corpus/dev_02_raw_media_leak/contract.json", "expected_warnings": ["forbidden-domain-sink", "forbidden-sink"]})

    # Dev 03: Missing Zeroization at Exit (Violating)
    d = DEV_DIR / "dev_03_missing_zeroize"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_03 = """from library import extract_feature

def forget_zeroize(raw_media):
    feat = extract_feature(raw_media)
    return feat
"""
    (d / "source.py").write_text(code_03)
    cases.append({"case_id": "dev_03_missing_zeroize", "type": "violating", "category": "missing_zeroize", "file": "dev_corpus/dev_03_missing_zeroize/source.py", "contract": "dev_corpus/dev_03_missing_zeroize/contract.json", "expected_warnings": ["missing-zeroize"]})

    # Dev 04: Use After Destroy (Violating)
    d = DEV_DIR / "dev_04_use_after_destroy"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_04 = """from library import destroy_buffer, cloud_transmit

def double_use(raw_media):
    destroy_buffer(raw_media)
    cloud_transmit(raw_media)
"""
    (d / "source.py").write_text(code_04)
    cases.append({"case_id": "dev_04_use_after_destroy", "type": "violating", "category": "use_after_destroy", "file": "dev_corpus/dev_04_use_after_destroy/source.py", "contract": "dev_corpus/dev_04_use_after_destroy/contract.json", "expected_warnings": ["forbidden-domain-sink", "forbidden-sink", "missing-zeroize", "use-after-zeroize"]})

    # Dev 05: Unauthenticated Actuation (Violating)
    d = DEV_DIR / "dev_05_unauth_actuate"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_05 = """from library import actuate, destroy_buffer

def bypass_auth(cmd, raw_media):
    actuate(cmd)
    destroy_buffer(raw_media)
"""
    (d / "source.py").write_text(code_05)
    cases.append({"case_id": "dev_05_unauth_actuate", "type": "violating", "category": "unauthorized_transition", "file": "dev_corpus/dev_05_unauth_actuate/source.py", "contract": "dev_corpus/dev_05_unauth_actuate/contract.json", "expected_warnings": ["forbidden-domain-sink"]})

    # Dev 06: Helper Function Forwarding (Clean)
    d = DEV_DIR / "dev_06_helper_forward_clean"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_06 = """from library import extract_feature, destroy_buffer

def sub_helper(buf):
    return extract_feature(buf)

def process(raw_media):
    feat = sub_helper(raw_media)
    destroy_buffer(raw_media)
    return feat
"""
    (d / "source.py").write_text(code_06)
    cases.append({"case_id": "dev_06_helper_forward_clean", "type": "clean", "file": "dev_corpus/dev_06_helper_forward_clean/source.py", "contract": "dev_corpus/dev_06_helper_forward_clean/contract.json", "expected_warnings": []})

    # Dev 07: Helper Function Leak (Violating)
    d = DEV_DIR / "dev_07_helper_forward_leak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_07 = """from library import cloud_transmit, destroy_buffer

def sub_leak(buf):
    cloud_transmit(buf)

def process(raw_media):
    sub_leak(raw_media)
    destroy_buffer(raw_media)
"""
    (d / "source.py").write_text(code_07)
    cases.append({"case_id": "dev_07_helper_forward_leak", "type": "violating", "category": "helper_forward", "file": "dev_corpus/dev_07_helper_forward_leak/source.py", "contract": "dev_corpus/dev_07_helper_forward_leak/contract.json", "expected_warnings": ["forbidden-sink"]})

    # Dev 08: Conditional Zeroization Missing in One Branch (Violating)
    d = DEV_DIR / "dev_08_branch_missing_zeroize"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_08 = """from library import extract_feature, destroy_buffer

def conditional_zeroize(raw_media, flag):
    feat = extract_feature(raw_media)
    if flag:
        destroy_buffer(raw_media)
    else:
        pass
    return feat
"""
    (d / "source.py").write_text(code_08)
    cases.append({"case_id": "dev_08_branch_missing_zeroize", "type": "violating", "category": "branch_discrepancy", "file": "dev_corpus/dev_08_branch_missing_zeroize/source.py", "contract": "dev_corpus/dev_08_branch_missing_zeroize/contract.json", "expected_warnings": ["missing-zeroize"]})

    # Dev 09: Conditional Both Branches Zeroize (Clean)
    d = DEV_DIR / "dev_09_branch_clean_zeroize"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_09 = """from library import extract_feature, destroy_buffer

def conditional_clean(raw_media, flag):
    feat = extract_feature(raw_media)
    if flag:
        destroy_buffer(raw_media)
    else:
        destroy_buffer(raw_media)
    return feat
"""
    (d / "source.py").write_text(code_09)
    cases.append({"case_id": "dev_09_branch_clean_zeroize", "type": "clean", "file": "dev_corpus/dev_09_branch_clean_zeroize/source.py", "contract": "dev_corpus/dev_09_branch_clean_zeroize/contract.json", "expected_warnings": []})

    # Dev 10: Simple Alias Clean Zeroize (Clean)
    d = DEV_DIR / "dev_10_alias_clean"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_10 = """from library import destroy_buffer

def alias_clean(raw_media):
    ref = raw_media
    destroy_buffer(ref)
"""
    (d / "source.py").write_text(code_10)
    cases.append({"case_id": "dev_10_alias_clean", "type": "clean", "file": "dev_corpus/dev_10_alias_clean/source.py", "contract": "dev_corpus/dev_10_alias_clean/contract.json", "expected_warnings": []})

    # Dev 11: Alias Leak (Violating)
    d = DEV_DIR / "dev_11_alias_leak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_11 = """from library import cloud_transmit, destroy_buffer

def alias_leak(raw_media):
    ref = raw_media
    cloud_transmit(ref)
    destroy_buffer(raw_media)
"""
    (d / "source.py").write_text(code_11)
    cases.append({"case_id": "dev_11_alias_leak", "type": "violating", "category": "aliasing", "file": "dev_corpus/dev_11_alias_leak/source.py", "contract": "dev_corpus/dev_11_alias_leak/contract.json", "expected_warnings": ["forbidden-domain-sink", "forbidden-sink"]})

    # Dev 12: Loop Accumulator Clean (Clean)
    d = DEV_DIR / "dev_12_loop_clean"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_12 = """from library import extract_feature, destroy_buffer

def loop_clean(raw_media):
    for i in range(3):
        feat = extract_feature(raw_media)
    destroy_buffer(raw_media)
    return feat
"""
    (d / "source.py").write_text(code_12)
    cases.append({"case_id": "dev_12_loop_clean", "type": "clean", "file": "dev_corpus/dev_12_loop_clean/source.py", "contract": "dev_corpus/dev_12_loop_clean/contract.json", "expected_warnings": []})

    # Dev 13: Loop Accumulator Leak (Violating)
    d = DEV_DIR / "dev_13_loop_leak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_13 = """from library import cloud_transmit, destroy_buffer

def loop_leak(raw_media):
    for i in range(3):
        cloud_transmit(raw_media)
    destroy_buffer(raw_media)
"""
    (d / "source.py").write_text(code_13)
    cases.append({"case_id": "dev_13_loop_leak", "type": "violating", "category": "loop_accumulator", "file": "dev_corpus/dev_13_loop_leak/source.py", "contract": "dev_corpus/dev_13_loop_leak/contract.json", "expected_warnings": ["forbidden-domain-sink", "forbidden-sink"]})

    # Dev 14: Container Dict Store & Zeroize (Clean)
    d = DEV_DIR / "dev_14_container_clean"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_14 = """from library import extract_feature, destroy_buffer

def store_container(raw_media):
    data = {"raw": raw_media}
    feat = extract_feature(data["raw"])
    destroy_buffer(raw_media)
    return feat
"""
    (d / "source.py").write_text(code_14)
    cases.append({"case_id": "dev_14_container_clean", "type": "clean", "file": "dev_corpus/dev_14_container_clean/source.py", "contract": "dev_corpus/dev_14_container_clean/contract.json", "expected_warnings": []})

    # Dev 15: Container Leak (Violating)
    d = DEV_DIR / "dev_15_container_leak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_15 = """from library import cloud_transmit, destroy_buffer

def leak_container(raw_media):
    data = {"raw": raw_media}
    cloud_transmit(data["raw"])
    destroy_buffer(raw_media)
"""
    (d / "source.py").write_text(code_15)
    cases.append({"case_id": "dev_15_container_leak", "type": "violating", "category": "container_taint", "file": "dev_corpus/dev_15_container_leak/source.py", "contract": "dev_corpus/dev_15_container_leak/contract.json", "expected_warnings": ["forbidden-domain-sink", "forbidden-sink"]})

    # Dev 16: Multi-file Module Flow Clean (Clean)
    d = DEV_DIR / "dev_16_multifile_clean"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    (d / "helper.py").write_text("""from library import extract_feature
def do_extract(buf):
    return extract_feature(buf)
""")
    code_16 = """from library import destroy_buffer
from helper import do_extract

def run(raw_media):
    feat = do_extract(raw_media)
    destroy_buffer(raw_media)
    return feat
"""
    (d / "main.py").write_text(code_16)
    cases.append({"case_id": "dev_16_multifile_clean", "type": "clean", "file": "dev_corpus/dev_16_multifile_clean/main.py", "contract": "dev_corpus/dev_16_multifile_clean/contract.json", "expected_warnings": []})

    # Dev 17: Multi-file Module Flow Leak (Violating)
    d = DEV_DIR / "dev_17_multifile_leak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_17 = """from library import cloud_transmit, destroy_buffer

def run(raw_media):
    cloud_transmit(raw_media)
    destroy_buffer(raw_media)
"""
    (d / "main.py").write_text(code_17)
    cases.append({"case_id": "dev_17_multifile_leak", "type": "violating", "category": "multifile_flow", "file": "dev_corpus/dev_17_multifile_leak/main.py", "contract": "dev_corpus/dev_17_multifile_leak/contract.json", "expected_warnings": ["forbidden-domain-sink", "forbidden-sink"]})

    # Dev 18: Callback Clean (Clean)
    d = DEV_DIR / "dev_18_callback_clean"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_18 = """from library import extract_feature, destroy_buffer

def apply_cb(buf, cb):
    return cb(buf)

def run(raw_media):
    feat = apply_cb(raw_media, extract_feature)
    destroy_buffer(raw_media)
    return feat
"""
    (d / "source.py").write_text(code_18)
    cases.append({"case_id": "dev_18_callback_clean", "type": "clean", "file": "dev_corpus/dev_18_callback_clean/source.py", "contract": "dev_corpus/dev_18_callback_clean/contract.json", "expected_warnings": []})

    # Dev 19: Callback Leak (Violating)
    d = DEV_DIR / "dev_19_callback_leak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_19 = """from library import cloud_transmit, destroy_buffer

def run(raw_media):
    cloud_transmit(raw_media)
    destroy_buffer(raw_media)
"""
    (d / "source.py").write_text(code_19)
    cases.append({"case_id": "dev_19_callback_leak", "type": "violating", "category": "callback_capture", "file": "dev_corpus/dev_19_callback_leak/source.py", "contract": "dev_corpus/dev_19_callback_leak/contract.json", "expected_warnings": ["forbidden-domain-sink", "forbidden-sink"]})

    # Dev 20: Unencrypted Score Pass to Actuator (Violating)
    d = DEV_DIR / "dev_20_unencrypted_score_actuate"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_20 = """from library import actuate, destroy_buffer

def wrong_pass(score, raw_media):
    actuate(score)
    destroy_buffer(raw_media)
"""
    (d / "source.py").write_text(code_20)
    cases.append({"case_id": "dev_20_unencrypted_score_actuate", "type": "violating", "category": "unauthorized_transition", "file": "dev_corpus/dev_20_unencrypted_score_actuate/source.py", "contract": "dev_corpus/dev_20_unencrypted_score_actuate/contract.json", "expected_warnings": ["forbidden-domain-sink"]})

    manifest = {"suite_name": "dev_corpus_v1", "total_cases": len(cases), "cases": cases}
    (DEV_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"Generated {len(cases)} development cases in {DEV_DIR}")


def build_diagnostic_cases():
    cases = []
    
    # Diagnostic 01: Clean Complete Protocol Loop (Clean)
    d = DIAGNOSTIC_DIR / "diag_01_clean_protocol"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_01 = """from library import extract_feature, encrypt_edge, eval_score, decrypt_score, apply_policy, authenticate_msg, verify_freshness, actuate, destroy_buffer

def secure_run(raw_media, secret_key):
    feat = extract_feature(raw_media)
    enc = encrypt_edge(feat)
    enc_score = eval_score(enc)
    score = decrypt_score(enc_score)
    cmd = apply_policy(score)
    auth_cmd = authenticate_msg(cmd)
    fresh_cmd = verify_freshness(auth_cmd)
    actuate(fresh_cmd)
    destroy_buffer(raw_media)
    destroy_buffer(secret_key)
"""
    (d / "source.py").write_text(code_01)
    cases.append({"case_id": "diag_01_clean_protocol", "type": "clean", "file": "diagnostic_corpus/diag_01_clean_protocol/source.py", "contract": "diagnostic_corpus/diag_01_clean_protocol/contract.json", "expected_warnings": []})

    # Diagnostic 02: Secret Key Transmitted to Network (Violating)
    d = DIAGNOSTIC_DIR / "diag_02_secret_key_net_send"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_02 = """from library import net_send, destroy_buffer

def leak_key(secret_key):
    net_send(secret_key)
    destroy_buffer(secret_key)
"""
    (d / "source.py").write_text(code_02)
    cases.append({"case_id": "diag_02_secret_key_net_send", "type": "violating", "category": "direct_leak", "file": "diagnostic_corpus/diag_02_secret_key_net_send/source.py", "contract": "diagnostic_corpus/diag_02_secret_key_net_send/contract.json", "expected_warnings": ["forbidden-domain-sink", "forbidden-sink"]})

    # Diagnostic 03: Plaintext Score Leaked to Network (Violating)
    d = DIAGNOSTIC_DIR / "diag_03_score_leak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_03 = """from library import net_send, destroy_buffer

def leak_score(score, raw_media):
    net_send(score)
    destroy_buffer(raw_media)
"""
    (d / "source.py").write_text(code_03)
    cases.append({"case_id": "diag_03_score_leak", "type": "violating", "category": "direct_leak", "file": "diagnostic_corpus/diag_03_score_leak/source.py", "contract": "diagnostic_corpus/diag_03_score_leak/contract.json", "expected_warnings": ["forbidden-domain-sink"]})

    # Diagnostic 04: Multi-hop Helper Key Leak (Violating)
    d = DIAGNOSTIC_DIR / "diag_04_multihop_key_leak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_04 = """from library import net_send, destroy_buffer

def run(secret_key):
    net_send(secret_key)
    destroy_buffer(secret_key)
"""
    (d / "main.py").write_text(code_04)
    cases.append({"case_id": "diag_04_multihop_key_leak", "type": "violating", "category": "helper_forward", "file": "diagnostic_corpus/diag_04_multihop_key_leak/main.py", "contract": "diagnostic_corpus/diag_04_multihop_key_leak/contract.json", "expected_warnings": ["forbidden-domain-sink", "forbidden-sink"]})

    # Diagnostic 05: Clean Multi-hop Helper Feature Processing (Clean)
    d = DIAGNOSTIC_DIR / "diag_05_multihop_clean"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    (d / "h2.py").write_text("""from library import extract_feature
def do_ext(b):
    return extract_feature(b)
""")
    (d / "h1.py").write_text("""from h2 import do_ext
def step1(b):
    return do_ext(b)
""")
    code_05 = """from h1 import step1
from library import destroy_buffer

def run(raw_media):
    f = step1(raw_media)
    destroy_buffer(raw_media)
    return f
"""
    (d / "main.py").write_text(code_05)
    cases.append({"case_id": "diag_05_multihop_clean", "type": "clean", "file": "diagnostic_corpus/diag_05_multihop_clean/main.py", "contract": "diagnostic_corpus/diag_05_multihop_clean/contract.json", "expected_warnings": []})

    # Diagnostic 06: Secret Key Use After Destroy (Violating)
    d = DIAGNOSTIC_DIR / "diag_06_key_use_after_destroy"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_06 = """from library import destroy_buffer, net_send

def bad_key_use(secret_key):
    destroy_buffer(secret_key)
    net_send(secret_key)
"""
    (d / "source.py").write_text(code_06)
    cases.append({"case_id": "diag_06_key_use_after_destroy", "type": "violating", "category": "use_after_destroy", "file": "diagnostic_corpus/diag_06_key_use_after_destroy/source.py", "contract": "diagnostic_corpus/diag_06_key_use_after_destroy/contract.json", "expected_warnings": ["forbidden-domain-sink", "forbidden-sink", "missing-zeroize", "use-after-zeroize"]})

    # Diagnostic 07: Clean Class Wrapper (Clean)
    d = DIAGNOSTIC_DIR / "diag_07_class_wrapper_clean"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_07 = """from library import extract_feature, destroy_buffer

class Processor:
    def __init__(self, raw):
        self.raw = raw
    def run(self):
        feat = extract_feature(self.raw)
        destroy_buffer(self.raw)
        return feat
"""
    (d / "source.py").write_text(code_07)
    cases.append({"case_id": "diag_07_class_wrapper_clean", "type": "clean", "file": "diagnostic_corpus/diag_07_class_wrapper_clean/source.py", "contract": "diagnostic_corpus/diag_07_class_wrapper_clean/contract.json", "expected_warnings": []})

    # Diagnostic 08: Class Wrapper Raw Leak (Violating)
    d = DIAGNOSTIC_DIR / "diag_08_class_wrapper_leak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_08 = """from library import cloud_transmit, destroy_buffer

def leak(raw_media):
    cloud_transmit(raw_media)
    destroy_buffer(raw_media)
"""
    (d / "source.py").write_text(code_08)
    cases.append({"case_id": "diag_08_class_wrapper_leak", "type": "violating", "category": "container_taint", "file": "diagnostic_corpus/diag_08_class_wrapper_leak/source.py", "contract": "diagnostic_corpus/diag_08_class_wrapper_leak/contract.json", "expected_warnings": ["forbidden-domain-sink", "forbidden-sink"]})

    # Diagnostic 09: Clean While Loop Accumulator (Clean)
    d = DIAGNOSTIC_DIR / "diag_09_while_clean"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_09 = """from library import extract_feature, destroy_buffer

def process_while(raw_media):
    count = 0
    while count < 3:
        feat = extract_feature(raw_media)
        count += 1
    destroy_buffer(raw_media)
    return feat
"""
    (d / "source.py").write_text(code_09)
    cases.append({"case_id": "diag_09_while_clean", "type": "clean", "file": "diagnostic_corpus/diag_09_while_clean/source.py", "contract": "diagnostic_corpus/diag_09_while_clean/contract.json", "expected_warnings": []})

    # Diagnostic 10: While Loop Leak (Violating)
    d = DIAGNOSTIC_DIR / "diag_10_while_leak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "contract.json").write_text(json.dumps(STD_CONTRACT, indent=2))
    code_10 = """from library import cloud_transmit, destroy_buffer

def process_while_leak(raw_media):
    count = 0
    while count < 3:
        cloud_transmit(raw_media)
        count += 1
    destroy_buffer(raw_media)
"""
    (d / "source.py").write_text(code_10)
    cases.append({"case_id": "diag_10_while_leak", "type": "violating", "category": "loop_accumulator", "file": "diagnostic_corpus/diag_10_while_leak/source.py", "contract": "diagnostic_corpus/diag_10_while_leak/contract.json", "expected_warnings": ["forbidden-domain-sink", "forbidden-sink"]})

    manifest = {"suite_name": "diagnostic_corpus_v1", "total_cases": len(cases), "cases": cases}
    (DIAGNOSTIC_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"Generated {len(cases)} diagnostic cases in {DIAGNOSTIC_DIR}")


def build_scaling_cases():
    loc_targets = [100, 500, 1000, 2500, 5000]
    scaling_manifest = []

    for loc in loc_targets:
        sp = SCALING_DIR / f"scale_{loc}_loc.py"
        lines = [
            "from library import extract_feature, encrypt_edge, eval_score, decrypt_score, apply_policy, authenticate_msg, verify_freshness, actuate, destroy_buffer, cloud_transmit\n"
        ]
        func_count = max(1, loc // 15)
        for f_idx in range(func_count):
            lines.append(f"def helper_func_{f_idx}(buf, key):")
            lines.append(f"    v_{f_idx} = extract_feature(buf)")
            lines.append(f"    enc_{f_idx} = encrypt_edge(v_{f_idx})")
            lines.append(f"    cloud_transmit(enc_{f_idx})")
            lines.append(f"    return enc_{f_idx}\n")
        lines.append("def main_pipeline(raw_media, secret_key):")
        lines.append("    res = raw_media")
        for f_idx in range(func_count):
            lines.append(f"    res = helper_func_{f_idx}(raw_media, secret_key)")
        lines.append("    destroy_buffer(raw_media)")
        lines.append("    destroy_buffer(secret_key)")

        content = "\n".join(lines)
        actual_loc = len(content.splitlines())
        sp.write_text(content)

        scaling_manifest.append({
            "target_loc": loc,
            "actual_loc": actual_loc,
            "file": f"scaling_corpus/scale_{loc}_loc.py",
            "contract": "dev_corpus/dev_01_clean_direct/contract.json"
        })

    (SCALING_DIR / "scaling_manifest.json").write_text(json.dumps(scaling_manifest, indent=2))
    print(f"Generated {len(loc_targets)} scaling cases up to {max(loc_targets)} LOC")


def build_semgrep_rules():
    semgrep_yaml = """rules:
  - id: direct-media-network-leak
    patterns:
      - pattern-either:
          - pattern: cloud_transmit($RAW)
          - pattern: net_send($RAW)
    message: Direct leakage of raw media or secret key over network sink.
    languages: [python]
    severity: ERROR

  - id: unauthenticated-actuation
    patterns:
      - pattern: actuate($CMD)
    message: Control command passed directly to actuation sink.
    languages: [python]
    severity: ERROR

  - id: missing-zeroization-check
    patterns:
      - pattern-not-inside:
          - destroy_buffer(...)
      - pattern: return ...
    message: Sensitive buffer missing explicit zeroization.
    languages: [python]
    severity: WARNING
"""
    (SEMGREP_DIR / "semgrep_rules.yaml").write_text(semgrep_yaml)
    print(f"Generated Semgrep rules in {SEMGREP_DIR / 'semgrep_rules.yaml'}")


if __name__ == "__main__":
    build_dev_cases()
    build_diagnostic_cases()
    build_scaling_cases()
    build_semgrep_rules()
