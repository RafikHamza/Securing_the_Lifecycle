#!/usr/bin/env python3
"""Independent Verification Evaluation & Semgrep Baseline Runner.

Evaluates:
- 20 Development Cases
- Freezing & Hashing Verifier SHA-256
- 10 diagnostic cases previously inspected during development
- Optional Semgrep execution on the diagnostic corpus
- Scaling Benchmark Suite (100 to 5000 LOC)

Outputs:
- results/commag/evaluation_results.json
- results/commag/evaluation_summary.csv
- results/commag/scaling_benchmark.csv
- results/commag/semgrep_comparison.json
"""
from __future__ import annotations
import ast
import csv
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cpd_verifier.contract import load_contract
from cpd_verifier.verifier import verify_file

VERIFIER_PATH = ROOT / "cpd_verifier" / "verifier.py"
EVAL_DIR = ROOT / "commag" / "evaluation"
RESULTS_DIR = ROOT / "results" / "commag"
DEV_MANIFEST_PATH = EVAL_DIR / "dev_corpus" / "manifest.json"
DIAGNOSTIC_MANIFEST_PATH = EVAL_DIR / "diagnostic_corpus" / "manifest.json"
SCALING_MANIFEST_PATH = EVAL_DIR / "scaling_corpus" / "scaling_manifest.json"
SEMGREP_RULES_PATH = EVAL_DIR / "semgrep_rules" / "semgrep_rules.yaml"


def compute_file_hash(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def count_loc_and_ast(src_path: Path) -> tuple[int, int]:
    code = src_path.read_text(encoding="utf-8")
    loc = len(code.splitlines())
    try:
        tree = ast.parse(code)
        ast_nodes = len(list(ast.walk(tree)))
    except Exception:
        ast_nodes = 0
    return loc, ast_nodes


def run_suite(manifest_path: Path, suite_type: str) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest["cases"]

    case_results = []
    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_tn = 0
    total_time_ms = 0.0

    for case in cases:
        src_path = ROOT / "commag" / "evaluation" / case["file"].replace("dev_corpus/", "").replace("diagnostic_corpus/", "")
        if not src_path.exists():
            src_path = ROOT / "commag" / "evaluation" / case["file"]

        contract_path = ROOT / "commag" / "evaluation" / case["contract"].replace("dev_corpus/", "").replace("diagnostic_corpus/", "")
        if not contract_path.exists():
            contract_path = ROOT / "commag" / "evaluation" / case["contract"]

        contract = load_contract(contract_path)
        loc, ast_nodes = count_loc_and_ast(src_path)

        start_t = time.perf_counter()
        violations = verify_file(contract, src_path)
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        total_time_ms += elapsed_ms

        observed_codes = sorted({v.code for v in violations})
        expected_codes = sorted(case["expected_warnings"])

        # Warning-level TP, FP, FN, TN calculation
        expected_set = set(expected_codes)
        observed_set = set(observed_codes)

        tp = len(expected_set & observed_set)
        fp = len(observed_set - expected_set)
        fn = len(expected_set - observed_set)
        tn = 1 if (not expected_set and not observed_set) else 0

        total_tp += tp
        total_fp += fp
        total_fn += fn
        total_tn += tn

        case_correct = (expected_codes == observed_codes)

        precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if tn > 0 else 0.0)
        recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if tn > 0 else 0.0)
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else (1.0 if tn > 0 else 0.0)

        case_results.append({
            "case_id": case["case_id"],
            "suite_type": suite_type,
            "type": case["type"],
            "category": case.get("category", "clean"),
            "loc": loc,
            "ast_nodes": ast_nodes,
            "expected_warnings": expected_codes,
            "observed_warnings": observed_codes,
            "case_correct": case_correct,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "elapsed_ms": round(elapsed_ms, 3)
        })

    agg_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    agg_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    agg_f1 = (2 * agg_precision * agg_recall) / (agg_precision + agg_recall) if (agg_precision + agg_recall) > 0 else 1.0
    case_accuracy = sum(1 for c in case_results if c["case_correct"]) / len(case_results)

    return {
        "suite_type": suite_type,
        "total_cases": len(case_results),
        "case_accuracy": round(case_accuracy, 4),
        "total_tp": total_tp,
        "total_fp": total_fp,
        "total_fn": total_fn,
        "total_tn": total_tn,
        "precision": round(agg_precision, 4),
        "recall": round(agg_recall, 4),
        "f1": round(agg_f1, 4),
        "total_time_ms": round(total_time_ms, 3),
        "cases": case_results
    }


def run_semgrep_baseline(diagnostic_results: dict) -> dict:
    """Run Semgrep baseline comparison on the diagnostic corpus files if semgrep is installed."""
    semgrep_available = False
    try:
        res = subprocess.run(["semgrep", "--version"], capture_output=True, text=True)
        if res.returncode == 0:
            semgrep_available = True
    except FileNotFoundError:
        semgrep_available = False

    if not semgrep_available:
        return {
            "tool": "Semgrep Baseline",
            "semgrep_installed": False,
            "status": "NOT_RUN",
            "reason": "Semgrep executable was not available; no detection metrics are reported.",
            "total_cases": 0,
            "total_tp": None,
            "total_fp": None,
            "total_fn": None,
            "total_tn": None,
            "precision": None,
            "recall": None,
            "f1": None,
            "cases": [],
        }

    semgrep_cases = []
    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_tn = 0

    diagnostic_manifest = json.loads(DIAGNOSTIC_MANIFEST_PATH.read_text(encoding="utf-8"))

    for case in diagnostic_manifest["cases"]:
        src_path = ROOT / "commag" / "evaluation" / case["file"].replace("diagnostic_corpus/", "")
        if not src_path.exists():
            src_path = ROOT / "commag" / "evaluation" / case["file"]

        expected_codes = case["expected_warnings"]
        has_expected_violation = len(expected_codes) > 0

        observed_semgrep_findings = 0
        if semgrep_available:
            cmd = ["semgrep", "--config", str(SEMGREP_RULES_PATH), str(src_path), "--json"]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0:
                try:
                    data = json.loads(proc.stdout)
                    observed_semgrep_findings = len(data.get("results", []))
                except Exception:
                    pass

        # Semgrep detection score logic
        if has_expected_violation and observed_semgrep_findings > 0:
            tp, fp, fn, tn = 1, 0, 0, 0
        elif has_expected_violation and observed_semgrep_findings == 0:
            tp, fp, fn, tn = 0, 0, 1, 0
        elif not has_expected_violation and observed_semgrep_findings > 0:
            tp, fp, fn, tn = 0, 1, 0, 0
        else:
            tp, fp, fn, tn = 0, 0, 0, 1

        total_tp += tp
        total_fp += fp
        total_fn += fn
        total_tn += tn

        semgrep_cases.append({
            "case_id": case["case_id"],
            "expected_violation": has_expected_violation,
            "semgrep_findings": observed_semgrep_findings,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn
        })

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else (1.0 if total_tn > 0 else 0.0)
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else (1.0 if total_tn > 0 else 0.0)
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tool": "Semgrep Baseline",
        "semgrep_installed": True,
        "status": "PASS",
        "total_cases": len(semgrep_cases),
        "total_tp": total_tp,
        "total_fp": total_fp,
        "total_fn": total_fn,
        "total_tn": total_tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "cases": semgrep_cases
    }


def run_scaling_benchmark() -> list[dict]:
    manifest = json.loads(SCALING_MANIFEST_PATH.read_text(encoding="utf-8"))
    contract = load_contract(ROOT / "commag" / "evaluation" / "dev_corpus" / "dev_01_clean_direct" / "contract.json")

    scaling_results = []
    for entry in manifest:
        src_path = ROOT / "commag" / "evaluation" / entry["file"].replace("scaling_corpus/", "")
        if not src_path.exists():
            src_path = ROOT / "commag" / "evaluation" / entry["file"]

        loc, ast_nodes = count_loc_and_ast(src_path)

        start_t = time.perf_counter()
        violations = verify_file(contract, src_path)
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0

        scaling_results.append({
            "target_loc": entry["target_loc"],
            "actual_loc": loc,
            "ast_nodes": ast_nodes,
            "verification_time_ms": round(elapsed_ms, 3),
            "loc_per_sec": round((loc / (elapsed_ms / 1000.0)), 1) if elapsed_ms > 0 else 0.0
        })

    return scaling_results


def main() -> int:
    print("==========================================================================")
    print("CPD VERIFIER DIAGNOSTIC EVALUATION RUNNER")
    print("==========================================================================")

    # 1. Dev Corpus
    print("\n--- Running 20 Development Cases ---")
    dev_results = run_suite(DEV_MANIFEST_PATH, "dev_corpus")
    print(f"Dev Corpus: Accuracy={dev_results['case_accuracy']*100:.1f}%, Precision={dev_results['precision']}, Recall={dev_results['recall']}, F1={dev_results['f1']}")

    # 2. Freeze Verifier
    verifier_hash = compute_file_hash(VERIFIER_PATH)
    print("\n--------------------------------------------------------------------------")
    print(f"RECORDING VERIFIER HASH FOR REPRODUCIBILITY:")
    print(f"  Verifier Path: {VERIFIER_PATH}")
    print(f"  Verifier SHA-256: {verifier_hash}")
    print("--------------------------------------------------------------------------")

    # 3. Diagnostic Corpus (Evaluated on Frozen Verifier)
    print("\n--- Running 10 Diagnostic Cases (not a blind benchmark) ---")
    diagnostic_results = run_suite(DIAGNOSTIC_MANIFEST_PATH, "diagnostic_corpus")
    print(f"Diagnostic Corpus: Accuracy={diagnostic_results['case_accuracy']*100:.1f}%, Precision={diagnostic_results['precision']}, Recall={diagnostic_results['recall']}, F1={diagnostic_results['f1']}")

    # 4. Mandatory Semgrep Baseline
    print("\n--- Attempting Semgrep on Diagnostic Corpus ---")
    semgrep_results = run_semgrep_baseline(diagnostic_results)
    if semgrep_results["status"] == "NOT_RUN":
        print("Semgrep: NOT RUN (executable unavailable)")
    else:
        print(f"Semgrep Baseline: Precision={semgrep_results['precision']}, Recall={semgrep_results['recall']}, F1={semgrep_results['f1']}")

    # 5. Scaling Benchmark
    print("\n--- Running Scaling Benchmark Suite (100 to 5000 LOC) ---")
    scaling_results = run_scaling_benchmark()
    for sr in scaling_results:
        print(f"  [{sr['actual_loc']} LOC / {sr['ast_nodes']} AST nodes]: {sr['verification_time_ms']} ms ({sr['loc_per_sec']} LOC/sec)")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Output JSON summary
    eval_summary = {
        "verifier_sha256": verifier_hash,
        "dev_corpus": dev_results,
        "diagnostic_corpus": diagnostic_results,
        "semgrep_baseline": semgrep_results,
        "scaling_benchmark": scaling_results
    }
    (RESULTS_DIR / "evaluation_results.json").write_text(json.dumps(eval_summary, indent=2), encoding="utf-8")

    # Output Summary CSV
    summary_csv_path = RESULTS_DIR / "evaluation_summary.csv"
    with open(summary_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["suite", "total_cases", "case_accuracy", "precision", "recall", "f1", "total_time_ms"])
        writer.writerow(["dev_corpus", dev_results["total_cases"], dev_results["case_accuracy"], dev_results["precision"], dev_results["recall"], dev_results["f1"], dev_results["total_time_ms"]])
        writer.writerow(["diagnostic_corpus", diagnostic_results["total_cases"], diagnostic_results["case_accuracy"], diagnostic_results["precision"], diagnostic_results["recall"], diagnostic_results["f1"], diagnostic_results["total_time_ms"]])
        writer.writerow(["semgrep_baseline", semgrep_results["total_cases"], "N/A", semgrep_results["precision"] if semgrep_results["precision"] is not None else "NOT_RUN", semgrep_results["recall"] if semgrep_results["recall"] is not None else "NOT_RUN", semgrep_results["f1"] if semgrep_results["f1"] is not None else "NOT_RUN", "N/A"])

    # Output Scaling CSV
    scaling_csv_path = RESULTS_DIR / "scaling_benchmark.csv"
    with open(scaling_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["target_loc", "actual_loc", "ast_nodes", "verification_time_ms", "loc_per_sec"])
        for sr in scaling_results:
            writer.writerow([sr["target_loc"], sr["actual_loc"], sr["ast_nodes"], sr["verification_time_ms"], sr["loc_per_sec"]])

    print(f"\nEvaluation completed successfully. Results saved to {RESULTS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
