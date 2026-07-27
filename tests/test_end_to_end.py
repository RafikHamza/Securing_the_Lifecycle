from __future__ import annotations

import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from cpd_verifier.benchmark import format_benchmark_results, run_benchmark
from cpd_verifier.cli import main
from cpd_verifier.contract import ContractError, load_contract, parse_contract
from cpd_verifier.generator import generate_artifacts
from cpd_verifier.verifier import verify_file, verify_source


class CPDVerifierEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.examples_dir = cls.repo_root / "examples"
        cls.contract_path = cls.examples_dir / "camera_roi.contract.json"
        cls.good_source_path = cls.examples_dir / "camera_roi_good.py"
        cls.faulty_source_path = cls.examples_dir / "camera_roi_faulty.py"

    def test_contract_loads(self) -> None:
        contract = load_contract(self.contract_path)
        self.assertEqual(contract.module, "camera_roi")
        self.assertEqual(len(contract.sensitive_buffers), 1)
        self.assertEqual(contract.sensitive_buffers[0].allowed_sinks, ("cpd_verifier_send_roi",))
        self.assertTrue(contract.sensitive_buffers[0].forbid_post_send_use)

    def test_contract_rejects_legacy_backend_field(self) -> None:
        raw = {
            "module": "camera_roi",
            "backend": {"transform": "rolling_xor"},
            "buffers": [
                {
                    "name": "roi",
                    "allowed_sinks": ["cpd_verifier_send_roi"],
                    "forbidden_sinks": ["net_send"],
                    "transport_sink": "net_send_encrypted",
                }
            ],
        }
        with self.assertRaises(ContractError):
            parse_contract(raw)

    def test_verifier_accepts_protected_example(self) -> None:
        contract = load_contract(self.contract_path)
        violations = verify_file(contract, self.good_source_path)
        self.assertEqual(violations, [])

    def test_verifier_rejects_plaintext_send(self) -> None:
        contract = load_contract(self.contract_path)
        violations = verify_file(contract, self.faulty_source_path)
        codes = {violation.code for violation in violations}
        self.assertEqual(codes, {"forbidden-sink", "missing-zeroize"})

    def test_verifier_rejects_transport_bypass(self) -> None:
        contract = load_contract(self.contract_path)
        source = """
def publish_roi(roi, roi_len):
    status = net_send_encrypted(roi, roi_len)
    secure_zeroize(roi, roi_len)
    return status
        """
        violations = verify_source(contract, source)
        codes = {violation.code for violation in violations}
        self.assertEqual(codes, {"transport-bypass"})

    def test_verifier_tracks_simple_aliases(self) -> None:
        contract = load_contract(self.contract_path)
        source = """
def publish_roi(roi, roi_len):
    alias = roi
    return net_send(alias, roi_len)
        """
        violations = verify_source(contract, source)
        codes = {violation.code for violation in violations}
        self.assertEqual(codes, {"forbidden-sink", "missing-zeroize"})

    def test_verifier_reports_missing_zeroize_per_function(self) -> None:
        contract = load_contract(self.contract_path)
        source = """
def publish_without_zeroize(roi, roi_len):
    return cpd_verifier_send_roi(roi, roi_len)

def publish_with_zeroize(roi, roi_len):
    status = cpd_verifier_send_roi(roi, roi_len)
    secure_zeroize(roi, roi_len)
    return status
        """
        violations = verify_source(contract, source)
        codes = [violation.code for violation in violations]
        self.assertEqual(codes.count("missing-zeroize"), 1)

    def test_verifier_resets_aliases_between_functions(self) -> None:
        contract = load_contract(self.contract_path)
        source = """
def prepare_roi(roi, roi_len):
    alias = roi
    secure_zeroize(alias, roi_len)
    return 0

def publish_public(alias, alias_len):
    return net_send(alias, alias_len)
        """
        violations = verify_source(contract, source)
        self.assertEqual(violations, [])

    def test_verifier_rejects_post_send_use_before_zeroize(self) -> None:
        contract = load_contract(self.contract_path)
        source = """
def publish_roi(roi, roi_len):
    status = cpd_verifier_send_roi(roi, roi_len)
    audit_roi(roi, roi_len)
    secure_zeroize(roi, roi_len)
    return status
        """
        violations = verify_source(contract, source)
        codes = {violation.code for violation in violations}
        self.assertEqual(codes, {"post-send-use"})

    def test_verifier_tracks_one_hop_helper_forwarding(self) -> None:
        contract = load_contract(self.contract_path)
        source = """
def relay_roi(buffer, length):
    return net_send(buffer, length)

def publish_roi(roi, roi_len):
    return relay_roi(roi, roi_len)
        """
        violations = verify_source(contract, source)
        codes = {violation.code for violation in violations}
        self.assertEqual(codes, {"forbidden-sink", "missing-zeroize"})

    def test_benchmark_reports_safe_and_violation_cases(self) -> None:
        contract = load_contract(self.contract_path)
        results = run_benchmark(contract, max_chain_depth=2, iterations=2)
        self.assertEqual(len(results), 6)

        safe_results = [result for result in results if result.case_name == "safe"]
        violation_results = [
            result for result in results if result.case_name == "violation"
        ]

        self.assertEqual({result.chain_depth for result in safe_results}, {0, 1, 2})
        self.assertTrue(all(result.violation_count == 0 for result in safe_results))
        self.assertTrue(
            all(result.violation_count >= 1 for result in violation_results)
        )

    def test_benchmark_formats_json_and_csv(self) -> None:
        contract = load_contract(self.contract_path)
        results = run_benchmark(contract, max_chain_depth=1, iterations=1)

        json_rows = json.loads(format_benchmark_results(results, "json"))
        csv_rows = list(
            csv.DictReader(io.StringIO(format_benchmark_results(results, "csv")))
        )

        self.assertEqual(len(json_rows), 4)
        self.assertEqual(len(csv_rows), 4)
        self.assertEqual(
            {row["case_name"] for row in json_rows},
            {"safe", "violation"},
        )
        self.assertEqual(
            {row["case_name"] for row in csv_rows},
            {"safe", "violation"},
        )

    def test_generator_writes_wrapper_files(self) -> None:
        contract = load_contract(self.contract_path)
        with tempfile.TemporaryDirectory() as temp_dir:
            written_files = generate_artifacts(contract, temp_dir)
            self.assertEqual(len(written_files), 3)
            header = Path(temp_dir) / "camera_roi_cpd_verifier.h"
            implementation = Path(temp_dir) / "camera_roi_cpd_verifier.c"
            self.assertTrue(header.exists())
            self.assertTrue(implementation.exists())
            header_text = header.read_text(encoding="utf-8")
            implementation_text = implementation.read_text(encoding="utf-8")
            self.assertIn(
                "int cpd_verifier_send_roi(uint8_t *raw_buffer, size_t length);",
                header_text,
            )
            self.assertIn("net_send_encrypted(dispatch_buffer, length)", implementation_text)
            self.assertIn("cpd_verifier_zeroize", implementation_text)
            self.assertNotIn("rolling_xor", implementation_text)

    def test_cli_returns_status_codes(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            success = main(
                [
                    "verify",
                    "--contract",
                    str(self.contract_path),
                    "--source",
                    str(self.good_source_path),
                ]
            )
            failure = main(
                [
                    "verify",
                    "--contract",
                    str(self.contract_path),
                    "--source",
                    str(self.faulty_source_path),
                ]
            )
            benchmark = main(
                [
                    "benchmark",
                    "--contract",
                    str(self.contract_path),
                    "--max-chain-depth",
                    "1",
                    "--iterations",
                    "1",
                ]
            )
        self.assertEqual(success, 0)
        self.assertEqual(failure, 1)
        self.assertEqual(benchmark, 0)

    def test_cli_benchmark_writes_structured_exports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            json_output = Path(temp_dir) / "benchmark.json"
            csv_output = Path(temp_dir) / "benchmark.csv"

            with contextlib.redirect_stdout(io.StringIO()):
                json_status = main(
                    [
                        "benchmark",
                        "--contract",
                        str(self.contract_path),
                        "--max-chain-depth",
                        "1",
                        "--iterations",
                        "1",
                        "--format",
                        "json",
                        "--output",
                        str(json_output),
                    ]
                )
                csv_status = main(
                    [
                        "benchmark",
                        "--contract",
                        str(self.contract_path),
                        "--max-chain-depth",
                        "1",
                        "--iterations",
                        "1",
                        "--format",
                        "csv",
                        "--output",
                        str(csv_output),
                    ]
                )

            self.assertEqual(json_status, 0)
            self.assertEqual(csv_status, 0)
            self.assertTrue(json_output.exists())
            self.assertTrue(csv_output.exists())

            json_rows = json.loads(json_output.read_text(encoding="utf-8"))
            csv_rows = list(
                csv.DictReader(io.StringIO(csv_output.read_text(encoding="utf-8")))
            )
            self.assertEqual(len(json_rows), 4)
            self.assertEqual(len(csv_rows), 4)


if __name__ == "__main__":
    unittest.main()