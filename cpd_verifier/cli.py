from __future__ import annotations

import argparse
from pathlib import Path

from .benchmark import format_benchmark_results, run_benchmark, write_benchmark_results
from .contract import ContractError, load_contract
from .experiment import run_experiment, write_experiment_results
from .generator import generate_artifacts
from .verifier import verify_file
from .cpp_verifier import verify_cpp_file


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "experiment":
            experiment_run = run_experiment(
                args.protocol,
                benchmark_max_chain_depth=args.benchmark_max_chain_depth,
                benchmark_iterations=args.benchmark_iterations,
            )
            written_files = write_experiment_results(experiment_run, args.output)
            for file_path in written_files:
                print(f"WROTE: {file_path}")
            return 0

        contract = load_contract(args.contract)
        if args.command == "verify":
            violations = verify_file(contract, args.source)
            if not violations:
                print(f"PASS: {args.source} satisfies {args.contract}")
                return 0

            print(f"FAIL: {args.source} violates {args.contract}")
            for violation in violations:
                print(
                    f"  line {violation.line}: {violation.code}: {violation.message}"
                )
            return 1

        if args.command == "verify-c":
            violations = verify_cpp_file(contract, args.source, extra_args=getattr(args, 'extra_arg', None))
            if not violations:
                print(f"PASS: {args.source} satisfies {args.contract}")
                return 0

            print(f"FAIL: {args.source} violates {args.contract}")
            for violation in violations:
                print(
                    f"  line {violation.line}: {violation.code}: {violation.message}"
                )
            return 1

        if args.command == "benchmark":
            results = run_benchmark(
                contract,
                max_chain_depth=args.max_chain_depth,
                iterations=args.iterations,
            )

            if args.output:
                output_path = write_benchmark_results(
                    results, args.output, args.output_format
                )
                print(f"WROTE: {output_path}")
                return 0

            print(format_benchmark_results(results, args.output_format), end="")
            return 0

        written_files = generate_artifacts(contract, args.output)
        for file_path in written_files:
            relative = Path(file_path)
            print(f"WROTE: {relative}")
        return 0
    except (ContractError, OSError, ValueError) as error:
        print(f"ERROR: {error}")
        return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cpd_verifier")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser("verify", help="verify a Python source file against a contract")
    verify_parser.add_argument("--contract", required=True, help="path to contract JSON")
    verify_parser.add_argument("--source", required=True, help="path to Python source file")

    verify_c_parser = subparsers.add_parser("verify-c", help="verify a C/C++ source file against a contract")
    verify_c_parser.add_argument("--contract", required=True, help="path to contract JSON")
    verify_c_parser.add_argument("--source", required=True, help="path to C/C++ source file")
    verify_c_parser.add_argument("--extra-arg", action="append", default=[], help="extra compiler argument for optional libclang parsing")

    generate_parser = subparsers.add_parser(
        "generate", help="generate approved-path wrapper code"
    )
    generate_parser.add_argument(
        "--contract", required=True, help="path to contract JSON"
    )
    generate_parser.add_argument(
        "--output", required=True, help="directory for generated files"
    )

    benchmark_parser = subparsers.add_parser(
        "benchmark", help="benchmark verifier performance on generated workloads"
    )
    benchmark_parser.add_argument(
        "--contract", required=True, help="path to contract JSON"
    )
    benchmark_parser.add_argument(
        "--max-chain-depth",
        type=int,
        default=5,
        help="maximum helper-chain depth to benchmark",
    )
    benchmark_parser.add_argument(
        "--iterations",
        type=int,
        default=20,
        help="number of verifier runs per benchmark case",
    )
    benchmark_parser.add_argument(
        "--format",
        dest="output_format",
        choices=("text", "json", "csv"),
        default="text",
        help="output format for benchmark results",
    )
    benchmark_parser.add_argument(
        "--output",
        help="write benchmark results to a file instead of stdout",
    )

    experiment_parser = subparsers.add_parser(
        "experiment", help="run the experiment protocol and write result artifacts"
    )
    experiment_parser.add_argument(
        "--protocol", required=True, help="path to experiment protocol JSON"
    )
    experiment_parser.add_argument(
        "--output", required=True, help="directory for experiment result artifacts"
    )
    experiment_parser.add_argument(
        "--benchmark-max-chain-depth",
        type=int,
        default=3,
        help="maximum helper-chain depth for the experiment benchmark pass",
    )
    experiment_parser.add_argument(
        "--benchmark-iterations",
        type=int,
        default=10,
        help="number of verifier runs per experiment benchmark case",
    )
    return parser