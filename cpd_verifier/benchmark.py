from __future__ import annotations

import csv
import io
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter

from .model import BufferContract, Contract
from .verifier import verify_source


BENCHMARK_FIELDS = (
    "buffer_name",
    "case_name",
    "chain_depth",
    "iterations",
    "average_ms",
    "median_ms",
    "p90_ms",
    "p95_ms",
    "max_ms",
    "violation_count",
)


@dataclass(frozen=True)
class BenchmarkResult:
    buffer_name: str
    case_name: str
    chain_depth: int
    iterations: int
    average_ms: float
    median_ms: float
    p90_ms: float
    p95_ms: float
    max_ms: float
    violation_count: int


def run_benchmark(
    contract: Contract, *, max_chain_depth: int = 5, iterations: int = 20
) -> list[BenchmarkResult]:
    if max_chain_depth < 0:
        raise ValueError("max_chain_depth must be non-negative")
    if iterations < 1:
        raise ValueError("iterations must be at least 1")
    if not contract.sensitive_buffers:
        raise ValueError("benchmark requires at least one sensitive buffer")

    results: list[BenchmarkResult] = []
    for buffer in contract.sensitive_buffers:
        for chain_depth in range(max_chain_depth + 1):
            results.append(
                _measure_case(
                    contract,
                    buffer,
                    case_name="safe",
                    chain_depth=chain_depth,
                    iterations=iterations,
                    source=_build_safe_source(buffer, chain_depth),
                )
            )
            results.append(
                _measure_case(
                    contract,
                    buffer,
                    case_name="violation",
                    chain_depth=chain_depth,
                    iterations=iterations,
                    source=_build_violation_source(buffer, chain_depth),
                )
            )
    return results


def format_benchmark_results(
    results: list[BenchmarkResult], output_format: str = "text"
) -> str:
    if output_format == "text":
        return "\n".join(_format_text_result(result) for result in results) + "\n"

    if output_format == "json":
        return json.dumps([_result_to_dict(result) for result in results], indent=2) + "\n"

    if output_format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=BENCHMARK_FIELDS)
        writer.writeheader()
        for result in results:
            writer.writerow(_result_to_dict(result))
        return buffer.getvalue()

    raise ValueError(f"unsupported benchmark output format '{output_format}'")


def write_benchmark_results(
    results: list[BenchmarkResult], output_path: str | Path, output_format: str
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        format_benchmark_results(results, output_format),
        encoding="utf-8",
    )
    return path


def _measure_case(
    contract: Contract,
    buffer: BufferContract,
    *,
    case_name: str,
    chain_depth: int,
    iterations: int,
    source: str,
) -> BenchmarkResult:
    durations_ms: list[float] = []
    violation_count = 0

    for _ in range(iterations):
        start_time = perf_counter()
        violations = verify_source(contract, source)
        durations_ms.append((perf_counter() - start_time) * 1000.0)
        violation_count = len(violations)

    durations_sorted = sorted(durations_ms)
    avg = sum(durations_sorted) / len(durations_sorted)
    mx = max(durations_sorted)
    def _percentile(values: list[float], p: float) -> float:
        if not values:
            return 0.0
        # linear interpolation between closest ranks
        k = (len(values) - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return values[int(k)]
        d0 = values[f] * (c - k)
        d1 = values[c] * (k - f)
        return d0 + d1

    median_ms = _percentile(durations_sorted, 50.0)
    p90_ms = _percentile(durations_sorted, 90.0)
    p95_ms = _percentile(durations_sorted, 95.0)

    return BenchmarkResult(
        buffer_name=buffer.name,
        case_name=case_name,
        chain_depth=chain_depth,
        iterations=iterations,
        average_ms=avg,
        median_ms=median_ms,
        p90_ms=p90_ms,
        p95_ms=p95_ms,
        max_ms=mx,
        violation_count=violation_count,
    )


def _format_text_result(result: BenchmarkResult) -> str:
    return (
        "BENCHMARK: "
        f"buffer={result.buffer_name} "
        f"case={result.case_name} "
        f"chain_depth={result.chain_depth} "
        f"iterations={result.iterations} "
        f"average_ms={result.average_ms:.3f} "
        f"median_ms={result.median_ms:.3f} "
        f"p90_ms={result.p90_ms:.3f} "
        f"p95_ms={result.p95_ms:.3f} "
        f"max_ms={result.max_ms:.3f} "
        f"violations={result.violation_count}"
    )


def _result_to_dict(result: BenchmarkResult) -> dict[str, object]:
    return dict(asdict(result))


def _build_safe_source(buffer: BufferContract, chain_depth: int) -> str:
    wrapper_name = _wrapper_name(buffer)
    entry_call_name = _entry_call_name(buffer.name, chain_depth, wrapper_name)
    helper_definitions = _build_helper_definitions(
        buffer.name,
        chain_depth,
        final_call_name=wrapper_name,
    )

    return (
        f"{helper_definitions}\n\n"
        f"def publish_{buffer.name}({buffer.name}, {buffer.name}_len):\n"
        f"    status = {entry_call_name}({buffer.name}, {buffer.name}_len)\n"
        f"    secure_zeroize({buffer.name}, {buffer.name}_len)\n"
        f"    return status\n"
    )


def _build_violation_source(buffer: BufferContract, chain_depth: int) -> str:
    forbidden_sink = buffer.forbidden_sinks[0]
    entry_call_name = _entry_call_name(buffer.name, chain_depth, forbidden_sink)
    helper_definitions = _build_helper_definitions(
        buffer.name,
        chain_depth,
        final_call_name=forbidden_sink,
    )

    return (
        f"{helper_definitions}\n\n"
        f"def publish_{buffer.name}({buffer.name}, {buffer.name}_len):\n"
        f"    return {entry_call_name}({buffer.name}, {buffer.name}_len)\n"
    )


def _build_helper_definitions(
    buffer_name: str, chain_depth: int, *, final_call_name: str
) -> str:
    if chain_depth == 0:
        return ""

    definitions: list[str] = []
    next_call_name = final_call_name
    for helper_index in range(chain_depth):
        helper_name = _helper_name(buffer_name, helper_index)
        definitions.append(
            f"def {helper_name}(buffer, length):\n"
            f"    return {next_call_name}(buffer, length)"
        )
        next_call_name = helper_name
    return "\n\n".join(definitions)


def _entry_call_name(buffer_name: str, chain_depth: int, final_call_name: str) -> str:
    if chain_depth == 0:
        return final_call_name
    return _helper_name(buffer_name, chain_depth - 1)


def _helper_name(buffer_name: str, helper_index: int) -> str:
    return f"cpd_verifier_chain_{buffer_name}_{helper_index}"


def _wrapper_name(buffer: BufferContract) -> str:
    if buffer.allowed_sinks:
        return buffer.allowed_sinks[0]
    return f"cpd_verifier_send_{buffer.name}"