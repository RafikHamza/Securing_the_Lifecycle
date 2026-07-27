from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter
from typing import Any

from .benchmark import BENCHMARK_FIELDS, run_benchmark
import math
from .contract import load_contract
from .model import Contract
from .verifier import verify_source


CASE_RESULT_FIELDS = (
    "case_id",
    "category",
    "contract_path",
    "source_files",
    "source_file_count",
    "line_count",
    "expected_codes",
    "actual_codes",
    "exact_match",
    "true_positives",
    "false_positives",
    "false_negatives",
    "precision",
    "recall",
    "f1",
    "elapsed_ms",
)
BENCHMARK_RESULT_FIELDS = ("contract_path", "module") + BENCHMARK_FIELDS
PROTOCOL_OUTPUT_KEYS = (
    "summary_json",
    "case_results_csv",
    "benchmark_results_csv",
    "benchmark_results_json",
    "report_markdown",
)


@dataclass(frozen=True)
class ResearchQuestion:
    question_id: str
    title: str
    description: str
    metrics: tuple[str, ...]


@dataclass(frozen=True)
class ExperimentProtocol:
    name: str
    version: str
    corpus_manifest: str
    research_questions: tuple[ResearchQuestion, ...]
    outputs: dict[str, str]


@dataclass(frozen=True)
class CorpusCase:
    case_id: str
    category: str
    contract_label: str
    source_labels: tuple[str, ...]
    contract_path: Path
    source_paths: tuple[Path, ...]
    expected_codes: tuple[str, ...]


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    category: str
    contract_path: str
    source_files: tuple[str, ...]
    source_file_count: int
    line_count: int
    expected_codes: tuple[str, ...]
    actual_codes: tuple[str, ...]
    exact_match: bool
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    elapsed_ms: float


@dataclass(frozen=True)
class ExperimentRun:
    protocol: ExperimentProtocol
    summary: dict[str, Any]
    case_results: tuple[CaseResult, ...]
    benchmark_rows: tuple[dict[str, Any], ...]


def load_protocol(protocol_path: str | Path) -> ExperimentProtocol:
    path = Path(protocol_path)
    raw = json.loads(path.read_text(encoding="utf-8"))

    research_questions_raw = raw.get("research_questions")
    if not isinstance(research_questions_raw, list) or not research_questions_raw:
        raise ValueError("protocol must define a non-empty 'research_questions' list")

    outputs_raw = raw.get("outputs")
    if not isinstance(outputs_raw, dict):
        raise ValueError("protocol must define an 'outputs' object")

    research_questions = tuple(
        _parse_research_question(question_raw) for question_raw in research_questions_raw
    )
    outputs = {
        key: _require_non_empty_string(outputs_raw, key) for key in PROTOCOL_OUTPUT_KEYS
    }
    return ExperimentProtocol(
        name=_require_non_empty_string(raw, "name"),
        version=_require_non_empty_string(raw, "version"),
        corpus_manifest=_require_non_empty_string(raw, "corpus_manifest"),
        research_questions=research_questions,
        outputs=outputs,
    )


def load_corpus_cases(manifest_path: str | Path) -> tuple[CorpusCase, ...]:
    path = Path(manifest_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    cases_raw = raw.get("cases")
    if not isinstance(cases_raw, list) or not cases_raw:
        raise ValueError("corpus manifest must define a non-empty 'cases' list")

    base_dir = path.parent
    return tuple(_parse_corpus_case(case_raw, base_dir) for case_raw in cases_raw)


def run_experiment(
    protocol_path: str | Path,
    *,
    benchmark_max_chain_depth: int = 3,
    benchmark_iterations: int = 10,
) -> ExperimentRun:
    protocol = load_protocol(protocol_path)
    protocol_file = Path(protocol_path)
    manifest_path = (protocol_file.parent / protocol.corpus_manifest).resolve()
    cases = load_corpus_cases(manifest_path)

    contract_cache: dict[Path, Contract] = {}
    case_results: list[CaseResult] = []
    for case in cases:
        contract = contract_cache.get(case.contract_path)
        if contract is None:
            contract = load_contract(case.contract_path)
            contract_cache[case.contract_path] = contract
        case_results.append(_run_case(case, contract))

    benchmark_rows: list[dict[str, Any]] = []
    for contract_path, contract in sorted(
        contract_cache.items(), key=lambda item: item[0].as_posix()
    ):
        for result in run_benchmark(
            contract,
            max_chain_depth=benchmark_max_chain_depth,
            iterations=benchmark_iterations,
        ):
            row = dict(asdict(result))
            row["contract_path"] = contract_path.as_posix()
            row["module"] = contract.module
            benchmark_rows.append(row)

    summary = _summarize_results(case_results, benchmark_rows)
    return ExperimentRun(
        protocol=protocol,
        summary=summary,
        case_results=tuple(case_results),
        benchmark_rows=tuple(benchmark_rows),
    )


def write_experiment_results(
    experiment_run: ExperimentRun, output_dir: str | Path
) -> tuple[Path, ...]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    summary_path = output_path / experiment_run.protocol.outputs["summary_json"]
    case_results_path = output_path / experiment_run.protocol.outputs["case_results_csv"]
    benchmark_results_csv_path = (
        output_path / experiment_run.protocol.outputs["benchmark_results_csv"]
    )
    benchmark_results_json_path = (
        output_path / experiment_run.protocol.outputs["benchmark_results_json"]
    )
    report_markdown_path = (
        output_path / experiment_run.protocol.outputs["report_markdown"]
    )

    summary_payload = {
        "protocol": {
            "name": experiment_run.protocol.name,
            "version": experiment_run.protocol.version,
            "research_questions": [
                asdict(question) for question in experiment_run.protocol.research_questions
            ],
        },
        "summary": experiment_run.summary,
    }
    summary_path.write_text(
        json.dumps(summary_payload, indent=2) + "\n",
        encoding="utf-8",
    )
    _write_csv(
        case_results_path,
        CASE_RESULT_FIELDS,
        [_case_result_to_row(result) for result in experiment_run.case_results],
    )
    _write_csv(
        benchmark_results_csv_path,
        BENCHMARK_RESULT_FIELDS,
        [dict(row) for row in experiment_run.benchmark_rows],
    )
    benchmark_results_json_path.write_text(
        json.dumps(list(experiment_run.benchmark_rows), indent=2) + "\n",
        encoding="utf-8",
    )
    report_markdown_path.write_text(
        render_experiment_report(experiment_run),
        encoding="utf-8",
    )
    return (
        summary_path,
        case_results_path,
        benchmark_results_csv_path,
        benchmark_results_json_path,
        report_markdown_path,
    )


def render_experiment_report(experiment_run: ExperimentRun) -> str:
    summary = experiment_run.summary
    rq_results = summary["research_question_results"]
    rq_titles = {
        question.question_id: question.title
        for question in experiment_run.protocol.research_questions
    }

    lines = [
        "# CPDVerifier Experiment Report",
        "",
        f"Protocol: {experiment_run.protocol.name} v{experiment_run.protocol.version}",
        "",
        "## Corpus Overview",
        "",
        *_render_markdown_table(
            ("Metric", "Value"),
            (
                ("Total cases", str(summary["total_cases"])),
                ("Exact matches", str(summary["exact_matches"])),
                (
                    "Exact match rate",
                    _format_ratio(summary["exact_match_rate"]),
                ),
                ("Source files", str(summary["source_file_count"])),
                ("Lines", str(summary["line_count"])),
            ),
        ),
        "",
        f"## {rq_titles['RQ1']}",
        "",
        *_render_markdown_table(
            ("Metric", "Value"),
            (
                (
                    "Exact match rate",
                    _format_ratio(rq_results["RQ1"]["exact_match_rate"]),
                ),
                (
                    "Macro precision",
                    _format_ratio(rq_results["RQ1"]["macro_precision"]),
                ),
                (
                    "Macro recall",
                    _format_ratio(rq_results["RQ1"]["macro_recall"]),
                ),
                (
                    "Macro F1",
                    _format_ratio(rq_results["RQ1"]["macro_f1"]),
                ),
            ),
        ),
        "",
        f"## {rq_titles['RQ2']}",
        "",
        "### Category Coverage",
        "",
        *_render_markdown_table(
            ("Category", "Cases", "Exact matches", "Exact match rate", "Mean verify ms"),
            tuple(
                (
                    category,
                    str(category_summary["cases"]),
                    str(category_summary["exact_matches"]),
                    _format_ratio(category_summary["exact_match_rate"]),
                    _format_ms(category_summary["mean_verify_ms"]),
                )
                for category, category_summary in sorted(
                    rq_results["RQ2"]["per_category"].items()
                )
            ),
        ),
        "",
        "### Violation Coverage",
        "",
        *_render_markdown_table(
            ("Violation code", "Expected cases", "Detected cases", "False positive cases"),
            tuple(
                (
                    code,
                    str(code_summary["expected_cases"]),
                    str(code_summary["detected_cases"]),
                    str(code_summary["false_positive_cases"]),
                )
                for code, code_summary in sorted(
                    rq_results["RQ2"]["per_violation_code"].items()
                )
            ),
        ),
        "",
        f"## {rq_titles['RQ3']}",
        "",
        *_render_markdown_table(
            ("Metric", "Value"),
            (
                ("Mean case verify ms", _format_ms(rq_results["RQ3"]["mean_case_verify_ms"])),
                ("Median case verify ms", _format_ms(rq_results["RQ3"]["median_case_verify_ms"])),
                ("P90 case verify ms", _format_ms(rq_results["RQ3"]["p90_case_verify_ms"])),
                ("P95 case verify ms", _format_ms(rq_results["RQ3"]["p95_case_verify_ms"])),
                ("Max case verify ms", _format_ms(rq_results["RQ3"]["max_case_verify_ms"])),
                ("Benchmark result count", str(rq_results["RQ3"]["benchmark_result_count"])),
                ("Mean benchmark average ms", _format_ms(rq_results["RQ3"]["mean_benchmark_average_ms"])),
                ("Median benchmark average ms", _format_ms(rq_results["RQ3"]["median_benchmark_average_ms"])),
                ("P90 benchmark average ms", _format_ms(rq_results["RQ3"]["p90_benchmark_average_ms"])),
                ("P95 benchmark average ms", _format_ms(rq_results["RQ3"]["p95_benchmark_average_ms"])),
                ("Max benchmark ms", _format_ms(rq_results["RQ3"]["max_benchmark_ms"])),
            ),
        ),
        "",
    ]
    return "\n".join(lines)


def _parse_research_question(raw: Any) -> ResearchQuestion:
    if not isinstance(raw, dict):
        raise ValueError("each research question must be an object")
    metrics = raw.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        raise ValueError("each research question must define a non-empty 'metrics' list")
    return ResearchQuestion(
        question_id=_require_non_empty_string(raw, "id"),
        title=_require_non_empty_string(raw, "title"),
        description=_require_non_empty_string(raw, "description"),
        metrics=tuple(_ensure_non_empty_string(metric, "metrics entry") for metric in metrics),
    )


def _parse_corpus_case(raw: Any, base_dir: Path) -> CorpusCase:
    if not isinstance(raw, dict):
        raise ValueError("each corpus case must be an object")

    sources_raw = raw.get("sources")
    if not isinstance(sources_raw, list) or not sources_raw:
        raise ValueError("each corpus case must define a non-empty 'sources' list")

    expected_codes_raw = raw.get("expected_codes", [])
    if not isinstance(expected_codes_raw, list):
        raise ValueError("'expected_codes' must be a list of strings")

    contract_label = _require_non_empty_string(raw, "contract")
    source_labels = tuple(
        _ensure_non_empty_string(source, "source path") for source in sources_raw
    )
    expected_codes = tuple(
        _ensure_non_empty_string(code, "expected code") for code in expected_codes_raw
    )
    return CorpusCase(
        case_id=_require_non_empty_string(raw, "case_id"),
        category=_require_non_empty_string(raw, "category"),
        contract_label=contract_label,
        source_labels=source_labels,
        contract_path=(base_dir / contract_label).resolve(),
        source_paths=tuple((base_dir / label).resolve() for label in source_labels),
        expected_codes=expected_codes,
    )


def _run_case(case: CorpusCase, contract: Contract) -> CaseResult:
    combined_source, line_count = _load_case_source(case.source_paths)
    start_time = perf_counter()
    violations = verify_source(contract, combined_source)
    elapsed_ms = (perf_counter() - start_time) * 1000.0

    expected_codes = set(case.expected_codes)
    actual_codes = {violation.code for violation in violations}
    true_positives = len(expected_codes.intersection(actual_codes))
    false_positives = len(actual_codes - expected_codes)
    false_negatives = len(expected_codes - actual_codes)
    precision, recall, f1 = _compute_scores(
        true_positives, false_positives, false_negatives
    )
    return CaseResult(
        case_id=case.case_id,
        category=case.category,
        contract_path=case.contract_label,
        source_files=case.source_labels,
        source_file_count=len(case.source_paths),
        line_count=line_count,
        expected_codes=tuple(sorted(expected_codes)),
        actual_codes=tuple(sorted(actual_codes)),
        exact_match=expected_codes == actual_codes,
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        f1=f1,
        elapsed_ms=elapsed_ms,
    )


def _load_case_source(source_paths: tuple[Path, ...]) -> tuple[str, int]:
    texts: list[str] = []
    total_lines = 0
    for source_path in source_paths:
        text = source_path.read_text(encoding="utf-8")
        texts.append(text)
        total_lines += len(text.splitlines())
    return "\n\n".join(texts), total_lines


def _compute_scores(
    true_positives: int, false_positives: int, false_negatives: int
) -> tuple[float, float, float]:
    if true_positives == 0 and false_positives == 0 and false_negatives == 0:
        return 1.0, 1.0, 1.0

    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives
    precision = (
        true_positives / precision_denominator if precision_denominator else 0.0
    )
    recall = true_positives / recall_denominator if recall_denominator else 0.0
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return precision, recall, f1


def _summarize_results(
    case_results: list[CaseResult], benchmark_rows: list[dict[str, Any]]
) -> dict[str, Any]:
    total_cases = len(case_results)
    exact_matches = sum(1 for result in case_results if result.exact_match)
    macro_precision = _mean(result.precision for result in case_results)
    macro_recall = _mean(result.recall for result in case_results)
    macro_f1 = _mean(result.f1 for result in case_results)
    mean_case_verify_ms = _mean(result.elapsed_ms for result in case_results)
    max_case_verify_ms = max((result.elapsed_ms for result in case_results), default=0.0)

    per_category: dict[str, dict[str, Any]] = {}
    per_violation_code: dict[str, dict[str, int]] = {}
    for result in case_results:
        category_summary = per_category.setdefault(
            result.category,
            {
                "cases": 0,
                "exact_matches": 0,
                "exact_match_rate": 0.0,
                "mean_verify_ms": 0.0,
                "line_count": 0,
            },
        )
        category_summary["cases"] += 1
        category_summary["line_count"] += result.line_count
        category_summary["mean_verify_ms"] += result.elapsed_ms
        if result.exact_match:
            category_summary["exact_matches"] += 1

        expected_codes = set(result.expected_codes)
        actual_codes = set(result.actual_codes)
        for code in expected_codes:
            code_summary = per_violation_code.setdefault(
                code,
                {
                    "expected_cases": 0,
                    "detected_cases": 0,
                    "false_positive_cases": 0,
                },
            )
            code_summary["expected_cases"] += 1
            if code in actual_codes:
                code_summary["detected_cases"] += 1

        for code in actual_codes - expected_codes:
            code_summary = per_violation_code.setdefault(
                code,
                {
                    "expected_cases": 0,
                    "detected_cases": 0,
                    "false_positive_cases": 0,
                },
            )
            code_summary["false_positive_cases"] += 1

    for category_summary in per_category.values():
        category_summary["exact_match_rate"] = (
            category_summary["exact_matches"] / category_summary["cases"]
            if category_summary["cases"]
            else 0.0
        )
        category_summary["mean_verify_ms"] = (
            category_summary["mean_verify_ms"] / category_summary["cases"]
            if category_summary["cases"]
            else 0.0
        )

    mean_benchmark_average_ms = _mean(float(row["average_ms"]) for row in benchmark_rows)
    max_benchmark_ms = max((float(row["max_ms"]) for row in benchmark_rows), default=0.0)

    # compute median and percentile metrics for case verification times
    case_times = [result.elapsed_ms for result in case_results]
    def _percentile(values: list[float], p: float) -> float:
        values = sorted(values)
        if not values:
            return 0.0
        k = (len(values) - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return values[int(k)]
        return values[f] * (c - k) + values[c] * (k - f)

    median_case_verify_ms = _percentile(case_times, 50.0)
    p90_case_verify_ms = _percentile(case_times, 90.0)
    p95_case_verify_ms = _percentile(case_times, 95.0)

    # compute median and percentile metrics for benchmark averages
    benchmark_avgs = [float(row["average_ms"]) for row in benchmark_rows]
    median_benchmark_average_ms = _percentile(benchmark_avgs, 50.0)
    p90_benchmark_average_ms = _percentile(benchmark_avgs, 90.0)
    p95_benchmark_average_ms = _percentile(benchmark_avgs, 95.0)

    return {
        "total_cases": total_cases,
        "exact_matches": exact_matches,
        "exact_match_rate": exact_matches / total_cases if total_cases else 0.0,
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "macro_f1": macro_f1,
        "mean_case_verify_ms": mean_case_verify_ms,
        "max_case_verify_ms": max_case_verify_ms,
        "line_count": sum(result.line_count for result in case_results),
        "source_file_count": sum(result.source_file_count for result in case_results),
        "per_category": per_category,
        "per_violation_code": per_violation_code,
        "research_question_results": {
            "RQ1": {
                "exact_match_rate": exact_matches / total_cases if total_cases else 0.0,
                "macro_precision": macro_precision,
                "macro_recall": macro_recall,
                "macro_f1": macro_f1,
            },
            "RQ2": {
                "per_category": per_category,
                "per_violation_code": per_violation_code,
            },
            "RQ3": {
                "mean_case_verify_ms": mean_case_verify_ms,
                "median_case_verify_ms": median_case_verify_ms,
                "p90_case_verify_ms": p90_case_verify_ms,
                "p95_case_verify_ms": p95_case_verify_ms,
                "max_case_verify_ms": max_case_verify_ms,
                "benchmark_result_count": len(benchmark_rows),
                "mean_benchmark_average_ms": mean_benchmark_average_ms,
                "median_benchmark_average_ms": median_benchmark_average_ms,
                "p90_benchmark_average_ms": p90_benchmark_average_ms,
                "p95_benchmark_average_ms": p95_benchmark_average_ms,
                "max_benchmark_ms": max_benchmark_ms,
            },
        },
    }


def _case_result_to_row(result: CaseResult) -> dict[str, Any]:
    return {
        "case_id": result.case_id,
        "category": result.category,
        "contract_path": result.contract_path,
        "source_files": ";".join(result.source_files),
        "source_file_count": result.source_file_count,
        "line_count": result.line_count,
        "expected_codes": ";".join(result.expected_codes),
        "actual_codes": ";".join(result.actual_codes),
        "exact_match": result.exact_match,
        "true_positives": result.true_positives,
        "false_positives": result.false_positives,
        "false_negatives": result.false_negatives,
        "precision": result.precision,
        "recall": result.recall,
        "f1": result.f1,
        "elapsed_ms": result.elapsed_ms,
    }


def _write_csv(path: Path, fieldnames: tuple[str, ...], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _render_markdown_table(
    headers: tuple[str, ...], rows: tuple[tuple[str, ...], ...]
) -> list[str]:
    header_row = "| " + " | ".join(headers) + " |"
    separator_row = "| " + " | ".join("---" for _ in headers) + " |"
    body_rows = ["| " + " | ".join(row) + " |" for row in rows]
    return [header_row, separator_row, *body_rows]


def _format_ratio(value: float) -> str:
    return f"{value:.3f}"


def _format_ms(value: float) -> str:
    return f"{value:.3f}"


def _mean(values) -> float:
    values = list(values)
    if not values:
        return 0.0
    return sum(values) / len(values)


def _require_non_empty_string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    return _ensure_non_empty_string(value, key)


def _ensure_non_empty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value.strip()