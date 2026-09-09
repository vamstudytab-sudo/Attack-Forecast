from __future__ import annotations

from pathlib import Path
import io
import zipfile
from typing import BinaryIO, Iterable

import pandas as pd

from backend.runtime.runtime_state import runtime
from backend.ml.predictor import feature_columns

# Large CICIDS captures are sampled deterministically so the dashboard stays
# responsive on ordinary laptops. The same sampled rows drive graph + timeline +
# ML + risk + forecast, so displayed evidence is internally consistent.
ROW_STRIDE = 100
HEAD_ROWS = 150
MAX_SAMPLED_PER_FILE = 10_000
MIN_MODEL_FEATURE_COVERAGE = 0.90


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [str(c).strip() for c in df.columns]
    return df


def _sample_csv_binary_stream(stream: BinaryIO, source_name: str) -> pd.DataFrame:
    """Read a deterministic, bounded sample from a potentially huge CSV stream."""
    try:
        stream.seek(0)
    except Exception:
        pass

    header = stream.readline()
    if not header:
        return pd.DataFrame()

    selected = [header]
    kept = 0
    for row_number, line in enumerate(stream, start=1):
        if row_number <= HEAD_ROWS or row_number % ROW_STRIDE == 0:
            selected.append(line)
            kept += 1
            if kept >= MAX_SAMPLED_PER_FILE:
                break

    if len(selected) == 1:
        return pd.DataFrame()

    data = b"".join(selected)
    # CICIDS exports are normally ASCII/UTF-8 compatible, but latin1 is a safe
    # lossless fallback for odd bytes in labels/headers.
    df = pd.read_csv(
        io.BytesIO(data),
        encoding="latin1",
        on_bad_lines="skip",
        low_memory=False,
    )
    return _normalize_columns(df)


def _sort_by_cic_timestamp(df: pd.DataFrame) -> pd.DataFrame:
    if "Timestamp" not in df.columns:
        return df
    work = df.copy()
    # CICIDS dates are usually day/month/year. Some variants use month/day/year,
    # so parse once with dayfirst and retain original order for unparseable rows.
    parsed = pd.to_datetime(work["Timestamp"], errors="coerce", dayfirst=True)
    work["__parsed_timestamp"] = parsed
    work["__original_order"] = range(len(work))
    work = work.sort_values(["__parsed_timestamp", "__original_order"], na_position="last")
    return work.drop(columns=["__parsed_timestamp", "__original_order"])


def _feature_coverage(df: pd.DataFrame) -> tuple[float, list[str]]:
    present = set(df.columns)
    missing = [c for c in feature_columns if c not in present]
    coverage = (len(feature_columns) - len(missing)) / max(len(feature_columns), 1)
    return coverage, missing


def _inspect_sample(df: pd.DataFrame, source_name: str) -> dict:
    missing_graph = [c for c in ("Source IP", "Destination IP") if c not in df.columns]
    coverage, missing_model = _feature_coverage(df)
    return {
        "source_file": source_name,
        "rows_sampled": len(df),
        "graph_compatible": not missing_graph,
        "missing_graph_columns": missing_graph,
        "model_feature_coverage": round(coverage, 4),
        "model_compatible": coverage >= MIN_MODEL_FEATURE_COVERAGE,
        "missing_model_features": missing_model,
    }


def _prepare_samples(samples: Iterable[tuple[pd.DataFrame, str]]):
    usable: list[pd.DataFrame] = []
    source_files: list[str] = []
    skipped_files: list[dict] = []
    schema_report: list[dict] = []

    for sample, source_name in samples:
        if sample.empty:
            skipped_files.append({"file": source_name, "reason": "No readable rows"})
            continue

        report = _inspect_sample(sample, source_name)
        schema_report.append(report)

        # A host-to-host graph cannot be truthfully generated from the
        # MachineLearningCSV variant because it lacks Source/Destination IP.
        # Ignore such files if the same uploaded folder also contains richer
        # GeneratedLabelledFlows files; fail only if no usable graph file exists.
        if not report["graph_compatible"]:
            skipped_files.append({
                "file": source_name,
                "reason": "Missing Source IP / Destination IP; not usable for host graph",
            })
            continue

        sample = sample.copy()
        sample["__source_file"] = source_name
        sample["__model_compatible"] = bool(report["model_compatible"])
        usable.append(sample)
        source_files.append(source_name)

    if not usable:
        raise ValueError(
            "No graph-compatible CICIDS flow CSV was found. Upload the GeneratedLabelledFlows "
            "folder/ZIP containing Source IP and Destination IP columns."
        )

    # Concatenation here is only over deterministic bounded samples (not the
    # original huge files), keeping memory predictable.
    combined = pd.concat(usable, ignore_index=True, sort=False)
    combined = _sort_by_cic_timestamp(combined)
    return combined, source_files, skipped_files, schema_report


def _run_analysis(combined: pd.DataFrame, dataset_name: str, source_files: list[str], skipped_files: list[dict], schema_report: list[dict], reset: bool):
    if reset:
        runtime.reset()

    runtime.dataset_name = dataset_name
    runtime.analysis_mode = (
        f"folder/CSV analysis using deterministic sampling: first {HEAD_ROWS} rows + every "
        f"{ROW_STRIDE}th flow per compatible CSV, then timestamp ordered"
    )

    runtime.process_sample(combined, "timestamp-ordered uploaded folder sample")
    runtime.source_files = source_files

    runtime.append_timeline(
        event="Dataset analysis completed",
        severity="LOW",
        description=(
            f"Analyzed {runtime.processed_rows:,} flow samples from {len(source_files)} graph-compatible "
            "CSV file(s). The graph and timeline were built from the same uploaded records."
        ),
        event_type="system",
    )

    return {
        "dataset_name": runtime.dataset_name,
        "processed_rows": runtime.processed_rows,
        "source_files": runtime.source_files,
        "skipped_files": skipped_files,
        "schema_report": schema_report,
        "graph_nodes": len(runtime.graph.nodes),
        "graph_edges": len(runtime.graph.edges),
        "timeline_events": len(runtime.timeline),
        "current_stage": runtime.attack_state.current_stage,
        "forecast": runtime.forecast(),
        "risk": runtime.risk_payload(),
    }


def analyze_streams(streams: Iterable[tuple[BinaryIO, str]], display_name: str, reset: bool = True):
    sampled = []
    for stream, source_name in streams:
        try:
            sample = _sample_csv_binary_stream(stream, source_name)
        except Exception as exc:
            sample = pd.DataFrame()
        sampled.append((sample, source_name))

    combined, source_files, skipped_files, schema_report = _prepare_samples(sampled)
    return _run_analysis(combined, display_name, source_files, skipped_files, schema_report, reset)


def analyze_paths(paths: Iterable[tuple[str | Path, str]], display_name: str, reset: bool = True):
    sampled = []
    for raw_path, source_name in paths:
        path = Path(raw_path)
        try:
            with path.open("rb") as stream:
                sample = _sample_csv_binary_stream(stream, source_name)
        except Exception:
            sample = pd.DataFrame()
        sampled.append((sample, source_name))

    combined, source_files, skipped_files, schema_report = _prepare_samples(sampled)
    return _run_analysis(combined, display_name, source_files, skipped_files, schema_report, reset)


def analyze_path(path: str | Path, display_name: str | None = None, reset: bool = True):
    path = Path(path)
    if path.suffix.lower() == ".csv":
        return analyze_paths([(path, path.name)], display_name or path.name, reset=reset)

    if path.suffix.lower() != ".zip":
        raise ValueError("Upload a .csv, .zip, or dataset folder containing CSV files.")

    sampled = []
    with zipfile.ZipFile(path) as zf:
        members = [m for m in zf.namelist() if m.lower().endswith(".csv")]
        if not members:
            raise ValueError("ZIP does not contain any CSV files.")
        for member in members:
            try:
                with zf.open(member) as stream:
                    sample = _sample_csv_binary_stream(stream, member)
            except Exception:
                sample = pd.DataFrame()
            sampled.append((sample, member))

    combined, source_files, skipped_files, schema_report = _prepare_samples(sampled)
    return _run_analysis(combined, display_name or path.name, source_files, skipped_files, schema_report, reset)
