"""Deterministic Matplotlib charts and auditable graph aggregates for Stage 2.0."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from reporting.export import (
    ANOMALY_BANDS,
    ATTACK_VALUES,
    CANONICAL_BEHAVIORS,
    TRIAGE_VALUES,
    canonical_json,
    percent,
)


PALETTE = ("#1769aa", "#f08a24", "#4caf50", "#8e44ad", "#555555", "#d1495b")
PROTOCOLS = ("ICMP", "TCP", "UDP", "OTHER")
DRIVER_FAMILIES = CANONICAL_BEHAVIORS[:-1]
FALLBACK_BEHAVIOR = CANONICAL_BEHAVIORS[-1]


class GraphDataError(ValueError):
    """Raised when rows cannot satisfy a frozen Stage 2.0 chart contract."""


def _identity(row: Mapping[str, object]) -> tuple[int, str]:
    number = row.get("source_record_number")
    source_id = row.get("source_record_id")
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise GraphDataError("chart row has an invalid source_record_number")
    if not isinstance(source_id, str) or not source_id:
        raise GraphDataError("chart row has an invalid source_record_id")
    return number, source_id


def _display(row: Mapping[str, object], name: str) -> object:
    context = row.get("display_context")
    return context.get(name) if isinstance(context, Mapping) else None


def _protocol(row: Mapping[str, object]) -> str:
    value = _display(row, "protocol_name")
    return str(value) if value in PROTOCOLS else "OTHER"


def _service(row: Mapping[str, object]) -> str:
    value = _display(row, "service_source")
    return str(value) if isinstance(value, str) and value else "Other/Missing"


def _ordered_by_rank(rows: Sequence[Mapping[str, object]]) -> list[Mapping[str, object]]:
    return sorted(rows, key=lambda row: int(row["anomaly_rank"]))


def _group_shares(rows: Sequence[Mapping[str, object]], groups: Sequence[str], selector) -> tuple[dict[str, int], dict[str, float]]:
    counts = {group: 0 for group in groups}
    for row in rows:
        counts[selector(row)] += 1
    return counts, {group: percent(counts[group], len(rows)) for group in groups}


def _feature_lookup(feature_rows: Sequence[Mapping[str, object]], feature_names: Sequence[str]) -> dict[tuple[int, str], Mapping[str, object]]:
    required = {"log_duration", "log_total_bytes", "duration_missing", "sent_bytes_missing", "received_bytes_missing", "zero_total_bytes"}
    if not required.issubset(feature_names):
        raise GraphDataError("Stage 1.7 feature schema lacks Chart 10 fields")
    result: dict[tuple[int, str], Mapping[str, object]] = {}
    for row in feature_rows:
        key = _identity(row)
        values = row.get("values")
        if key in result or not isinstance(values, list) or len(values) != len(feature_names):
            raise GraphDataError("Stage 1.7 feature rows have an invalid identity or value vector")
        result[key] = row
    return result


def _feature_groups(rows: Sequence[Mapping[str, object]], features: Mapping[tuple[int, str], Mapping[str, object]], positions: Mapping[str, int], feature_name: str) -> dict[str, dict[str, object]]:
    grouped: dict[str, dict[str, object]] = {
        "top_100": {"values": [], "missing_count": 0, "zero_count": 0},
        "remainder": {"values": [], "missing_count": 0, "zero_count": 0},
    }
    for row in rows:
        feature = features.get(_identity(row))
        if feature is None:
            raise GraphDataError("final row has no corresponding Stage 1.7 feature row")
        values = feature["values"]
        assert isinstance(values, list)
        group = grouped["top_100" if int(row["anomaly_rank"]) <= 100 else "remainder"]
        if feature_name == "log_duration":
            missing = values[positions["duration_missing"]] == 1.0
            zero = not missing and values[positions["log_duration"]] == 0.0
        else:
            missing = values[positions["sent_bytes_missing"]] == 1.0 or values[positions["received_bytes_missing"]] == 1.0
            zero = not missing and values[positions["zero_total_bytes"]] == 1.0
        if missing:
            group["missing_count"] = int(group["missing_count"]) + 1
            continue
        value = values[positions[feature_name]]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise GraphDataError(f"{feature_name} must be numeric in the Stage 1.7 feature artifact")
        cast_values = group["values"]
        assert isinstance(cast_values, list)
        cast_values.append(float(value))
        if zero:
            group["zero_count"] = int(group["zero_count"]) + 1
    for group in grouped.values():
        values = group["values"]
        assert isinstance(values, list)
        values.sort()
        group["eligible_count"] = len(values)
    return grouped


def _driver_counts(rows: Sequence[Mapping[str, object]], *, include_fallback: bool) -> dict[str, int]:
    counts = {name: 0 for name in CANONICAL_BEHAVIORS}
    for row in rows:
        behaviors = row.get("suspected_behaviors")
        if not isinstance(behaviors, list):
            raise GraphDataError("suspected_behaviors must be a list for graph aggregation")
        observed = {value for value in behaviors if value in DRIVER_FAMILIES}
        for name in observed:
            counts[name] += 1
        if include_fallback and not observed and FALLBACK_BEHAVIOR in behaviors:
            counts[FALLBACK_BEHAVIOR] += 1
    return counts


def _score_map(score_rows: Sequence[Mapping[str, object]] | None) -> dict[tuple[int, str], float]:
    if score_rows is None:
        return {}
    result: dict[tuple[int, str], float] = {}
    for row in score_rows:
        value = row.get("raw_abnormality")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise GraphDataError("Stage 1.8 score row has no numeric raw_abnormality")
        key = _identity(row)
        if key in result:
            raise GraphDataError("duplicate Stage 1.8 score identity")
        result[key] = float(value)
    return result


def _score_histogram(values: Sequence[float]) -> dict[str, int]:
    """Return the fixed 0–100, width-five histogram used by Chart 01."""

    counts = {f"{start}-{start + 5}": 0 for start in range(0, 105, 5)}
    for value in values:
        if value < 0 or value > 100:
            raise GraphDataError("anomaly_score is outside the Chart 01 0–100 domain")
        start = min(100, int(value // 5) * 5)
        counts[f"{start}-{start + 5}"] += 1
    return counts


def _values_sha256(values: Sequence[object]) -> str:
    return hashlib.sha256(canonical_json(list(values)).encode("utf-8")).hexdigest()


def build_graph_data(rows: Sequence[Mapping[str, object]], feature_rows: Sequence[Mapping[str, object]], feature_names: Sequence[str], score_rows: Sequence[Mapping[str, object]] | None = None) -> dict[str, dict[str, object]]:
    """Return the frozen, renderer-independent aggregates for all ten charts."""

    ordered = _ordered_by_rank(rows)
    if not ordered:
        raise GraphDataError("graphs require at least one final row")
    features = _feature_lookup(feature_rows, feature_names)
    positions = {name: index for index, name in enumerate(feature_names)}
    raw_scores = _score_map(score_rows)
    top_50 = [row for row in ordered if int(row["anomaly_rank"]) <= 50]
    top_100 = [row for row in ordered if int(row["anomaly_rank"]) <= 100]
    top_1000 = [row for row in ordered if int(row["anomaly_rank"]) <= 1000]
    remaining = [row for row in ordered if int(row["anomaly_rank"]) > 1000]

    protocol_selected, protocol_selected_shares = _group_shares(top_1000, PROTOCOLS, _protocol)
    protocol_remaining, protocol_remaining_shares = _group_shares(remaining, PROTOCOLS, _protocol)
    selected_services = Counter(_service(row) for row in top_1000)
    top_services = sorted((name for name in selected_services if name != "Other/Missing"), key=lambda name: (-selected_services[name], name))[:10]
    service_labels = [*top_services, "Other/Missing"]

    def service_bucket(row: Mapping[str, object]) -> str:
        value = _service(row)
        return value if value in top_services else "Other/Missing"

    service_selected, service_selected_shares = _group_shares(top_1000, service_labels, service_bucket)
    service_remaining, service_remaining_shares = _group_shares(remaining, service_labels, service_bucket)
    top_50_drivers = _driver_counts(top_50, include_fallback=True)
    top_1000_drivers = _driver_counts(top_1000, include_fallback=False)

    reference_scores = [float(row["anomaly_score"]) for row in ordered if row["partition"] == "REFERENCE"]
    holdout_scores = [float(row["anomaly_score"]) for row in ordered if row["partition"] == "HOLDOUT"]
    return {
        "01_score_distribution.png": {
            "reference_scores": reference_scores,
            "holdout_scores": holdout_scores,
            "histogram_bins": {
                "REFERENCE": _score_histogram(reference_scores),
                "HOLDOUT": _score_histogram(holdout_scores),
            },
            "partition_counts": {"REFERENCE": sum(row["partition"] == "REFERENCE" for row in ordered), "HOLDOUT": sum(row["partition"] == "HOLDOUT" for row in ordered)},
        },
        "02_top20_scores.png": {
            "rows": [{"anomaly_rank": int(row["anomaly_rank"]), "source_record_number": int(row["source_record_number"]), "anomaly_score": float(row["anomaly_score"]), "raw_abnormality": raw_scores.get(_identity(row))} for row in ordered[:20]],
            "top_20_count": min(20, len(ordered)),
        },
        "03_anomaly_bands.png": {"counts": {name: sum(row["anomaly_band"] == name for row in ordered) for name in ANOMALY_BANDS}, "denominator": len(ordered)},
        "04_protocol_representation.png": {"groups": list(PROTOCOLS), "selected_counts": protocol_selected, "remaining_counts": protocol_remaining, "selected_shares": protocol_selected_shares, "remaining_shares": protocol_remaining_shares, "selected_denominator": len(top_1000), "remaining_denominator": len(remaining)},
        "05_service_representation.png": {"groups": service_labels, "selected_counts": service_selected, "remaining_counts": service_remaining, "selected_shares": service_selected_shares, "remaining_shares": service_remaining_shares, "selected_denominator": len(top_1000), "remaining_denominator": len(remaining)},
        "06_observed_anomaly_driver_frequency.png": {"groups": list(CANONICAL_BEHAVIORS), "top_50_counts": top_50_drivers, "top_1000_counts": top_1000_drivers, "top_50_shares": {name: percent(top_50_drivers[name], len(top_50)) for name in CANONICAL_BEHAVIORS}, "top_1000_shares": {name: percent(top_1000_drivers[name], len(top_1000)) for name in CANONICAL_BEHAVIORS}, "top_50_denominator": len(top_50), "top_1000_denominator": len(top_1000)},
        "07_auto_triage_distribution.png": {"counts": {name: sum(row["auto_triage"] == name for row in ordered) for name in TRIAGE_VALUES}, "denominator": len(ordered)},
        "08_evidence_strength.png": {"groups": ["HIGH", "MEDIUM", "LOW", "NULL"], "counts": {name: sum(row.get("evidence_strength") == name for row in ordered) if name != "NULL" else sum(row.get("evidence_strength") is None for row in ordered) for name in ("HIGH", "MEDIUM", "LOW", "NULL")}, "denominator": len(ordered)},
        "09_suspected_attack_interpretation.png": {"groups": ["Possible reconnaissance activity", "Unclassified suspicious behavior", "No attack-type interpretation"], "counts": _suspected_attack_interpretation_counts(ordered), "denominator": len(ordered)},
        "10_feature_comparison.png": {"features": {"log_total_bytes": _feature_groups(ordered, features, positions, "log_total_bytes"), "log_duration": _feature_groups(ordered, features, positions, "log_duration")}, "rank_groups": {"top_100": len(top_100), "remainder": len(ordered) - len(top_100)}},
    }


def graph_manifest_counts(name: str, data: Mapping[str, object]) -> dict[str, object]:
    """Return compact, deterministic evidence for independently auditing a chart."""

    if name == "10_feature_comparison.png":
        features = data["features"]
        assert isinstance(features, Mapping)
        return {"rank_groups": data["rank_groups"], "features": {feature: {group: {"eligible_count": values["eligible_count"], "missing_count": values["missing_count"], "zero_count": values["zero_count"], "values_sha256": _values_sha256(values["values"])} for group, values in feature_groups.items()} for feature, feature_groups in features.items()}}
    if name == "02_top20_scores.png":
        return {"top_20_count": data["top_20_count"], "ranked_values": data["rows"]}
    return {key: value for key, value in data.items() if key not in {"reference_scores", "holdout_scores", "rows"}}


def _save(path: Path, title: str, xlabel: str, ylabel: str) -> None:
    plt.title(title, fontsize=13)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()


def _bar(path: Path, labels: Sequence[str], counts: Sequence[int], denominator: int, title: str, *, horizontal: bool = False) -> None:
    figure, axis = plt.subplots(figsize=(10, 6))
    positions = list(range(len(labels)))
    colors = [PALETTE[index % len(PALETTE)] for index in positions]
    if horizontal:
        axis.barh(positions, counts, color=colors)
        axis.set_yticks(positions, labels)
        axis.invert_yaxis()
        axis.set_xlabel("Record count")
        axis.set_ylabel("Category")
        for pos, count in zip(positions, counts):
            axis.text(count, pos, f" {count:,} ({percent(count, denominator):.3f}%)", va="center", fontsize=8)
    else:
        axis.bar(positions, counts, color=colors)
        axis.set_xticks(positions, labels, rotation=20, ha="right")
        axis.set_ylabel("Record count")
        axis.set_xlabel("Category")
        for pos, count in zip(positions, counts):
            axis.text(pos, count, f"{count:,}\n{percent(count, denominator):.3f}%", ha="center", va="bottom", fontsize=8)
    _save(path, title, axis.get_xlabel(), axis.get_ylabel())


def _write_top20(data: Mapping[str, object], path: Path) -> None:
    rows = data["rows"]
    assert isinstance(rows, list)
    labels, values = [], []
    for row in reversed(rows):
        assert isinstance(row, Mapping)
        raw = row["raw_abnormality"]
        raw_label = f"; raw={float(raw):.9f}" if raw is not None else ""
        labels.append(f"#{row['anomaly_rank']} / {row['source_record_number']}{raw_label}")
        values.append(float(row["anomaly_score"]))
    figure, axis = plt.subplots(figsize=(10, 8))
    axis.barh(labels, values, color=PALETTE[0])
    axis.set_xlabel("Anomaly Score (0–100; not attack probability)")
    axis.set_ylabel("Anomaly rank / source record number / raw abnormality")
    _save(path, "Top 20 Anomalies by Rank", axis.get_xlabel(), axis.get_ylabel())


def _write_comparison(data: Mapping[str, object], path: Path, title: str, xlabel: str, *, selected_label: str, remaining_label: str, figure_size: tuple[int, int] = (10, 6), label_rotation: int = 20) -> None:
    groups, selected, remaining = data["groups"], data["selected_shares"], data["remaining_shares"]
    selected_counts, remaining_counts = data["selected_counts"], data["remaining_counts"]
    assert isinstance(groups, list) and isinstance(selected, Mapping) and isinstance(remaining, Mapping)
    assert isinstance(selected_counts, Mapping) and isinstance(remaining_counts, Mapping)
    figure, axis = plt.subplots(figsize=figure_size)
    positions, width = list(range(len(groups))), .38
    axis.bar([position - width / 2 for position in positions], [float(selected[group]) for group in groups], width, label=selected_label, color=PALETTE[0])
    axis.bar([position + width / 2 for position in positions], [float(remaining[group]) for group in groups], width, label=remaining_label, color=PALETTE[1])
    for position, group in zip(positions, groups):
        axis.text(position - width / 2, float(selected[group]), f"{int(selected_counts[group]):,}\n{float(selected[group]):.2f}%", ha="center", va="bottom", fontsize=7)
        axis.text(position + width / 2, float(remaining[group]), f"{int(remaining_counts[group]):,}\n{float(remaining[group]):.2f}%", ha="center", va="bottom", fontsize=7)
    axis.set_xticks(positions, groups, rotation=label_rotation, ha="right", fontsize=7)
    axis.set_ylabel("Share of rank group (%)")
    axis.set_xlabel(xlabel)
    axis.legend()
    _save(path, title, axis.get_xlabel(), axis.get_ylabel())


def _write_driver_comparison(data: Mapping[str, object], path: Path) -> None:
    groups, top_50, top_1000 = data["groups"], data["top_50_shares"], data["top_1000_shares"]
    counts_50, counts_1000 = data["top_50_counts"], data["top_1000_counts"]
    assert isinstance(groups, list) and isinstance(top_50, Mapping) and isinstance(top_1000, Mapping)
    assert isinstance(counts_50, Mapping) and isinstance(counts_1000, Mapping)
    display_groups = [str(group).replace("_", "\n") for group in groups]
    figure, axis = plt.subplots(figsize=(13, 7))
    positions, width = list(range(len(groups))), .38
    axis.bar([position - width / 2 for position in positions], [float(top_50[group]) for group in groups], width, label="Top 50 records", color=PALETTE[0])
    axis.bar([position + width / 2 for position in positions], [float(top_1000[group]) for group in groups], width, label="Top 1,000 records", color=PALETTE[1])
    for position, group in zip(positions, groups):
        axis.text(position - width / 2, float(top_50[group]), f"{int(counts_50[group])}\n{float(top_50[group]):.1f}%", ha="center", va="bottom", fontsize=7)
        axis.text(position + width / 2, float(top_1000[group]), f"{int(counts_1000[group])}\n{float(top_1000[group]):.1f}%", ha="center", va="bottom", fontsize=7)
    axis.set_xticks(positions, display_groups, fontsize=7)
    axis.set_ylabel("Share of rank group records (%)")
    axis.set_xlabel("Complete suspected-behavior tag (not top reasons)")
    axis.legend()
    _save(path, "Observed Anomaly Driver Frequency", axis.get_xlabel(), axis.get_ylabel())


def _write_feature_comparison(data: Mapping[str, object], path: Path) -> None:
    features = data["features"]
    assert isinstance(features, Mapping)
    figure, axes = plt.subplots(1, 2, figsize=(10, 5))
    for axis, name, label in zip(axes, ("log_total_bytes", "log_duration"), ("log_total_bytes", "log_duration (unit-neutral)")):
        groups = features[name]
        assert isinstance(groups, Mapping)
        for group_name, color, legend in (("top_100", PALETTE[0], "Rank ≤ 100"), ("remainder", PALETTE[1], "Remaining ranks")):
            group = groups[group_name]
            assert isinstance(group, Mapping)
            values = group["values"]
            assert isinstance(values, list)
            if values:
                axis.plot(values, [(index + 1) / len(values) for index in range(len(values))], color=color, label=f"{legend} (n={len(values)}, missing={group['missing_count']}, zero={group['zero_count']})")
            else:
                axis.plot([], [], color=color, label=f"{legend} (no eligible values; missing={group['missing_count']})")
        axis.set_title(label)
        axis.set_xlabel("Stage 1.7 feature value")
        axis.set_ylabel("Empirical cumulative proportion")
        axis.legend(fontsize=7)
    figure.suptitle("Feature Comparison (missing operands excluded; duration units unresolved)")
    figure.tight_layout()
    figure.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(figure)


def _suspected_attack_interpretation_counts(rows: Sequence[Mapping[str, object]]) -> list[int]:
    return [sum(row.get("suspected_attack_type") == ATTACK_VALUES[0] for row in rows), sum(row.get("suspected_attack_type") == ATTACK_VALUES[1] for row in rows), sum(row.get("suspected_attack_type") is None for row in rows)]


def write_all_graphs(rows: Sequence[Mapping[str, object]], feature_rows: Sequence[Mapping[str, object]], feature_names: Sequence[str], graphs_dir: str | Path, *, score_rows: Sequence[Mapping[str, object]] | None = None, source_identities: Mapping[str, object] | None = None) -> list[dict[str, object]]:
    """Render the ten frozen charts and return their compact audit manifest."""

    directory = Path(graphs_dir)
    directory.mkdir(parents=True, exist_ok=True)
    data = build_graph_data(rows, feature_rows, feature_names, score_rows)
    writers = {
        "01_score_distribution.png": _write_score_distribution,
        "02_top20_scores.png": _write_top20,
        "03_anomaly_bands.png": lambda item, target: _bar(target, ANOMALY_BANDS, [int(item["counts"][name]) for name in ANOMALY_BANDS], int(item["denominator"]), "Anomaly Band Distribution"),
        "04_protocol_representation.png": lambda item, target: _write_comparison(item, target, "Protocol Representation by Rank Selection", "Source-assigned protocol representation", selected_label="Rank ≤ 1,000", remaining_label="Rank > 1,000"),
        "05_service_representation.png": lambda item, target: _write_comparison(item, target, "Service Representation by Rank Selection", "Source-assigned service representation", selected_label="Rank ≤ 1,000", remaining_label="Rank > 1,000", figure_size=(15, 7), label_rotation=28),
        "06_observed_anomaly_driver_frequency.png": _write_driver_comparison,
        "07_auto_triage_distribution.png": lambda item, target: _bar(target, TRIAGE_VALUES, [int(item["counts"][name]) for name in TRIAGE_VALUES], int(item["denominator"]), "Auto-Triage Distribution"),
        "08_evidence_strength.png": lambda item, target: _bar(target, item["groups"], [int(item["counts"][name]) for name in item["groups"]], int(item["denominator"]), "Evidence Strength Distribution"),
        "09_suspected_attack_interpretation.png": lambda item, target: _bar(target, item["groups"], item["counts"], int(item["denominator"]), "Suspected Attack Interpretation Distribution", horizontal=True),
        "10_feature_comparison.png": _write_feature_comparison,
    }
    manifest: list[dict[str, object]] = []
    for name, writer in writers.items():
        writer(data[name], directory / name)
        identities = dict(source_identities or {})
        if name != "10_feature_comparison.png":
            identities.pop("stage_1_7_feature_sha256", None)
        manifest.append({"name": name, "status": "PASS", "reason": "Renderer input reconciles to the frozen Stage 2.0 chart definition.", "source_identities": identities, "counts": graph_manifest_counts(name, data[name]), "relative_path": f"graphs/{name}"})
    return manifest


def _write_score_distribution(data: Mapping[str, object], path: Path) -> None:
    figure, axis = plt.subplots(figsize=(10, 6))
    bins = list(range(0, 106, 5))
    for key, color, label in (("reference_scores", PALETTE[0], "REFERENCE"), ("holdout_scores", PALETTE[1], "HOLDOUT")):
        values = data[key]
        assert isinstance(values, list)
        axis.hist(values, bins=bins, alpha=.75, label=label, color=color, edgecolor="white")
    axis.set_xlabel("Anomaly score (0–100; relative abnormality, not attack probability)")
    axis.set_ylabel("Record count")
    axis.legend()
    _save(path, "Anomaly Score Distribution", axis.get_xlabel(), axis.get_ylabel())
