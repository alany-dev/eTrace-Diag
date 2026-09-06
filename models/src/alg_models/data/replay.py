"""Replay and ingestion adapters.

Inputs: JSONL / CSV replay files; OTLP and Prometheus adapters are pure
Python readers that map wire formats onto `TelemetryPoint`. When a collector
is unavailable or lacks permissions, callers MUST use replay of `observed`
fixtures or mark points non-observable — never fabricate fine-grained values.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Iterable

from ..schemas import TelemetryFrame, TelemetryPoint, Source, Quality


def parse_replay_jsonl(text: str | bytes) -> TelemetryFrame:
    """Parse a JSONL replay into a validated, sorted, deduplicated frame.

    Each line is a JSON object matching `TelemetryPoint` fields; `quality` and
    `source` default to `observed` / `replay`. Duplicate or unsorted points
    raise `ValueError` with the offending key — never silently dropped.
    """
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    raw: list[TelemetryPoint] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"replay line {lineno}: invalid JSON: {exc}") from exc
        obj.setdefault("quality", "observed")
        obj.setdefault("source", "replay")
        raw.append(TelemetryPoint.model_validate(obj))
    return _frame_from_sorted(raw)


def parse_replay_csv(text: str | bytes) -> TelemetryFrame:
    """Parse CSV replay. Required header columns: ts_ns, entity_id,
    entity_type, metric_id, value. Optional: quality, source, unit,
    sample_interval_ns, attrs (JSON-encoded)."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    reader = csv.DictReader(io.StringIO(text))
    required = {"ts_ns", "entity_id", "entity_type", "metric_id", "value"}
    if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
        raise ValueError(f"CSV missing required columns {sorted(required)}")
    raw: list[TelemetryPoint] = []
    for row in reader:
        obj = {
            "ts_ns": int(row["ts_ns"]),
            "entity_id": row["entity_id"],
            "entity_type": row["entity_type"],
            "metric_id": row["metric_id"],
            "value": _coerce_value(row["value"]),
            "quality": row.get("quality") or "observed",
            "source": row.get("source") or "replay",
            "unit": row.get("unit") or None,
        }
        if row.get("sample_interval_ns"):
            obj["sample_interval_ns"] = int(row["sample_interval_ns"])
        if row.get("attrs"):
            obj["attrs"] = json.loads(row["attrs"])
        raw.append(TelemetryPoint.model_validate(obj))
    return _frame_from_sorted(raw)


def _coerce_value(v: str) -> float | int | bool | None:
    v = v.strip()
    if v == "" or v.lower() in ("null", "none", "nan"):
        return None
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    try:
        return int(v)
    except ValueError:
        return float(v)


def _frame_from_sorted(points: list[TelemetryPoint]) -> TelemetryFrame:
    points.sort(key=lambda p: (p.ts_ns, p.entity_id, p.metric_id, p.quality))
    # dedupe exact duplicates; keep last-occurring (replay convention)
    dedup: dict[tuple[str, str, int, str], TelemetryPoint] = {}
    for p in points:
        key = (p.entity_id, p.metric_id, p.ts_ns, p.quality)
        if key in dedup:
            raise ValueError(f"duplicate point {key} in replay (exact duplicates forbidden)")
        dedup[key] = p
    ordered = sorted(dedup.values(), key=lambda p: (p.ts_ns, p.entity_id, p.metric_id, p.quality))
    return TelemetryFrame(points=tuple(ordered))


def load_replay(path: str | Path) -> TelemetryFrame:
    """Load a replay file by extension (.jsonl / .csv)."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"replay file not found: {p}")
    data = p.read_bytes()
    if p.suffix.lower() == ".csv":
        return parse_replay_csv(data)
    if p.suffix.lower() in (".jsonl", ".json", ".ndjson"):
        return parse_replay_jsonl(data)
    raise ValueError(f"unsupported replay extension: {p.suffix}")


def dump_replay_jsonl(frame: TelemetryFrame, path: str | Path) -> None:
    """Write a frame as JSONL for deterministic replay / fixtures."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for pt in frame.points:
        obj = pt.model_dump()
        if not obj["attrs"]:
            del obj["attrs"]
        if obj["unit"] is None:
            del obj["unit"]
        if obj["sample_interval_ns"] is None:
            del obj["sample_interval_ns"]
        lines.append(json.dumps(obj, sort_keys=True))
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


# ---------------------------------------------------------------------------
# Adapters for external wire formats. These map onto the same contract fields
# so downstream code is format-agnostic. Availability of live collectors is a
# capability question — see alg_models.collectors.
# ---------------------------------------------------------------------------


def telemetry_from_otlp(metrics: Iterable[dict], *, source: Source = "otlp") -> list[TelemetryPoint]:
    """Map OpenTelemetry metric points (resource_metric → scope_metric →
    number_data_point) onto TelemetryPoint.

    Expected input record shape (as produced by a minimal OTLP JSON exporter):
      {"resource": {"service.name": "...", "host.id": "..."},
       "scope": {"name": "..."},
       "metrics": [{"name": "system.cpu.utilization", "unit": "1",
                    "type": "gauge",
                    "points": [{"time_unix_nano": 123, "as_double": 0.42}]}]}
    """
    out: list[TelemetryPoint] = []
    for rm in metrics:
        res = rm.get("resource", {})
        host_id = res.get("host.id") or res.get("host.name") or "unknown-host"
        service = res.get("service.name")
        entity_type = "pod" if service else "host"
        entity_id = service or host_id
        for scope_metric in rm.get("metrics", []):
            name = scope_metric.get("name")
            unit = scope_metric.get("unit")
            for pt in scope_metric.get("points", []):
                ts = int(pt.get("time_unix_nano", 0))
                value = pt.get("as_double", pt.get("as_int"))
                attrs = dict(pt.get("attributes", {}))
                attrs["scope"] = rm.get("scope", {}).get("name", "")
                out.append(
                    TelemetryPoint(
                        ts_ns=ts,
                        entity_id=entity_id,
                        entity_type=entity_type,
                        metric_id=name,
                        value=value,
                        unit=unit,
                        source=source,
                        attrs=attrs,
                    )
                )
    return out


def telemetry_from_prometheus(
    text: str, *, labels: dict[str, str] | None = None, entity_id: str = "prom-host"
) -> list[TelemetryPoint]:
    """Parse a Prometheus text exposition into a list of TelemetryPoints.

    Timestamps are seconds→ns conversion when present; absent timestamps get
    `ts_ns=0` and the caller is responsible for assigning a timebase (replays
    of Prometheus scrapes must be re-stamped deterministically).
    """
    out: list[TelemetryPoint] = []
    labels = labels or {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            payload = line.split("{", 1)[1] if "{" in line else line
            if "{" in line:
                name, rest = line.split("{", 1)
                rest = rest.split("}", 1)
                values_part = rest[1].strip()
                metric_labels = rest[0]
            else:
                name, values_part = payload.split(" ", 1)
                metric_labels = ""
            parts = values_part.split()
            if not parts:
                continue
            value = float(parts[0])
            ts = int(float(parts[1]) * 1e9) if len(parts) > 1 else 0
            attrs: dict[str, str] = dict(labels)
            if metric_labels:
                for kv in metric_labels.split(","):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        attrs[k.strip()] = v.strip().strip('"')
            out.append(
                TelemetryPoint(
                    ts_ns=ts,
                    entity_id=entity_id,
                    entity_type="host",
                    metric_id=name,
                    value=value,
                    source="prometheus",
                    attrs=attrs,
                )
            )
        except (ValueError, IndexError) as exc:
            raise ValueError(f"unparseable prometheus line: {line!r}") from exc
    return out