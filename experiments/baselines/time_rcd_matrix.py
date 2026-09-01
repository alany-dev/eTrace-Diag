"""Aggregate Time-RCD module-matrix JSONs into a CSV table.

    uv run python -m experiments.baselines.time_rcd_matrix \
        --dir results/time_rcd --out results/time_rcd/module_matrix.csv

Reads every ``<label>.json`` in ``--dir``, sorted by experiment name. Failed
JSONs (``status == "failed"``) are NEVER skipped: they become rows with empty
metric cells and the error in the note column.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

COLUMNS = [
    "experiment",
    "module",
    "status",
    "machines",
    "mean_point_f1",
    "mean_seg_f1",
    "mean_vus_pr",
    "wall_s",
    "threshold_rule",
    "calibration_basis",
    "note",
]


def _rows(files: list[Path]) -> list[dict]:
    rows = []
    for path in sorted(files):
        data = json.loads(path.read_text())
        if data.get("status") == "failed":
            rows.append(
                {
                    "experiment": data.get("experiment", path.stem),
                    "module": data.get("module", ""),
                    "status": "failed",
                    "machines": data.get("machines", ""),
                    "mean_point_f1": "",
                    "mean_seg_f1": "",
                    "mean_vus_pr": "",
                    "wall_s": "",
                    "threshold_rule": data.get("threshold_rule", ""),
                    "calibration_basis": data.get("calibration_basis", ""),
                    "note": data.get("note", ""),
                }
            )
            continue
        rows.append(
            {
                "experiment": data.get("experiment", path.stem),
                "module": data.get("module", ""),
                "status": data.get("status", "ok"),
                "machines": data.get("machines", ""),
                "mean_point_f1": data.get("mean_point_f1", ""),
                "mean_seg_f1": data.get("mean_seg_f1", ""),
                "mean_vus_pr": data.get("mean_vus_pr", ""),
                "wall_s": data.get("wall_s", ""),
                "threshold_rule": data.get("threshold_rule", ""),
                "calibration_basis": data.get("calibration_basis", ""),
                "note": data.get("note", ""),
            }
        )
    rows.sort(key=lambda r: str(r["experiment"]))
    return rows


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="experiments.baselines.time_rcd_matrix")
    p.add_argument("--dir", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)

    d = Path(args.dir)
    files = [f for f in sorted(d.glob("*.json"))]
    rows = _rows(files)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} rows -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
