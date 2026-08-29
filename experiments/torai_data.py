#!/usr/bin/env python3
"""Build a TORAI-format dataset from the local RCAEval RE2 parquet snapshot.

The authoritative TORAI dataset lives on Figshare behind an AWS WAF challenge
(experiments/download_torai_data.py). When that archive is unavailable, this
module re-aggregates the already-on-disk RE2 cases (data/rca_eval/re2{ob,ss,tt}*)
following the TORAI paper's data model (§3.1), producing the same directory
layout:

    data/torai/torai-{OB|SS|TT}/{service}_{fault}/{run}/
        simple_metrics.csv  logts.csv  [tracets_err.csv tracets_lat.csv]  inject_time.txt

- simple_metrics.csv: 1s metric columns flattened as {service}_{metric} + time
- logts.csv: Drain-template log counts at 15s bins ({service}_{template} columns)
- tracets_err.csv: per-service error-span counts at 15s bins ({service}_errors)
- tracets_lat.csv: per-service mean span latency at 15s bins ({service}_latency)

SS cases have no traces in RE2, mirroring the official torai-SS layout.

Usage:
    uv run python -m experiments.torai_data --source data/rca_eval --dest data/torai
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

BIN_S = 15
_VAR_TOKEN = re.compile(
    r"^\s*(?:<.*>|[-\+]?\d+(?:\.\d+)?(?:[eE][-\+]?\d+)?|[0-9a-fA-F]{6,}(?::[0-9a-fA-F]{1,4})?|"
    r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|0x[0-9a-fA-F]+|[-_\w]*\d[-_\w]*)$"
)
_SPLIT = re.compile(r"([^\w\s]|_)")


class _Drain:
    """Compact classic Drain (LogPAI-style, MIT): fixed-depth prefix tree over
    masked tokens with similarity-based log-group merging. Keeps the template
    count small (~tens per service) instead of one column per distinct message."""

    def __init__(self, depth: int = 3, sim_th: float = 0.5, max_groups: int = 500):
        self.depth = depth
        self.sim_th = sim_th
        self.max_groups = max_groups
        self._prefix: dict[tuple[str, ...], list[list[str]]] = {}
        self._templates: list[str] = []

    @staticmethod
    def _mask(tok: str) -> str:
        return "<*>" if _VAR_TOKEN.match(tok) else tok

    def _tokens(self, message: str) -> list[str]:
        return [self._mask(t) for t in _SPLIT.sub(" ", str(message)).split() if t]

    def _sim(self, a: list[str], b: list[str]) -> float:
        if not a and not b:
            return 1.0
        same = sum(1 for x, y in zip(a, b) if x == y)
        return same / max(len(a), len(b))

    def match(self, message: str) -> int:
        """Return the log-group id for message (creating it if new)."""
        tokens = self._tokens(message) or ["<*>"]
        prefix = tuple(tokens[: self.depth]) if len(tokens) >= self.depth else tuple(tokens)
        for idx in self._prefix.get(prefix, []):
            gtokens = self._templates[idx].split()
            if len(gtokens) != len(tokens):
                continue
            if self._sim(gtokens, tokens) >= self.sim_th:
                # merge: differing positions become wildcards
                merged = [
                    g if g == t else "<*>"
                    for g, t in zip(gtokens, tokens)
                ]
                if merged != gtokens:
                    self._templates[idx] = " ".join(merged)
                return idx
        if len(self._templates) >= self.max_groups:
            # safety valve: reuse the last group rather than unbounded growth
            self._prefix.setdefault(prefix, []).append(len(self._templates) - 1)
            return len(self._templates) - 1
        idx = len(self._templates)
        self._templates.append(" ".join(tokens))
        self._prefix.setdefault(prefix, []).append(idx)
        return idx


def _template_id(template: str) -> str:
    return hashlib.md5(template.encode("utf-8")).hexdigest()[:8]


def build_logts(logs: pd.DataFrame) -> pd.DataFrame:
    """Count log templates per service at 15s bins, columns = {service}_{gid}.
    Templates come from a per-service classic Drain parser (bounded group
    count), keeping the column count in the tens-to-low-hundreds range."""
    if logs.empty:
        return pd.DataFrame(columns=["time"])
    df = logs.copy()
    rows: list[dict] = []
    for svc in sorted(df["container_name"].astype(str).unique()):
        sub = df[df["container_name"] == svc]
        drain = _Drain()
        bins = (sub["timestamp"].astype("int64") // BIN_S) * BIN_S
        for bin_val, message in zip(bins.tolist(), sub["message"].astype(str).tolist()):
            rows.append({"bin": int(bin_val), "col": f"{svc}_{drain.match(message):04d}"})
    counts = pd.DataFrame(rows).groupby(["bin", "col"]).size().unstack(fill_value=0)
    counts.index.name = "time"
    full_idx = range(int(counts.index.min()), int(counts.index.max()) + 1, BIN_S)
    counts = counts.reindex(full_idx, fill_value=0)
    counts.index.name = "time"
    counts = counts.reset_index()
    return counts


def build_traces(traces: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Per-service 15s aggregates: error counts and mean latency.
    The ``time`` column is an HH:MM string; bin by ``startTimeMillis`` (epoch ms)."""
    if traces.empty:
        empty = pd.DataFrame(columns=["time"])
        return empty, empty
    df = traces.copy()
    df["bin"] = (df["startTimeMillis"].astype("int64") // (BIN_S * 1000)) * BIN_S
    err = (
        df.assign(
            is_err=(pd.to_numeric(df["statusCode"], errors="coerce").fillna(0) != 200).astype(int)
        )
        .groupby(["bin", "serviceName"])["is_err"]
        .sum()
        .unstack(fill_value=0)
    )
    err.columns = [f"{c}_errors" for c in err.columns]
    lat = df.groupby(["bin", "serviceName"])["duration"].mean().unstack()
    lat.columns = [f"{c}_latency" for c in lat.columns]
    full_idx = range(int(df["bin"].min()), int(df["bin"].max()) + 1, BIN_S)
    err = err.reindex(full_idx, fill_value=0)
    lat = lat.reindex(full_idx).fillna(0.0)
    err.index.name = "time"
    lat.index.name = "time"
    return err.reset_index(), lat.reset_index()


def convert_case(case_dir: Path, out_dir: Path) -> None:
    metrics = pd.read_parquet(case_dir / "metrics.parquet")
    metrics.to_csv(out_dir / "simple_metrics.csv", index=False)

    logs_path = case_dir / "logs.parquet"
    if logs_path.is_file():
        logs = pd.read_parquet(logs_path)
        logts = build_logts(logs)
    else:
        logts = pd.DataFrame(columns=["time"])
    logts.to_csv(out_dir / "logts.csv", index=False)

    traces_path = case_dir / "traces.parquet"
    if traces_path.is_file():
        traces = pd.read_parquet(traces_path)
        traces_err, traces_lat = build_traces(traces)
        traces_err.to_csv(out_dir / "tracets_err.csv", index=False)
        traces_lat.to_csv(out_dir / "tracets_lat.csv", index=False)

    (out_dir / "inject_time.txt").write_text(
        (case_dir / "inject_time.txt").read_text().strip() + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="data/rca_eval", help="RCAEval RE2 snapshot root")
    parser.add_argument("--dest", default="data/torai", help="output root")
    parser.add_argument(
        "--dataset",
        choices=["re2ob", "re2ss", "re2tt"],
        required=False,
        help="restrict to one suite",
    )
    args = parser.parse_args(argv)

    src = Path(args.source)
    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)
    suites = [args.dataset] if args.dataset else ["re2ob", "re2ss", "re2tt"]

    suite_map = {"re2ob": "torai-OB", "re2ss": "torai-SS", "re2tt": "torai-TT"}
    n_cases = 0
    for suite in suites:
        case_dirs = sorted(src.glob(f"{suite}_*_*"))
        for case_dir in case_dirs:
            if not (case_dir / "metrics.parquet").is_file():
                continue
            m = re.match(rf"{suite}_(.+)_(\d+)$", case_dir.name)
            if not m:
                continue
            service_fault, run = m.group(1), m.group(2)
            out_dir = dest / suite_map[suite] / service_fault / run
            out_dir.mkdir(parents=True, exist_ok=True)
            convert_case(case_dir, out_dir)
            n_cases += 1
        print(f"{suite}: done")

    (dest / "build_manifest.json").write_text(
        json.dumps(
            {
                "source": "derived-from-re2",
                "source_path": str(src),
                "n_cases": n_cases,
                "log_template": "classic Drain (LogPAI-style, depth=3, sim_th=0.5, max 500 groups/service), column={service}_{gid}",
                "bin_seconds": BIN_S,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"total cases: {n_cases} -> {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())