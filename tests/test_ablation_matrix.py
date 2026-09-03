"""Runner/matrix unit tests for the TORAI ablation harness.

Covers the canonical module contract (16 masks, fixed order, validation),
metadata screen/confirm splits, paired metric semantics, failed-row
preservation in the CSV, and cold recomputation of paired deltas.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.torai_ablation_matrix import (
    CSV_COLUMNS,
    canonical_label,
    canonical_label_from_spec,
    build_rows,
    build_summary,
    load_runs,
    module_masks,
    parse_modules,
    paired_metrics,
    screen_confirm_split,
    write_matrix_csv,
)


def _run(**overrides) -> dict:
    rec = {
        "suite": "RE1",
        "stage": "screen",
        "modules": "none",
        "variant": "improved",
        "seed": 7,
        "n_total": 3,
        "p50_s": 1.0,
        "p95_s": 2.0,
        "total_s": 10.0,
        "peak_rss_mb": 100.0,
        "status": "ok",
        "cases": [
            {"case": "c1", "rank": 1, "latency_s": 1.0},
            {"case": "c2", "rank": 3, "latency_s": 1.5},
            {"case": "c3", "rank": 8, "latency_s": 2.0},
        ],
        "failures": [],
    }
    rec.update(overrides)
    return rec


class TestCanonicalParser:
    def test_16_masks_cover_exactly_all_subsets(self):
        masks = module_masks()
        assert len(masks) == 16
        subsets = {frozenset(m.split("+")) if m != "none" else frozenset() for m in masks}
        assert len(subsets) == 16  # all 2^4 subsets, unique
        for size in range(5):
            import itertools
            for combo in itertools.combinations(("tail", "guided", "onset", "consensus"), size):
                assert frozenset(combo) in subsets

    def test_canonical_string_unique_and_fixed_order(self):
        assert canonical_label_from_spec("tail,guided,onset,consensus") == \
            "tail+guided+onset+consensus"
        assert canonical_label_from_spec("none") == "none"
        assert canonical_label_from_spec("") == "none"
        assert canonical_label(["consensus", "tail"]) == "tail+consensus"  # fixed order
        # every mask maps to itself under the parser round-trip
        for m in module_masks():
            spec = m.replace("+", ",") if m != "none" else "none"
            assert canonical_label_from_spec(spec) == m

    def test_parser_rejects_invalid_specs(self):
        for bad in ("foo", "tail,tail", "guided,tail", "tail,,guided", "tail,",
                    ",tail", "tail,guided,onset,onset"):
            with pytest.raises(ValueError):
                parse_modules(bad)

    def test_parser_mapping_is_exact(self):
        assert parse_modules("tail") == {"severity_method": "empirical_tail"}
        assert parse_modules("guided") == {"guided_ci": True}
        assert parse_modules("onset") == {"temporal_precedence": True}
        assert parse_modules("consensus") == {"rcd_consensus": True}
        assert parse_modules("none") == {}


class TestStageSplit:
    def test_screen_confirm_disjoint_and_sized(self):
        groups = {
            ("ob", "cpu"): [f"re1ob_c{i}" for i in range(10)],
            ("ss", "mem"): [f"re1ss_m{i}" for i in range(3)],
        }
        screen, confirm = screen_confirm_split(groups)
        assert not (screen & confirm)
        # ceil(0.2*10)=2 screen for group 1; ceil(0.2*3)=1 for group 2
        assert len(screen) == 3
        assert len(confirm) == 10
        assert screen | confirm == {
            f"re1ob_c{i}" for i in range(10)
        } | {f"re1ss_m{i}" for i in range(3)}


class TestPairedMetrics:
    def test_paired_uses_only_both_rank_cases(self):
        base_cases = [
            {"case": "c1", "rank": 2},
            {"case": "c2", "rank": 4},
            {"case": "c3", "rank": 6},  # base-only (candidate failed)
        ]
        cand_cases = [
            {"case": "c1", "rank": 1},
            {"case": "c2", "rank": 5},
            {"case": "c4", "rank": 1},  # candidate-only recovery
        ]
        p = paired_metrics(cand_cases, base_cases)
        assert p["paired_n"] == 2  # c1, c2 only
        # paired cand avg5 = (1.0 + 1/3)/2 = 2/3; base = (2/3 + 1/3)/2 = 1/2
        assert p["paired_avg5_delta"] == pytest.approx(1 / 6, abs=1e-9)


    def test_empty_intersection(self):
        p = paired_metrics([{"case": "x", "rank": 1}], [{"case": "y", "rank": 1}])
        assert p["paired_n"] == 0
        assert p["paired_avg5_delta"] is None


class TestMatrixRows:
    def test_failed_rows_survive_in_csv(self, tmp_path):
        (tmp_path / "good.json").write_text(json.dumps(_run()))
        (tmp_path / "bad.json").write_text("{not json")
        (tmp_path / "partial.json").write_text(json.dumps({"suite": "RE1"}))
        runs = load_runs(tmp_path)
        assert sum(1 for r in runs if r.get("status") == "failed") == 2
        rows = build_rows(runs)
        write_matrix_csv(rows, tmp_path / "matrix.csv")
        text = (tmp_path / "matrix.csv").read_text()
        assert "status" in text
        assert text.count("failed") == 2

    def test_summary_paired_delta_cold_recompute(self, tmp_path):
        base = _run(
            modules="none",
            cases=[
                {"case": "c1", "rank": 2},
                {"case": "c2", "rank": 5},
            ],
        )
        cand = _run(
            modules="tail",
            cases=[
                {"case": "c1", "rank": 1},
                {"case": "c2", "rank": 5},
            ],
        )
        rows = build_rows([base, cand])
        summary = build_summary([base, cand], rows, None)
        strata = {k: v for k, v in summary["strata"].items()}
        key_tail = "RE1|screen|tail|improved"
        assert key_tail in strata
        # paired delta on {c1, c2}: cand ac1=0.5 base ac1=0.0 -> +0.5
        assert strata[key_tail]["paired_ac1_delta_mean"] == pytest.approx(0.5, abs=1e-9)

    def test_csv_columns_contract(self):
        assert CSV_COLUMNS[:5] == ["suite", "stage", "modules", "variant", "seed"]
        for col in ("n_total", "n_evaluable", "paired_n", "ac@1", "ac@3", "ac@5",
                    "avg@5", "paired_avg5_delta", "paired_ac1_delta", "p50_s",
                    "p95_s", "total_s", "peak_rss_mb", "failure_count", "status"):
            assert col in CSV_COLUMNS
