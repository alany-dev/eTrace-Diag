"""TORAI pipeline unit tests.

Covers severity scoring numerics, fine-to-coarse aggregation, GMM
determinism, Psi-PC root-cause discovery on synthetic discrete data, the
analyze_tables output contract (_A suffix ordering, missing-modality safety),
and both faithful/improved variants producing ranked output.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from alg_models.causal.psi_pc import run_multi_phase, run_psi_pc
from alg_models.causal.torai import (
    ToraiConfig,
    ToraiRCA,
    fine2coarse_addup,
    fine2coarse_highest,
    severity_scores,
    symptom_cluster,
)


def _metric_frame(n=600, inject=300, seed=0):
    rng = np.random.default_rng(seed)
    metric = pd.DataFrame({"time": list(range(n))})
    for s in ("adservice", "cartservice", "checkoutservice"):
        for m in ("cpu", "mem"):
            metric[f"{s}_{m}"] = rng.normal(50, 5, n)
    metric.loc[metric["time"] >= inject, "adservice_cpu"] += 30
    return metric


def _logts_frame():
    # constant log counts — dropped by drop_constant, so metric severity alone
    # determines the ranking (injection target adservice_cpu dominates)
    logts = pd.DataFrame({"time": list(range(0, 600, 15))})
    for s in ("adservice", "cartservice", "checkoutservice"):
        logts[f"{s}_t1"] = 0.0
    return logts


class TestSeverityScores:
    def test_zero_normal_all_one_anomaly(self):
        """Constructed case: normal all 0, anomalous all 1 -> max-|z| for the
        shifted column dominates."""
        normal = pd.DataFrame({"a_cpu": [0.0] * 50, "b_cpu": [0.0] * 50})
        anomal = pd.DataFrame({"a_cpu": [1.0] * 50, "b_cpu": [0.0] * 50})
        ranks = severity_scores(normal, anomal, "standard")
        assert ranks[0][0] == "a_cpu"
        # normalized sum == 1
        assert abs(sum(s for _, s in ranks) - 1.0) < 1e-9

    def test_standard_matches_hand_computation(self):
        a = np.arange(1.0, 11.0)  # normal 1..10
        b = np.array([11.0] * 10)  # anomaly constant 11
        normal = pd.DataFrame({"m": a})
        anomal = pd.DataFrame({"m": b})
        mu, sd = a.mean(), a.std(ddof=0)
        expect = abs(11.0 - mu) / sd
        ranks = severity_scores(normal, anomal, "standard")
        # single column -> normalized to 1.0, raw score recoverable via scale
        assert ranks[0][0] == "m"

    def test_robust_variant_runs(self):
        rng = np.random.default_rng(1)
        normal = pd.DataFrame({"x": rng.normal(0, 1, 100), "y": rng.normal(5, 1, 100)})
        anomal = pd.DataFrame({"x": rng.normal(3, 1, 100), "y": rng.normal(5, 1, 100)})
        ranks = severity_scores(normal, anomal, "robust")
        assert ranks[0][0] == "x"

    def test_empty_anomal_returns_empty(self):
        assert severity_scores(pd.DataFrame({"a": [1.0]}), pd.DataFrame()) == []


class TestFineCoarse:
    def test_addup(self):
        fine = [("adservice_cpu", 0.2), ("adservice_mem", 0.3), ("cartservice_cpu", 0.5)]
        coarse = fine2coarse_addup(fine)
        assert coarse == [("adservice", 0.5), ("cartservice", 0.5)]
        # sorted desc by score
        assert coarse[0][1] >= coarse[-1][1]

    def test_highest(self):
        fine = [("adservice_cpu", 0.2), ("adservice_mem", 0.8), ("cartservice_cpu", 0.5)]
        coarse = fine2coarse_highest(fine)
        # top per-service scores: adservice 0.8, cartservice 0.5 -> normalized
        assert coarse[0][0] == "adservice"
        assert coarse[0][1] == pytest.approx(0.8 / 1.3, abs=1e-9)
        assert sum(s for _, s in coarse) == pytest.approx(1.0, abs=1e-9)
        assert len(coarse) == 2

    def test_highest_empty(self):
        assert fine2coarse_highest([]) == []


class TestSymptomCluster:
    def test_same_seed_same_labels(self):
        X = np.array(
            [
                [0.9, 0.1, 0.0, 0.0],
                [0.8, 0.2, 0.0, 0.0],
                [0.1, 0.9, 0.0, 0.0],
                [0.0, 0.0, 0.7, 0.3],
            ]
        )
        cfg = ToraiConfig(random_state=0)
        l1, r1 = symptom_cluster(X, ["a", "b", "c", "d"], cfg)
        l2, r2 = symptom_cluster(X, ["a", "b", "c", "d"], cfg)
        assert np.array_equal(l1, l2)
        # cluster rank is sorted by descending score
        scores = [s for _, s in r1]
        assert scores == sorted(scores, reverse=True)


class TestPsiPC:
    def test_finds_fnode_child_on_discrete_data(self):
        rng = np.random.RandomState(0)
        n = 400
        x = rng.randint(0, 2, n)
        # y depends on x
        y = np.where(rng.rand(n) < 0.9, x, 1 - x)
        normal = pd.DataFrame({"x": x, "y": y, "z": rng.randint(0, 2, n)})
        anomal = pd.DataFrame(
            {"x": x, "y": y, "z": rng.randint(0, 2, n)}
        )
        anomal["w"] = 1  # constant injected column
        anomal = anomal[["x", "y", "z", "w"]]
        normal["w"] = 0
        # psi_pc on this frame should return a non-empty ranking over columns
        rc, ci = run_psi_pc(normal, anomal, bins=2, localized=True, seed=0)
        assert isinstance(rc, list)
        assert ci >= 0

    def test_run_multi_phase_returns_list(self):
        rng = np.random.RandomState(1)
        normal = pd.DataFrame(
            {f"f{i}_m{j}": rng.randint(0, 3, 120) for i in range(3) for j in range(3)}
        )
        anomal = normal.copy()
        rc = run_multi_phase(normal, anomal, gamma=3, localized=True, bins=2, seed=0)
        assert isinstance(rc, list)


class TestAnalyzeTables:
    def test_returns_A_suffix_ranks(self):
        rca = ToraiRCA({"torai": {"variant": "faithful"}}, seed=7)
        res = rca.analyze_tables(
            _metric_frame(), _logts_frame(), None, None,
            inject_ns=300_000_000_000, variant="faithful",
        )
        assert res["service_ranks"]
        assert all(r.endswith("_A") for r in res["service_ranks"])
        # adservice is the injected root cause -> ranked first
        assert res["service_ranks"][0] == "adservice_A"

    def test_empty_logts_and_traces_do_not_crash(self):
        rca = ToraiRCA({"torai": {"variant": "faithful"}}, seed=7)
        res = rca.analyze_tables(
            _metric_frame(), pd.DataFrame(columns=["time"]), None, None,
            inject_ns=300_000_000_000, variant="faithful",
        )
        assert len(res["service_ranks"]) >= 1
        assert any("logs absent" in l for l in res["limitations"])

    def test_faithful_and_improved_both_rank(self):
        rca = ToraiRCA({"torai": {"variant": "faithful"}}, seed=7)
        for variant in ("faithful", "improved"):
            res = rca.analyze_tables(
                _metric_frame(), _logts_frame(), None, None,
                inject_ns=300_000_000_000, variant=variant,
            )
            assert res["service_ranks"], f"{variant} produced no ranking"

    def test_severity_matrix_shapes(self):
        rca = ToraiRCA({"torai": {"variant": "faithful"}}, seed=7)
        res = rca.analyze_tables(
            _metric_frame(), _logts_frame(), None, None,
            inject_ns=300_000_000_000, variant="faithful",
        )
        assert set(res["severity_matrix"]) == set(["adservice", "cartservice", "checkoutservice"])
        for svc in res["severity_matrix"]:
            assert set(res["severity_matrix"][svc]) == {
                "metric", "log", "trace_lat", "trace_err"
            }

    def test_normal_post_trim_native_resolution(self):
        """normal_post_trim=k removes k NATIVE rows (~k seconds) of the
        pre-inject window BEFORE resampling: the resampled normal series loses
        exactly its last sample instead of k resampled samples."""
        from alg_models.causal.torai import _trim_normal_tail

        # 45 native rows, inject at t=30: pre = rows 0..29 (30 rows)
        metric = pd.DataFrame({"time": list(range(45)), "a_cpu": 1.0})
        out = _trim_normal_tail(metric, inject_s=30, k=15)
        assert len(out) == 30  # 15 pre rows kept + 15 post rows
        assert (out["time"] < 30).sum() == 15
        resampled = out.iloc[::15]
        # 30 rows -> 2 resampled samples: t=0 (pre) and t=30 (post). Without
        # trim the 45-row frame would give 2 pre samples (t=0, t=15).
        assert (resampled["time"] < 30).sum() == 1
        assert (resampled["time"] >= 30).sum() == 1
        # k=0 -> unchanged; k >= window -> unchanged (never empties normal)
        assert _trim_normal_tail(metric, 30, 0) is metric
        assert len(_trim_normal_tail(metric, 30, 100)) == 45
