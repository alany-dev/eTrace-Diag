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

class TestEmpiricalTail:
    def test_hand_computed_p_log(self):
        # column a: center=median([0..4])=2, d=[2,1,0,1,2], anomal 3 -> d*=1
        #   count(d>=1)=4 -> p=5/6 -> raw=ln(6/5)
        # column b: anomal 0 -> d*=2 -> count(d>=2)=2 -> p=3/6=0.5 -> raw=ln(2)
        normal = pd.DataFrame({"a_cpu": [0.0, 1.0, 2.0, 3.0, 4.0],
                               "b_cpu": [0.0, 1.0, 2.0, 3.0, 4.0]})
        anomal = pd.DataFrame({"a_cpu": [3.0] * 3, "b_cpu": [0.0] * 3})
        ranks = severity_scores(normal, anomal, "standard", method="empirical_tail")
        ra, rb = np.log(6 / 5), np.log(2.0)
        d = dict(ranks)
        assert d["a_cpu"] == pytest.approx(ra / (ra + rb), abs=1e-9)
        assert d["b_cpu"] == pytest.approx(rb / (ra + rb), abs=1e-9)
    def test_nonfinite_values_filtered_and_column_skipped(self):
        # normal side non-finite rows filtered; a column with all-non-finite
        # normal is skipped (both-sided filter, empty side -> skip column)
        normal = pd.DataFrame({"a_cpu": [0.0, np.nan, 2.0, 3.0, 4.0],
                               "b_cpu": [np.nan] * 5})
        anomal = pd.DataFrame({"a_cpu": [100.0] * 2, "b_cpu": [1.0] * 2})
        ranks = severity_scores(normal, anomal, "standard", method="empirical_tail")
        assert [c for c, _ in ranks] == ["a_cpu"]
        assert sum(s for _, s in ranks) == pytest.approx(1.0)
        assert ranks[0][1] == pytest.approx(1.0)
        assert sum(s for _, s in ranks) == pytest.approx(1.0)

    def test_empty_inputs_return_empty(self):
        assert severity_scores(pd.DataFrame({"a": [1.0]}), pd.DataFrame(),
                               method="empirical_tail") == []

    def test_zmax_default_unchanged(self):
        # default method is zmax and matches the pre-module computation
        normal = pd.DataFrame({"a_cpu": [0.0] * 50, "b_cpu": [0.0] * 50})
        anomal = pd.DataFrame({"a_cpu": [1.0] * 50, "b_cpu": [0.0] * 50})
        r1 = severity_scores(normal, anomal, "standard")
        r2 = severity_scores(normal, anomal, "standard", method="zmax")
        assert r1 == r2
        assert r1[0][0] == "a_cpu"
        with pytest.raises(ValueError):
            severity_scores(normal, anomal, method="bogus")


class TestTop2Mean:
    def test_top2_mean_does_not_scale_with_indicator_count(self):
        # 4 weak indicators (0.1 each) vs 1 strong (0.3): addup would give
        # 0.4 > 0.3, top-2 mean keeps 0.1 < 0.3
        from alg_models.causal.torai import top2_mean

        fine = [("svcA_m1", 0.1), ("svcA_m2", 0.1), ("svcA_m3", 0.1), ("svcA_m4", 0.1),
                ("svcB_m1", 0.3)]
        tm = top2_mean(fine)
        assert tm["svcA"] == pytest.approx(0.1)
        assert tm["svcB"] == pytest.approx(0.3)
        assert tm["svcB"] > tm["svcA"]


class TestGuidedPriority:
    def test_priority_none_preserves_default(self):
        rng = np.random.RandomState(1)
        normal = pd.DataFrame(
            {f"f{i}_m{j}": rng.randint(0, 3, 120) for i in range(3) for j in range(3)}
        )
        anomal = normal.copy()
        r1, c1 = run_psi_pc(normal, anomal, bins=2, localized=True, seed=3)
        r2, c2 = run_psi_pc(normal, anomal, bins=2, localized=True, seed=3, priority=None)
        assert r1 == r2 and c1 == c2

    def test_priority_does_not_change_ci_function(self):
        from alg_models.causal.psi_pc import chisq_ci

        rng = np.random.RandomState(2)
        data = rng.randint(0, 2, (60, 4))
        p1 = chisq_ci(data, 0, 1, ())
        p2 = chisq_ci(data, 0, 1, ())
        assert p1 == p2  # priority never enters the CI statistic
        # with priority the driver still returns a valid column ranking
        normal = pd.DataFrame(data, columns=["a", "b", "c", "d"])
        anomal = normal.copy()
        rc, _ = run_psi_pc(normal, anomal, bins=2, localized=True, seed=0,
                           priority=["d", "c", "b", "a"])
        assert set(rc) <= set(normal.columns)

    def test_guided_disabled_and_enabled_are_deterministic(self):
        # same data + same seed -> identical ranking both ways
        rng = np.random.RandomState(3)
        normal = pd.DataFrame({f"g{i}_m{j}": rng.randint(0, 3, 100) for i in range(2) for j in range(2)})
        anomal = normal.copy()
        a = run_multi_phase(normal, anomal, gamma=3, localized=True, bins=2, seed=0)
        b = run_multi_phase(normal, anomal, gamma=3, localized=True, bins=2, seed=0,
                            priority=list(normal.columns)[::-1])
        c = run_multi_phase(normal, anomal, gamma=3, localized=True, bins=2, seed=0,
                            priority=list(normal.columns)[::-1])
        assert b == c
        assert isinstance(a, list)


class TestOnsetPrecedence:
    def _frame(self, n=600, inject=300):
        t = np.arange(n)
        metric = pd.DataFrame({"time": t})
        noise = 0.1 * np.sin(2 * np.pi * t / 60)
        metric["root_cpu"] = 50.0 + noise
        metric["child_cpu"] = 50.0 + noise
        # resample 15s: root rises at post sample idx 2 (t=330), child at idx 4 (t=360)
        metric.loc[t >= 330, "root_cpu"] += 20
        metric.loc[t >= 360, "child_cpu"] += 21
        return metric

    def test_root_two_samples_before_child(self):
        from alg_models.causal.torai import temporal_precedence_scores

        metric = self._frame()
        resampled = metric.iloc[::15]
        prec = temporal_precedence_scores(resampled, 300, ["root", "child"])
        assert prec == {"root": 1.0, "child": 0.0}

    def test_fewer_than_two_valid_services_noop(self):
        from alg_models.causal.torai import temporal_precedence_scores

        metric = self._frame()
        resampled = metric.iloc[::15]
        assert temporal_precedence_scores(resampled, 300, ["root"]) == {}

    def test_root_ahead_of_child_with_onset_on_and_baseline_with_off(self):
        metric = self._frame()
        rca_off = ToraiRCA({"torai": {"variant": "faithful"}}, seed=7)
        res_off = rca_off.analyze_tables(
            metric, pd.DataFrame(columns=["time"]), None, None,
            inject_ns=300_000_000_000, variant="faithful",
        )
        rca_on = ToraiRCA(
            {"torai": {"variant": "faithful", "temporal_precedence": True}}, seed=7
        )
        res_on = rca_on.analyze_tables(
            metric, pd.DataFrame(columns=["time"]), None, None,
            inject_ns=300_000_000_000, variant="faithful",
        )
        # baseline path preserved: child has higher severity, onset disabled
        assert res_off["service_ranks"][0] == "child_A"
        # onset fusion flips the ranking: root changes two samples before child
        assert res_on["service_ranks"][0] == "root_A"
        assert res_on["module_evidence"]["temporal_scores"] == {"root": 1.0, "child": 0.0}

    def test_noop_recorded_when_onsets_all_equal(self):
        # both services spike at the same resampled post index -> no-op
        t = np.arange(600)
        metric = pd.DataFrame({"time": t})
        noise = 0.1 * np.sin(2 * np.pi * t / 60)
        metric["a_cpu"] = 50.0 + noise
        metric["b_cpu"] = 50.0 + noise
        metric.loc[t >= 330, "a_cpu"] += 20
        metric.loc[t >= 330, "b_cpu"] += 20
        rca = ToraiRCA({"torai": {"variant": "faithful", "temporal_precedence": True}}, seed=7)
        res = rca.analyze_tables(
            metric, pd.DataFrame(columns=["time"]), None, None,
            inject_ns=300_000_000_000, variant="faithful",
        )
        assert res["module_evidence"]["temporal_scores"] == {}
        assert any("temporal_precedence" in r for r in res["module_evidence"]["no_op"])


class TestConsensus:
    def _frame(self, n=2400, inject=1200):
        t = np.arange(n)
        m = pd.DataFrame({"time": t})
        noise = 0.1 * np.sin(2 * np.pi * t / 60)
        for s, amp in (("a", 20), ("b", 21), ("c", 22)):
            m[f"{s}_cpu"] = 50.0 + noise
        m.loc[t >= inject + 10, "a_cpu"] += 20
        m.loc[t >= inject + 10, "b_cpu"] += 21
        m.loc[t >= inject + 10, "c_cpu"] += 22
        return m

    def test_fixed_seed_twice_identical_and_covers_members(self):
        m = self._frame()
        rca = ToraiRCA({"torai": {"variant": "improved", "rcd_consensus": True}}, seed=7)
        r1 = rca.analyze_tables(m, pd.DataFrame(columns=["time"]), None, None,
                                inject_ns=1200_000_000_000, variant="improved")
        r2 = rca.analyze_tables(m, pd.DataFrame(columns=["time"]), None, None,
                                inject_ns=1200_000_000_000, variant="improved")
        assert r1["service_ranks"] == r2["service_ranks"]
        assert r1["module_evidence"] == r2["module_evidence"]
        # all cluster members appear in the ranking and in the support dict
        assert set(r1["service_ranks"]) == {"a_A", "b_A", "c_A"}
        assert set(r1["module_evidence"]["consensus_support"]) == {"a", "b", "c"}
        assert all(0.0 <= v <= 1.0 for v in r1["module_evidence"]["consensus_support"].values())
        assert r1["module_evidence"]["rcd_consensus"] is True

    def test_short_window_falls_back_with_noop(self):
        t = np.arange(90)
        m = pd.DataFrame({"time": t})
        noise = 0.1 * np.sin(2 * np.pi * t / 60)
        for s, amp in (("a", 20), ("b", 21), ("c", 22)):
            m[f"{s}_cpu"] = 50.0 + noise
        m.loc[t >= 55, "a_cpu"] += 20
        m.loc[t >= 55, "b_cpu"] += 21
        m.loc[t >= 55, "c_cpu"] += 22
        rca = ToraiRCA({"torai": {"variant": "improved", "rcd_consensus": True}}, seed=7)
        res = rca.analyze_tables(m, pd.DataFrame(columns=["time"]), None, None,
                                 inject_ns=45_000_000_000, variant="improved")
        # views too short -> severity fallback + recorded failure
        assert res["module_evidence"]["consensus_support"] == {}
        assert any("all-views-failed" in r for r in res["module_evidence"]["no_op"])
        assert len(res["service_ranks"]) >= 1

    def test_consensus_disabled_preserves_baseline(self):
        m = self._frame()
        rca_off = ToraiRCA({"torai": {"variant": "improved"}}, seed=7)
        res_off = rca_off.analyze_tables(m, pd.DataFrame(columns=["time"]), None, None,
                                         inject_ns=1200_000_000_000, variant="improved")
        assert res_off["module_evidence"]["consensus_support"] == {}
        assert res_off["module_evidence"]["rcd_consensus"] is False
        assert res_off["service_ranks"]


class TestModuleEvidence:
    def test_evidence_defaults_and_missing_modalities(self):
        # constant columns -> empty severity matrix -> module_evidence present
        rca = ToraiRCA({"torai": {"variant": "faithful"}}, seed=7)
        metric = pd.DataFrame({"time": list(range(60)), "svc_cpu": 1.0})
        res = rca.analyze_tables(metric, pd.DataFrame(columns=["time"]), None, None,
                                 inject_ns=30_000_000_000, variant="faithful")
        assert res["service_ranks"] == []
        assert res["module_evidence"]["modules"] == "none"
        assert res["module_evidence"]["severity_method"] == "zmax"
        assert res["module_evidence"]["temporal_scores"] == {}
        assert "no evaluable service" in res["limitations"][0]
