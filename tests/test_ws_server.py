"""WS bridge adapter tests (no network, no torch).

Covers AnomalyFeatures -> telemetry adaptation (gauge/cumulative semantics),
evidence bundle -> TORAI multi-modal inputs, the causal pipeline on synthetic
single-host series, abstention paths, and Time-RCD-Fuse segmentation logic
with a stubbed checkpoint (fit/scoring math only).
"""

from __future__ import annotations

import numpy as np
import pytest

from alg_models.detection import DETECTOR_REGISTRY
from alg_models.detection.time_rcd_fuse import TimeRCDFuseDetector
from alg_models.schemas import TelemetryFrame, TelemetryPoint
from alg_models.ws_server import (
    anomaly_features_to_points,
    evidence_to_inputs,
    run_causal,
)


def _msg(ts_ns: int, cpu_user: float, mem_free: float = 100.0, procs: list[dict] | None = None) -> dict:
    return {
        "v": 2, "seq": 0, "ts_ns": ts_ns,
        "host": {
            "total": {"user": cpu_user, "system": 10.0, "iowait": 1.0},
            "mem": {"mem_free_kb": mem_free},
            "vm": {"pgmajfault": 100.0},
            "psi": {"cpu": {"some": 0.1}, "io": {"some": 0.0}, "memory": {"some": 0.0}},
            "disks": [{"io_ticks_ms": 5.0, "weighted_ticks_ms": 2.0, "ios_in_flight": 1.0}],
            "ctxt": 1000.0, "procs_running": 2.0,
        },
        "ebpf": {"lock_waits_total": 7.0, "switch_total": 50.0},
        "network": {"ifaces": [{"rx_bytes": 10.0, "tx_bytes": 20.0}]},
        "top_tasks": procs or [],
    }


class TestAnomalyFeaturesAdapter:
    def test_first_tick_gauges_only_then_deltas(self):
        pts1, prev = anomaly_features_to_points(_msg(1_000_000_000, 100.0), {})
        pts2, _ = anomaly_features_to_points(_msg(2_000_000_000, 130.0), prev)
        by_id = {p.metric_id: p for p in pts2 if p.entity_id == "host"}
        # gauge passthrough
        assert by_id["mem_free"].value == 100.0
        # cumulative delta (130 - 100)
        assert by_id["cpu_user"].value == pytest.approx(30.0)
        # first tick: no cumulative values at all
        assert all(
            p.metric_id in ("mem_free", "io_inflight", "psi_io", "psi_mem", "psi_cpu", "procs_running")
            for p in pts1
            if p.entity_id == "host"
        )

    def test_proc_channels_deltas_and_entity(self):
        msg = _msg(1_000_000_000, 50.0, procs=[{"pid": 42, "tgid": 42, "comm": "stress",
                                                  "utime": 100.0, "stime": 10.0, "nvcsw": 5.0,
                                                  "nivcsw": 2.0, "minflt": 1.0, "majflt": 0.0,
                                                  "rss_kb": 9000.0, "read_bytes": 0.0,
                                                  "write_bytes": 0.0, "run_delay_ns": 0.0,
                                                  "syscr": 0.0, "syscw": 0.0}])
        _, prev = anomaly_features_to_points(msg, {})
        msg2 = _msg(2_000_000_000, 50.0, procs=[{"pid": 42, "tgid": 42, "comm": "stress",
                                                   "utime": 140.0, "stime": 10.0, "nvcsw": 5.0,
                                                   "nivcsw": 2.0, "minflt": 1.0, "majflt": 0.0,
                                                   "rss_kb": 9500.0, "read_bytes": 0.0,
                                                   "write_bytes": 0.0, "run_delay_ns": 0.0,
                                                   "syscr": 0.0, "syscw": 0.0}])
        pts2, _ = anomaly_features_to_points(msg2, prev)
        proc = [p for p in pts2 if p.entity_id == "proc42"]
        assert proc, "proc points missing"
        by_id = {p.metric_id: p for p in proc}
        assert by_id["cpu_user"].value == pytest.approx(40.0)  # utime delta
        assert by_id["rss"].value == pytest.approx(9500.0)  # gauge


class TestEvidenceInputs:
    def test_empty_body_abstains(self):
        frame, logs, traces, incident = evidence_to_inputs({})
        assert len(frame.points) == 0
        assert logs == () and traces == ()
        assert incident is None

    def test_full_bundle_maps_modalities(self):
        body = {
            "anomaly_start_ts": 300_000_000_000,
            "anomaly_end_ts": 330_000_000_000,
            "deep_indicators": [{"type": "cpu", "confidence": 0.95}],
            "series": [
                {"entity": "host", "metric": "cpu", "ts_ns": 200_000_000_000, "value": 10.0},
                {"entity": "proc1", "metric": "cpu", "ts_ns": 200_000_000_000, "value": 5.0},
                {"entity": "proc1", "metric": "cpu", "ts_ns": 320_000_000_000, "value": 95.0},
            ],
            "events": {
                "oom": [{"ts_ns": 310_000_000_000, "entity": "host", "kind": "kill"}],
                "syscall": [{"ts_ns": 305_000_000_000, "entity": "proc1", "name": "futex"}],
                "runq": [{"ts_ns": 306_000_000_000, "entity": "proc1", "wait_ns": 5_000_000}],
                "lock": [{"ts_ns": 307_000_000_000, "entity": "proc1", "wait_ns": 9_000_000}],
            },
        }
        frame, logs, traces, incident = evidence_to_inputs(body)
        assert len(frame.points) == 3
        assert {l.template_id for l in logs} == {"oom_kill", "syscall_futex"}
        assert {(t.status, t.attrs["evidence"]) for t in traces} == {
            ("OK", "runq_wait"), ("ERR", "lock_wait")
        }
        assert incident is not None
        assert incident.start_ts_ns == 300_000_000_000
        assert incident.metric_scores == {"cpu": 0.95}


class TestCausalPipeline:
    def test_synthetic_cpu_spike_finds_proc(self):
        n = 600
        body = {
            "anomaly_start_ts": 300_000_000_000,
            "anomaly_end_ts": 450_000_000_000,
            "deep_indicators": [{"type": "cpu", "confidence": 0.95}],
            "series": [],
        }
        for t in range(n):
            ts = t * 1_000_000_000
            body["series"].append(
                {"entity": "proc7", "metric": "cpu", "ts_ns": ts,
                 "value": 10.0 + 0.5 * np.sin(t / 7.0) + (60.0 if t >= 300 else 0.0)}
            )
            body["series"].append(
                {"entity": "proc9", "metric": "cpu", "ts_ns": ts,
                 "value": 12.0 + 0.5 * np.cos(t / 5.0)}
            )
        result = run_causal({"torai": {"variant": "fast", "resample_s": 15}}, body)
        assert result["ok"] is True
        report = result["report"]
        assert report["candidates"], "no root-cause candidates"
        assert report["candidates"][0]["entity_id"] == "proc7"
        assert report["candidates"][0]["rank"] == 1

    def test_empty_series_abstains(self):
        result = run_causal({}, {"series": []})
        assert result["ok"] is False
        assert "abstained_reason" in result


class TestFuseSegmentation:
    def _frame(self, n=40, spike_at=30, channels=("a", "b")) -> TelemetryFrame:
        pts = []
        for t in range(n):
            for ci, ch in enumerate(channels):
                v = 1.0
                if t >= spike_at and ci == 0:
                    v = 8.0
                pts.append(
                    TelemetryPoint(
                        ts_ns=t * 1_000_000_000, entity_id="host", entity_type="host",
                        metric_id=ch, value=v, source="replay",
                    )
                )
        return TelemetryFrame(points=tuple(pts))

    def test_fit_then_score_with_stubbed_checkpoint(self):
        det = TimeRCDFuseDetector(threshold=0.5)
        train = self._frame(n=40, spike_at=40)  # all-normal train
        det.fit(train, None, seed=7)
        assert det._med is not None and det._q99 > 0

        # stub the torch checkpoint: scores are low except a spike block
        class _StubDet:
            def predict(self, mat):
                out = np.full(mat.shape[0], 0.4)
                out[30:36] = 0.95
                return out

        det._det = _StubDet()
        incs = det.score(self._frame(n=40, spike_at=30))
        assert incs, "no incident emitted"
        assert incs[0].status in ("anomaly", "uncertain")
        assert 25 <= (incs[0].start_ts_ns // 1_000_000_000) <= 31
        assert incs[0].metric_scores, "channel contributions missing"
        assert det.params() == 0  # frozen checkpoint

    def test_registered(self):
        assert "time_rcd_fuse" in DETECTOR_REGISTRY
