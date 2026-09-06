"""TORAI: Multi-Source Root Cause Analysis for Microservice Blind Spots.

Ported from `RCAEval/e2e/torai.py` + `RCAEval/e2e/rcd.py` (MIT license,
https://github.com/phamquiluan/RCAEval).

Orchestrates per-modality anomaly scoring, GMM clustering, and RCD-based
within-cluster refinement to produce a service-ranked report.

Two variants (identical numerics, different severity implementation):

- ``variant="faithful"``: reference per-column StandardScaler loop
  (RCAEval original style).
- ``variant="fast"``: vectorized numpy severity (default; output identical to
  faithful on finite data, faster on wide tables).

The module-improved variant (TORAI-QT: diag GMM / BIC truncation / quantile
discretization / normal-tail trim) and the ablation modules (empirical-tail
severity, temporal precedence, RCD consensus, guided CI) were removed: the
full-factor ablation concluded keeping the original TORAI pipeline
(see ADR-0002).

The public API:
    ToraiRCA(cfg_dict, seed=7).analyze(frame, train, val, ...) -> CausalReport
"""

import warnings

warnings.filterwarnings("ignore")  # reference parity: RCAEval torai.py ignores sklearn noise

import numpy as np
import pandas as pd
from dataclasses import dataclass
from sklearn.mixture import GaussianMixture

from ..schemas import (
    CausalReport,
    Direction,
    IncidentWindow,
    LogEvent,
    RootCauseCandidate,
    SymptomCluster,
    TelemetryFrame,
    TraceSpan,
)
from . import psi_pc

TORAI_MODALITIES = ("metric", "log", "trace_lat", "trace_err")


@dataclass
class ToraiConfig:
    resample_s: int = 15
    gamma: int = 5
    bins: int = 5
    localized: bool = True
    random_state: int = 0
    gmm_max_iter: int = 50
    max_cols: int = 64  # live guard: truncate cluster tables to top-N variance
                         # columns before Psi-PC (O(cols^2) blowup on wide
                         # single-host evidence; same measure as the AIOps
                         # adapter's --max-cols 50, perf-only)
    variant: str = "fast"  # "faithful" = per-column reference; "fast" = vectorized

    def __post_init__(self) -> None:
        if self.variant not in {"faithful", "fast"}:
            raise ValueError(f"variant must be faithful|fast, got {self.variant!r}")


# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------

def _severity_faithful(
    normal: pd.DataFrame,
    anomal: pd.DataFrame,
) -> list[tuple[str, float]]:
    """Reference per-column StandardScaler max-|z| severity, normalized to sum 1."""
    from sklearn.preprocessing import StandardScaler

    if normal is None or anomal is None or normal.empty or anomal.empty:
        return []
    result: list[tuple[str, float]] = []
    for col in list(normal.columns):
        if col not in anomal.columns:
            continue
        nv = normal[col].to_numpy(dtype=np.float64)
        av = anomal[col].to_numpy(dtype=np.float64)
        nv = nv[np.isfinite(nv)]
        av = av[np.isfinite(av)]
        if nv.size == 0 or av.size == 0:
            continue
        scaler = StandardScaler()
        scaler.fit(nv.reshape(-1, 1))
        z = scaler.transform(av.reshape(-1, 1)).ravel()
        result.append((col, float(np.max(np.abs(z)))))
    result.sort(key=lambda x: x[1], reverse=True)
    total = sum(s for _, s in result) or 1.0
    return [(col, s / total) for col, s in result]


def _severity_fast(
    normal: pd.DataFrame,
    anomal: pd.DataFrame,
) -> list[tuple[str, float]]:
    """Vectorized mean/std max-|z| severity (identical output to the
    faithful per-column loop on finite data), normalized to sum 1."""
    if normal is None or anomal is None or normal.empty or anomal.empty:
        return []
    cols = list(normal.columns)
    a = normal.to_numpy(dtype=np.float64, na_value=0.0)
    b = anomal.to_numpy(dtype=np.float64, na_value=0.0)
    center = np.nanmean(a, axis=0)
    scale = np.nanstd(a, axis=0)
    scale = np.where(scale == 0, 1.0, scale)
    z = (b - center) / scale
    scores = np.max(np.abs(z), axis=0)
    result = list(zip(cols, scores.tolist()))
    result.sort(key=lambda x: x[1], reverse=True)
    total = sum(s for _, s in result) or 1.0
    return [(col, s / total) for col, s in result]


def severity_scores(
    normal: pd.DataFrame,
    anomal: pd.DataFrame,
    *,
    variant: str = "fast",
) -> list[tuple[str, float]]:
    """Per-column severity (standard-scaler max-|z|), normalized to sum 1.

    ``variant="faithful"`` uses the reference per-column StandardScaler loop;
    ``variant="fast"`` (default) uses the vectorized path. Both produce
    identical rankings on finite data (asserted by the parity test).
    """
    if variant == "faithful":
        return _severity_faithful(normal, anomal)
    return _severity_fast(normal, anomal)


# Fine-to-coarse aggregation
# ---------------------------------------------------------------------------

def fine2coarse_addup(fine_ranks: list[tuple[str, float]]) -> list[tuple[str, float]]:
    """Sum per-service scores (service = prefix before first '_')."""
    score_dict: dict[str, float] = {}
    for col, score in fine_ranks:
        svc = col.split("_")[0]
        score_dict[svc] = score_dict.get(svc, 0.0) + score
    return sorted(score_dict.items(), key=lambda x: x[1], reverse=True)


def fine2coarse_highest(fine_ranks: list[tuple[str, float]]) -> list[tuple[str, float]]:
    """Highest per-service score, deduping, re-normalized."""
    best: dict[str, float] = {}
    for col, score in fine_ranks:
        svc = col.split("_")[0]
        if svc not in best or score > best[svc]:
            best[svc] = score
    total = sum(best.values()) or 1.0
    return [
        (svc, s / total)
        for svc, s in sorted(best.items(), key=lambda x: x[1], reverse=True)
    ]


# ---------------------------------------------------------------------------
# Symptom clustering
# ---------------------------------------------------------------------------

def symptom_cluster(
    X: np.ndarray,
    services: list[str],
    cfg: ToraiConfig,
) -> tuple[np.ndarray, list[tuple[int, float]]]:
    """GMM clustering with BIC selection over 1..N components, full covariance
    (faithful semantics). Returns (labels, cluster_rank)."""
    n = X.shape[0]
    bics: list[float] = []
    fitted: dict[int, GaussianMixture] = {}
    for n_comp in range(1, n + 1):
        gmm = GaussianMixture(
            n_components=n_comp,
            covariance_type="full",
            max_iter=cfg.gmm_max_iter,
            random_state=cfg.random_state,
        )
        gmm.fit(X)
        fitted[n_comp] = gmm
        bics.append(gmm.bic(X))
    best = int(np.argmin(bics)) + 1
    # reuse the BIC-best estimator from the scan instead of refitting an
    # identical one (same params/data/seed -> identical labels; saves 1 fit)
    gmm = fitted[best]
    labels = gmm.predict(X)
    mean_scores = np.mean(X, axis=1)
    cluster_rank: list[tuple[int, float]] = []
    for cl in set(labels):
        idx = np.where(labels == cl)[0]
        cluster_rank.append((int(cl), float(np.mean(mean_scores[idx]))))
    cluster_rank.sort(key=lambda x: x[1], reverse=True)
    return labels, cluster_rank


# ---------------------------------------------------------------------------
# Table helpers (faithful port of RCAEval io.time_series)
# ---------------------------------------------------------------------------

def _drop_constant(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty or df.shape[1] == 0:
        return df
    return df.loc[:, (df != df.iloc[0]).any()]


def _drop_time(df: pd.DataFrame) -> pd.DataFrame:
    if "time" in df.columns:
        return df.drop(columns=["time"])
    return df


def _convert_mem_mb(df: pd.DataFrame) -> pd.DataFrame:
    def _mem(x: pd.Series) -> pd.Series:
        if not x.name.endswith("_mem"):
            return x
        return x / 1e6

    return df.apply(_mem)


def _preprocess(df: pd.DataFrame) -> pd.DataFrame:
    df = _drop_constant(_convert_mem_mb(_drop_time(df)))
    df = _drop_constant(df)
    return df


# ---------------------------------------------------------------------------
# to_torai_frames — API/CLI input -> TORAI tables
# ---------------------------------------------------------------------------

def to_torai_frames(
    frame: TelemetryFrame,
    logs: tuple[LogEvent, ...] = (),
    traces: tuple[TraceSpan, ...] = (),
    *,
    resample_s: int = 15,
) -> dict[str, pd.DataFrame]:
    """Convert a telemetry frame + optional logs/traces into TORAI tables.

    Metric columns are ``{entity_id}_{metric_id}``; log columns are
    ``{entity_id}_{template_id}``; trace error/latency columns are
    ``{service_name}_errors`` / ``{service_name}_latency``. Only points with
    ``quality == "observed"`` are used. Missing modalities yield empty
    DataFrames (blind-spot semantics).
    """
    return {
        "metric": _frame_to_metric(frame),
        "logts": _logs_to_table(logs),
        "tracets_err": _traces_to_tables(traces)[0],
        "tracets_lat": _traces_to_tables(traces)[1],
    }


def _frame_to_metric(frame: TelemetryFrame) -> pd.DataFrame:
    pts = [p for p in frame.points if p.quality == "observed"]
    if not pts:
        return pd.DataFrame(columns=["time"])
    cols: dict[str, dict[int, float]] = {}
    ts: set[int] = set()
    for p in pts:
        sec = p.ts_ns // 1_000_000_000
        ts.add(sec)
        col = f"{p.entity_id}_{p.metric_id}"
        cols.setdefault(col, {})[sec] = float(p.value) if p.value is not None else 0.0
    ordered = sorted(ts)
    rows = {"time": ordered}
    for col, d in cols.items():
        rows[col] = [d.get(t, 0.0) for t in ordered]
    return pd.DataFrame(rows)


def _logs_to_table(logs: tuple[LogEvent, ...]) -> pd.DataFrame:
    if not logs:
        return pd.DataFrame(columns=["time"])
    cols: dict[str, dict[int, float]] = {}
    ts: set[int] = set()
    for log in logs:
        sec = log.ts_ns // 1_000_000_000
        ts.add(sec)
        col = f"{log.entity_id}_{log.template_id}"
        d = cols.setdefault(col, {})
        d[sec] = d.get(sec, 0.0) + 1.0
    ordered = sorted(ts)
    rows = {"time": ordered}
    for col, d in cols.items():
        rows[col] = [d.get(t, 0.0) for t in ordered]
    return pd.DataFrame(rows)


def _traces_to_tables(traces: tuple[TraceSpan, ...]) -> tuple[pd.DataFrame, pd.DataFrame]:
    if not traces:
        return pd.DataFrame(columns=["time"]), pd.DataFrame(columns=["time"])
    err_cols: dict[str, dict[int, float]] = {}
    lat_cols: dict[str, dict[int, list[float]]] = {}
    ts: set[int] = set()
    for sp in traces:
        sec = sp.start_ts_ns // 1_000_000_000
        ts.add(sec)
        svc = sp.service_name
        ed = err_cols.setdefault(svc, {})
        ed[sec] = ed.get(sec, 0.0) + (
            0.0 if sp.status in (None, "", "OK", "ok") else 1.0
        )
        ld = lat_cols.setdefault(svc, {}).setdefault(sec, [])
        ld.append(sp.end_ts_ns - sp.start_ts_ns)
    ordered = sorted(ts)
    err_rows = {"time": ordered}
    lat_rows = {"time": ordered}
    for svc in sorted(set(err_cols) | set(lat_cols)):
        err_rows[f"{svc}_errors"] = [err_cols.get(svc, {}).get(t, 0.0) for t in ordered]
        lat_rows[f"{svc}_latency"] = [
            float(np.mean(lat_cols.get(svc, {}).get(t, [0.0]))) for t in ordered
        ]
    return pd.DataFrame(err_rows), pd.DataFrame(lat_rows)


class ToraiRCA:
    """TORAI multi-source RCA model (the only causal model).

    ``cfg`` is a dict; the ``torai`` key holds ``ToraiConfig`` overrides
    (including ``variant: faithful|fast``).
    """

    def __init__(self, cfg: dict, *, seed: int = 7):
        tc = cfg.get("torai", {}) if isinstance(cfg, dict) else {}
        if not isinstance(tc, dict):
            tc = {}
        self.cfg = ToraiConfig(**tc)
        self.seed = seed
        self._full_cfg = cfg if isinstance(cfg, dict) else {}

    # -- detection (ported from graph_rca.py, Model 1 reuse) ---------------

    def _detect(self, frame: TelemetryFrame, train: TelemetryFrame, val: TelemetryFrame) -> IncidentWindow:
        from ..detection import DETECTOR_REGISTRY

        det_cfg = dict(self._full_cfg.get("detector", {}))
        name = det_cfg.pop("name", "edge_cascade")
        det = DETECTOR_REGISTRY[name](**det_cfg)
        det.fit(train, val, seed=self.seed)
        incidents = self._merge_overlapping(det.score(frame))
        flagged = [
            i for i in incidents
            if i.status in ("anomaly", "uncertain") and i.severity > 0
        ]
        if not flagged:
            raise RuntimeError(
                "no anomalous/uncertain incident detected in causal input; cannot analyze"
            )
        return max(
            flagged,
            key=lambda i: (i.status == "anomaly", len(i.metric_scores), i.severity),
        )

    @staticmethod
    def _merge_overlapping(incidents: list[IncidentWindow]) -> list[IncidentWindow]:
        if not incidents:
            return []
        incidents = sorted(incidents, key=lambda i: (i.start_ts_ns, -i.end_ts_ns))
        merged: list[IncidentWindow] = [incidents[0]]
        for inc in incidents[1:]:
            last = merged[-1]
            if inc.start_ts_ns <= last.end_ts_ns:
                merged[-1] = IncidentWindow(
                    incident_id=last.incident_id,
                    start_ts_ns=last.start_ts_ns,
                    end_ts_ns=max(last.end_ts_ns, inc.end_ts_ns),
                    detected_at_ns=last.detected_at_ns,
                    status=(
                        "anomaly"
                        if (last.status == "anomaly" or inc.status == "anomaly")
                        else "uncertain"
                    ),
                    severity=max(last.severity, inc.severity),
                    metric_scores={**last.metric_scores, **inc.metric_scores},
                    directions={**last.directions, **inc.directions},
                    model_version=last.model_version,
                )
            else:
                merged.append(inc)
        return merged

    @staticmethod
    def _anomalous_metrics(incident: IncidentWindow) -> list[str]:
        return list(incident.metric_scores.keys())

    # -- core pipeline (faithful to RCAEval torai()) ----------------------

    def analyze_tables(
        self,
        metric: pd.DataFrame,
        logts: pd.DataFrame,
        traces_err: pd.DataFrame | None = None,
        traces_lat: pd.DataFrame | None = None,
        inject_ns: int = 0,
    ) -> dict:
        """Core TORAI pipeline over DataFrames (benchmark entry point).

        Mirrors RCAEval ``torai()``: severity -> GMM clustering -> per-cluster
        RCD refinement -> ``{service}_A`` ranked output.
        """
        cfg = self.cfg
        has_traces = (
            traces_err is not None
            and len(traces_err) > 0
            and traces_lat is not None
            and len(traces_lat) > 0
        )

        # Lightweight speedup: BLAS/OpenMP thread pools default to one thread per
        # core (64 here); for these small matrices the oversubscription burns CPU
        # and makes latency erratic under load. Capping to 4 threads measured
        # fastest and produces identical rankings (verified byte-equal across
        # limits 1/2/4/64 on the RE1 subset and the heaviest RE2 case).
        from threadpoolctl import threadpool_limits

        with threadpool_limits(limits=4):
            return self._analyze_tables_impl(
                cfg, has_traces, metric, logts, traces_err, traces_lat, inject_ns
            )

    def _analyze_tables_impl(
        self,
        cfg: ToraiConfig,
        has_traces: bool,
        metric: pd.DataFrame,
        logts: pd.DataFrame,
        traces_err: pd.DataFrame | None,
        traces_lat: pd.DataFrame | None,
        inject_ns: int,
    ) -> dict:
        # ---- metric ----
        inject_s = inject_ns // 1_000_000_000
        metric = metric.iloc[:: cfg.resample_s, :]
        normal_metric = metric[metric["time"] < inject_s]
        anomal_metric = metric[metric["time"] >= inject_s]
        normal_metric = _preprocess(normal_metric)
        anomal_metric = _preprocess(anomal_metric)
        intersect = [c for c in normal_metric.columns if c in anomal_metric.columns]
        normal_metric = normal_metric[intersect]
        anomal_metric = anomal_metric[intersect]

        # ---- logts ----
        logts = _drop_constant(logts)
        if "time" not in logts.columns:  # degenerate single-row frame
            logts = pd.DataFrame(columns=["time"])
        normal_logts = logts[logts["time"] < inject_s]
        anomal_logts = logts[logts["time"] >= inject_s]
        normal_logts = _drop_time(normal_logts)
        anomal_logts = _drop_time(anomal_logts)

        # ---- traces ----
        if has_traces:
            traces_err = _drop_constant(traces_err.ffill().fillna(0))
            traces_lat = _drop_constant(traces_lat.ffill().fillna(0))
            if "time" not in traces_err.columns:
                traces_err = pd.DataFrame(columns=["time"])
            if "time" not in traces_lat.columns:
                traces_lat = pd.DataFrame(columns=["time"])
            normal_te = _drop_time(traces_err[traces_err["time"] < inject_s])
            anomal_te = _drop_time(traces_err[traces_err["time"] >= inject_s])
            # faithful: normal side of traces_err drops last 2 rows
            if len(normal_te) > 2:
                normal_te = normal_te.iloc[:-2]
            normal_tl = _drop_time(traces_lat[traces_lat["time"] < inject_s])
            anomal_tl = _drop_time(traces_lat[traces_lat["time"] >= inject_s])

        # ---- severity ----
        metric_ranks = severity_scores(normal_metric, anomal_metric, variant=cfg.variant)
        log_ranks = severity_scores(normal_logts, anomal_logts, variant=cfg.variant)
        trace_err_ranks: list[tuple[str, float]] = []
        trace_lat_ranks: list[tuple[str, float]] = []
        if has_traces:
            trace_err_ranks = severity_scores(normal_te, anomal_te, variant=cfg.variant)
            trace_lat_ranks = severity_scores(normal_tl, anomal_tl, variant=cfg.variant)

        svc_metric_ranks = fine2coarse_addup(metric_ranks)
        svc_log_ranks = fine2coarse_highest(log_ranks)
        svc_trace_err_ranks = fine2coarse_addup(trace_err_ranks)
        svc_trace_lat_ranks = fine2coarse_addup(trace_lat_ranks)

        # rename "frontendservice" -> "frontend" (reference parity)
        svc_metric_ranks = _rename_frontend(svc_metric_ranks)
        svc_log_ranks = _rename_frontend(svc_log_ranks)
        svc_trace_err_ranks = _rename_frontend(svc_trace_err_ranks)
        svc_trace_lat_ranks = _rename_frontend(svc_trace_lat_ranks)

        # ---- service x modality matrix ----
        m = pd.DataFrame(
            {
                "metric": pd.Series(
                    [s for _, s in svc_metric_ranks], index=[i for i, _ in svc_metric_ranks]
                ),
                "log": pd.Series(
                    [s for _, s in svc_log_ranks], index=[i for i, _ in svc_log_ranks]
                ),
                "trace_lat": pd.Series(
                    [s for _, s in svc_trace_lat_ranks],
                    index=[i for i, _ in svc_trace_lat_ranks],
                ),
                "trace_err": pd.Series(
                    [s for _, s in svc_trace_err_ranks],
                    index=[i for i, _ in svc_trace_err_ranks],
                ),
            }
        )
        m = m.fillna(0)
        service_list = m.index.to_list()
        X = m.to_numpy()

        if X.shape[0] == 0:
            # no service carried any severity (e.g. all metric columns constant
            # in the normal window); return an empty ranking instead of
            # crashing the GMM BIC scan (reference torai() would also fail).
            return {
                "service_ranks": [],
                "cluster_labels": [],
                "cluster_scores": [],
                "severity_matrix": {},
                "indicator_ranks": {},
                "limitations": ["no evaluable service (all metrics constant)"],
            }

        # ---- clustering ----
        labels, cluster_rank = symptom_cluster(X, service_list, cfg)

        # ---- per-cluster refinement (reference parity) ----
        service_ranks_rcd: list[str] = []
        cluster_labels_out: list[int] = []
        cluster_scores_out: list[tuple[int, float]] = []
        for cl_idx, cl_score in cluster_rank:
            idx = np.where(labels == cl_idx)[0]
            services_of_cluster = [service_list[i] for i in idx]
            scores_of_them = np.mean(X, axis=1)[idx]

            cluster_labels_out.append(int(cl_idx))
            cluster_scores_out.append((int(cl_idx), float(cl_score)))

            if len(services_of_cluster) == 1:
                service_ranks_rcd.append(services_of_cluster[0])
                continue

            # sort by severity within cluster (fallback order)
            aa = list(zip(services_of_cluster, scores_of_them))
            aa.sort(key=lambda x: x[1], reverse=True)

            # metric + logts subsets for this cluster
            tmp_metric = metric.loc[
                :, metric.columns.str.startswith(tuple(services_of_cluster))
            ]
            if "time" in metric.columns:
                tmp_metric["time"] = metric["time"]
            tmp_logts = logts.loc[
                :, logts.columns.str.startswith(tuple(services_of_cluster))
            ]
            if "time" in logts.columns:
                tmp_logts["time"] = logts["time"]

            tmp_ranks = self._rcd_multimodal(
                {"metric": tmp_metric, "logts": tmp_logts},
                inject_ns,
                dataset=None,
                gamma=cfg.gamma,
                localized=cfg.localized,
                bins=cfg.bins,
                resample_s=cfg.resample_s,
                max_cols=cfg.max_cols,
            )
            tmp_ranks = [s.split("_")[0] for s in tmp_ranks]
            internal = []
            if tmp_ranks:
                internal = [tmp_ranks[0]]
                for s in tmp_ranks[1:]:
                    if s not in internal:
                        internal.append(s)

            if len(internal) == len(services_of_cluster):
                # RCD ordering replaces severity ordering within the cluster
                service_ranks_rcd.extend(internal)
            else:
                for a, _ in aa:
                    service_ranks_rcd.append(a)

        # final service ranks (with _A suffix, RCAEval evaluator convention)
        service_ranks = [f"{svc}_A" for svc in service_ranks_rcd]

        # severity matrix (service -> {modality: score})
        severity_matrix: dict[str, dict[str, float]] = {}
        for svc in service_list:
            severity_matrix[svc] = {
                mod: float(m.loc[svc, mod]) if svc in m.index else 0.0
                for mod in TORAI_MODALITIES
            }

        # fine-grained indicator ranks per service
        indicator_ranks: dict[str, list[tuple[str, float]]] = {}
        all_fine = metric_ranks + log_ranks + trace_err_ranks + trace_lat_ranks
        for svc in service_list:
            inds = sorted(
                (x for x in all_fine if x[0].split("_")[0] == svc),
                key=lambda x: x[1],
                reverse=True,
            )
            indicator_ranks[svc] = inds

        limitations: list[str] = []
        if not has_traces:
            limitations.append("traces absent (blind spot)")
        if not len(logts) or not logts.columns.difference(["time"]).any():
            limitations.append("logs absent (blind spot)")

        return {
            "service_ranks": service_ranks,
            "cluster_labels": labels.tolist(),
            "cluster_scores": cluster_scores_out,
            "severity_matrix": severity_matrix,
            "indicator_ranks": indicator_ranks,
            "limitations": limitations,
        }

    def _rcd_multimodal(
        self,
        data: dict[str, pd.DataFrame],
        inject_ns: int,
        dataset=None,
        gamma: int = 5,
        localized: bool = True,
        bins: int = 5,
        resample_s: int = 15,
        max_cols: int = 64,
        seed: int | None = None,
    ) -> list[str]:
        """RCD on a metric+logts cluster subset (faithful port)."""
        metric = data["metric"]
        logts = data["logts"]
        inject_s = inject_ns // 1_000_000_000

        metric = metric.iloc[::resample_s, :]
        normal_metric = metric[metric["time"] < inject_s]
        anomal_metric = metric[metric["time"] >= inject_s]
        normal_metric = _preprocess(normal_metric)
        anomal_metric = _preprocess(anomal_metric)
        intersect = [c for c in normal_metric.columns if c in anomal_metric.columns]
        normal_metric = normal_metric[intersect]
        anomal_metric = anomal_metric[intersect]

        logts = _drop_constant(logts)
        normal_logts = _drop_time(logts[logts["time"] < inject_s])
        anomal_logts = _drop_time(logts[logts["time"] >= inject_s])

        normal_data = pd.concat([normal_metric, normal_logts], axis=1)
        anomal_data = pd.concat([anomal_metric, anomal_logts], axis=1)
        normal_data = normal_data.loc[:, ~normal_data.columns.duplicated()].fillna(0)
        anomal_data = anomal_data.loc[:, ~anomal_data.columns.duplicated()].fillna(0)

        normal_df = _preprocess(normal_data)
        anomal_df = _preprocess(anomal_data)
        normal_df, anomal_df = psi_pc._match_columns(normal_df, anomal_df)

        if normal_df.empty or anomal_df.empty:
            return []

        # Live single-host guard: per-cluster tables can carry ~1000 columns
        # (entities x metrics); Psi-PC scales ~O(cols^2). Keep the max_cols
        # highest-variance columns (perf-only, documented in ToraiConfig).
        if normal_df.shape[1] > max_cols:
            var = pd.concat([normal_df, anomal_df]).var(axis=0, skipna=True)
            keep = list(var.sort_values(ascending=False).index[:max_cols])
            normal_df = normal_df[keep]
            anomal_df = anomal_df[keep]

        return psi_pc.run_multi_phase(
            normal_df,
            anomal_df,
            gamma=gamma,
            localized=localized,
            bins=bins,
            seed=self.seed if seed is None else seed,
            discretize_strategy="kmeans",
            priority=None,
        )

    # -- public analyze API ----------------------------------------------

    def analyze(
        self,
        frame: TelemetryFrame,
        train: TelemetryFrame,
        val: TelemetryFrame,
        *,
        top_k: int = 3,
        incident: IncidentWindow | None = None,
        logs: tuple[LogEvent, ...] = (),
        traces: tuple[TraceSpan, ...] = (),
    ) -> CausalReport:
        """Run TORAI over API/CLI inputs and assemble a CausalReport."""
        if incident is None:
            incident = self._detect(frame, train, val)
        cfg = self.cfg

        tables = to_torai_frames(frame, logs, traces, resample_s=cfg.resample_s)
        metric = tables["metric"]
        logts = tables["logts"]
        traces_err = tables["tracets_err"]
        traces_lat = tables["tracets_lat"]
        if traces_err.empty or traces_lat.empty:
            traces_err = traces_lat = None

        result = self.analyze_tables(
            metric,
            logts,
            traces_err,
            traces_lat,
            inject_ns=incident.start_ts_ns,
        )

        candidates: list[RootCauseCandidate] = []
        for rank, svc_a in enumerate(result["service_ranks"], start=1):
            svc = svc_a[:-2] if svc_a.endswith("_A") else svc_a
            sev = result["severity_matrix"].get(svc, {})
            indicators = result["indicator_ranks"].get(svc, [])
            direction: Direction = "mixed"
            if indicators:
                direction = "up" if indicators[0][1] > 0 else "down"
            candidates.append(
                RootCauseCandidate(
                    entity_id=svc,
                    rank=rank,
                    score=1.0 / rank,
                    direction=direction,
                    severity=sev,
                    evidence_indicators=[i for i, _ in indicators[:5]],
                    cluster_id=-1,
                    abstained_reason=None,
                )
            )

        service_list = list(result["severity_matrix"].keys())
        clusters: list[SymptomCluster] = []
        for cl_idx, cl_score in result["cluster_scores"]:
            members = [
                service_list[i]
                for i, lab in enumerate(result["cluster_labels"])
                if lab == cl_idx
            ]
            clusters.append(
                SymptomCluster(
                    cluster_id=int(cl_idx), members=members, cluster_score=float(cl_score)
                )
            )

        limitations = [f"variant: {cfg.variant}"] + result["limitations"]
        if len(service_list) == 1:
            limitations.append("single-service fallback: RCD refinement skipped")

        return CausalReport(
            incident_id=incident.incident_id,
            window=incident,
            anomalous_metrics=self._anomalous_metrics(incident),
            candidates=candidates,
            clusters=clusters,
            limitations=limitations,
            model_version="0.1.0",
        )


def _rename_frontend(items: list[tuple[str, float]]) -> list[tuple[str, float]]:
    return [("frontend", s) if i == "frontendservice" else (i, s) for i, s in items]
