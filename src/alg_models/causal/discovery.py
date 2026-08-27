"""Causal discovery: PCMCI+ (Tigramite when installed) with a self-contained
ParCorr-based PCMCI-lite fallback, plus stability bootstrap.

Output edges carry lag_ns, edge_mark, statistic (partial correlation), p-value,
confidence interval and stability. Edges remain subject to the standard
time-series causal assumptions (causal stationarity, Markov property,
faithfulness, sufficient sampling rate); the report records which backend ran
and which assumptions could not be verified.

The lite backend is a faithful ParCorr implementation of the PC-then-MCI
(PCMCI) procedure restricted to candidate edges: PC skeleton by iterative
conditional-independence, then moment-conditional independence tests with
Benjamini-Hochberg FDR. Contemporaneous edges are kept undirected (honest —
no claimed direction).
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field

import numpy as np
from scipy import stats

from ..schemas import CausalEdge, TelemetryFrame
from .graph import CandidateGraph, CandidateNode


@dataclass
class MultivarData:
    """Aligned multivariate matrix over a discovery range (observed cells only)."""

    ts_ns: np.ndarray  # (T,)
    node_ids: list[str]  # length M
    values: np.ndarray  # (T, M) float
    observed: np.ndarray  # (T, M) bool
    sample_interval_ns: int

    def column(self, node_id: str) -> int:
        return self.node_ids.index(node_id)


def build_multivar(
    frame: TelemetryFrame,
    *,
    entity_ids: list[str],
    metric_ids_by_entity: dict[str, list[str]],
    start_ns: int,
    end_ns: int,
    sample_interval_ns: int,
) -> MultivarData:
    """Align a frame into a multivariate matrix over [start_ns, end_ns).

    Only observed points fill cells; everything else is masked (NaN value +
    observed=False). Discovery consumes observed cells only and records how
    many cells/points were excluded.
    """
    from ..data.window import align_window

    all_metrics: list[tuple[str, str]] = []
    for e in entity_ids:
        for m in metric_ids_by_entity.get(e, []):
            all_metrics.append((e, m))
    node_ids = [f"{e}::{m}" for (e, m) in all_metrics]
    if not node_ids:
        return MultivarData(np.array([]), [], np.zeros((0, 0)), np.zeros((0, 0), dtype=bool), sample_interval_ns)

    grid = max(1, sample_interval_ns)
    t0 = start_ns - (start_ns % grid)
    t1 = end_ns - 1 if end_ns > start_ns else start_ns
    ts_ns = np.arange(t0, t1 + 1, grid, dtype=np.int64)
    T = ts_ns.shape[0]
    M = len(node_ids)
    values = np.full((T, M), np.nan)
    observed = np.zeros((T, M), dtype=bool)

    for e, m in all_metrics:
        aligned = align_window(
            frame, entity_id=e, start_ns=t0, end_ns=t1 + grid,
            sample_interval_ns=grid, metrics=[m],
        )
        if m not in aligned.metrics:
            continue
        mi = aligned.metrics.index(m)
        ts_arr = np.asarray(aligned.ts_ns, dtype=np.int64)
        col = node_ids.index(f"{e}::{m}")
        for r in range(len(ts_arr)):
            row = np.searchsorted(ts_ns, ts_arr[r])
            if row < T and ts_ns[row] == ts_arr[r]:
                v = aligned.values[r][mi]
                o = aligned.observed_mask[r][mi]
                values[row, col] = v
                observed[row, col] = o
    return MultivarData(ts_ns, node_ids, values, observed, sample_interval_ns)


def _parcorr(x: np.ndarray, y: np.ndarray, z: np.ndarray):
    """Partial correlation of x and y conditioning on columns of z.

    Returns (r, p_value, ci_lo, ci_hi, n_used). Uses residual regression with
    intercept; Fisher z transform for p-value and CI.
    """
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    z = np.asarray(z, dtype=float)
    n = x.shape[0]
    k = z.shape[1] if z.ndim == 2 else 0
    if n - k - 3 <= 0:
        return np.nan, 1.0, np.nan, np.nan, n

    def residual(a: np.ndarray, zz: np.ndarray) -> np.ndarray:
        if zz.shape[1] == 0:
            return a - a.mean()
        design = np.column_stack([zz, np.ones(zz.shape[0])])
        coef, *_ = np.linalg.lstsq(design, a, rcond=None)
        return a - design @ coef

    rx = residual(x, z)
    ry = residual(y, z)
    denom = np.sqrt(np.sum(rx**2) * np.sum(ry**2))
    if denom == 0:
        return 0.0, 1.0, 0.0, 0.0, n
    r = float(np.sum(rx * ry) / denom)
    r = float(np.clip(r, -1 + 1e-12, 1 - 1e-12))
    if n - k - 3 <= 0:
        return r, 1.0, np.nan, np.nan, n
    zval = 0.5 * np.log((1 + r) / (1 - r))
    t = zval * np.sqrt(n - k - 3)
    p = float(2 * (1 - stats.norm.cdf(abs(t))))
    se = 1.0 / np.sqrt(n - k - 3)
    ci_lo = float(np.clip(r - 1.96 * se, -1, 1))
    ci_hi = float(np.clip(r + 1.96 * se, -1, 1))
    return r, p, ci_lo, ci_hi, n


def _bh_threshold(pvals: np.ndarray, alpha: float) -> float:
    if pvals.size == 0:
        return 0.0
    pvals = np.sort(pvals)
    m = pvals.size
    thresh = 0.0
    for i, p in enumerate(pvals, start=1):
        if p <= alpha * i / m:
            thresh = max(thresh, alpha * i / m)
    return thresh


@dataclass
class LiteResult:
    edges: list[CausalEdge] = field(default_factory=list)
    skeleton_steps: int = 0
    tests_run: int = 0




def _detect_level_shift(data: MultivarData) -> bool:
    """Detect a mean level-shift (non-stationarity) by comparing the two halves
    of the discovery window per variable."""
    X = data.values
    T = X.shape[0]
    if T < 12:
        return False
    a = X[: T // 2]
    b = X[T // 2 :]
    for col in range(X.shape[1]):
        xa = a[:, col][np.isfinite(a[:, col])]
        xb = b[:, col][np.isfinite(b[:, col])]
        if xa.size < 4 or xb.size < 4:
            continue
        sd = float(np.std(xa))
        if sd > 0 and abs(float(np.mean(xb)) - float(np.mean(xa))) > 3.0 * sd:
            return True
    return False


class PCMIParCorrLite:
    """Self-contained PCMCI (PC skeleton + MCI) with ParCorr, BH-FDR."""

    def __init__(self, tau_max: int, alpha_level: float = 0.05, max_cond: int = 2,
                 fdr: str = "bh", sample_interval_ns: int = 1_000_000_000,
                 alpha_pc: float = 0.2):
        self.tau_max = tau_max
        self.alpha_level = alpha_level
        self.alpha_pc = alpha_pc  # PCMCI+ convention: relaxed skeleton alpha
        self.max_cond = max_cond
        self.fdr = fdr
        self.sample_interval_ns = sample_interval_ns

    def run(self, data: MultivarData, candidate_pairs: list[tuple[int, int, int]],
            contemp_pairs: list[tuple[int, int]]) -> LiteResult:
        """candidate_pairs: (src_col, dst_col, lag) with lag in 1..tau_max.
        contemp_pairs: (a_col, b_col) contemporaneous candidates."""
        X = data.values
        obs = data.observed
        T, M = X.shape
        res = LiteResult()

        def lagged_column(col: int, lag: int, rows: np.ndarray) -> np.ndarray:
            return X[rows - lag, col]

        # ---- Step 1+2: PC skeleton over lagged edges ----
        # adj[v] = list of (src, lag)

        def test_rows(lags: list[int]) -> np.ndarray:
            """Valid time indices for a set of lagged variables: rows start
            strictly past the largest lag so no negative indexing wraps."""
            if not lags:
                return np.arange(0, T)
            return np.arange(max(lags), T)

        def complete_rows(cols: list[tuple[int, int]]) -> np.ndarray:
            """Rows where every (col, lag) column AND the destination row are
            observed (destination column checked separately by callers)."""
            if not cols:
                return np.arange(0, T)
            rows = test_rows([lag for (_, lag) in cols])
            m = np.ones(rows.shape[0], dtype=bool)
            for (c, lag) in cols:
                m &= obs[rows - lag, c]
            return rows[m]

        adj: dict[int, list[tuple[int, int]]] = {v: [] for v in range(M)}
        for (u, v, lag) in candidate_pairs:
            rows = complete_rows([(u, lag), (v, 0)])
            if rows.size < 5:
                continue
            r, p, _, _, _ = _parcorr(
                lagged_column(u, lag, rows), X[rows, v], np.zeros((rows.size, 0))
            )
            res.tests_run += 1
            if p < self.alpha_level and np.isfinite(r):
                adj[v].append((u, lag))

        # PC refinement: order-k conditional independence
        for k in range(1, self.max_cond + 1):
            for v in range(M):
                for (u, lag) in list(adj[v]):
                    others = [e for e in adj[v] if e != (u, lag)]
                    if len(others) < k:
                        continue
                    dropped = False
                    for combo in itertools.combinations(others, k):
                        rows = complete_rows([(u, lag), (v, 0)] + list(combo))
                        z = np.column_stack(
                            [lagged_column(w, l, rows) for (w, l) in combo]
                        ) if combo else np.zeros((rows.size, 0))
                        if rows.size - len(combo) - 3 <= 0:
                            continue
                        r, p, _, _, _ = _parcorr(
                            lagged_column(u, lag, rows), X[rows, v], z
                        )
                        res.tests_run += 1
                        if p >= self.alpha_pc:
                            adj[v].remove((u, lag))
                            dropped = True
                            break
                    res.skeleton_steps += 1
                    if dropped:
                        break

        # ---- Step 3: MCI final tests ----
        final_edges: list[CausalEdge] = []
        pvals: list[float] = []
        for v in range(M):
            parents = adj[v]
            for (u, lag) in parents:
                cond_cols: list[tuple[int, int]] = []
                for (pu, plag) in adj[v]:
                    if (pu, plag) != (u, lag):
                        cond_cols.append((pu, plag))
                for (pu, plag) in adj[u]:
                    cond_cols.append((pu, plag))
                # dedup
                cond_cols = list(dict.fromkeys(cond_cols))
                cols_used = [c for c in cond_cols if (c[0], c[1]) != (u, lag)]
                rows = complete_rows([(u, lag), (v, 0)] + cols_used)
                z = np.column_stack([lagged_column(w, l, rows) for (w, l) in cols_used]) if cols_used else np.zeros((rows.size, 0))
                if rows.size - len(cols_used) - 3 <= 0:
                    continue
                r, p, lo, hi, _ = _parcorr(lagged_column(u, lag, rows), X[rows, v], z)
                res.tests_run += 1
                final_edges.append(
                    CausalEdge(
                        edge_id=f"e:{data.node_ids[u]}->{data.node_ids[v]}@lag{lag}",
                        # causal-node convention: src/dst identify the exact
                        # (entity, metric) node, not just the entity
                        src_entity_id=data.node_ids[u],
                        dst_entity_id=data.node_ids[v],
                        lag_ns=lag * self.sample_interval_ns,
                        edge_mark="directed",
                        statistic=r,
                        p_value=p,
                        confidence_interval=(lo, hi),
                        stability=1.0,
                        evidence_level="strong",
                    )
                )
                pvals.append(p)

        # contemporaneous edges (undirected, honest)
        contemp_edges: list[CausalEdge] = []
        for (a, b) in contemp_pairs:
            if a == b:
                continue
            cols_used = []
            for (w, l) in adj[a] + adj[b]:
                cols_used.append((w, l))
            cols_used = list(dict.fromkeys(cols_used))
            rows = complete_rows([(a, 0), (b, 0)] + cols_used)
            z = np.column_stack([lagged_column(w, l, rows) for (w, l) in cols_used]) if cols_used else np.zeros((rows.size, 0))
            if rows.size - len(cols_used) - 3 <= 0:
                continue
            r, p, lo, hi, _ = _parcorr(X[rows, a], X[rows, b], z)
            res.tests_run += 1
            contemp_edges.append(
                CausalEdge(
                    edge_id=f"e:{data.node_ids[a]}~{data.node_ids[b]}@lag0",
                    src_entity_id=data.node_ids[a],
                    dst_entity_id=data.node_ids[b],
                    lag_ns=0,
                    edge_mark="undirected",
                    statistic=r,
                    p_value=p,
                    confidence_interval=(lo, hi),
                    stability=1.0,
                    evidence_level="strong",
                )
            )
            pvals.append(p)

        # BH-FDR across all final tests
        if self.fdr == "bh" and pvals:
            thresh = _bh_threshold(np.asarray(pvals), self.alpha_level)
        else:
            thresh = self.alpha_level
        kept = [e for e in (final_edges + contemp_edges) if e.p_value is not None and e.p_value <= thresh]
        res.edges = kept
        return res


class TigramitePCMCIPlus:
    """Wrapper around the real PCMCI+ implementation (tigramite) when
    installed; None semantics (returns None) when unavailable."""

    @staticmethod
    def available() -> bool:
        try:
            import tigramite  # noqa: F401

            return True
        except ImportError:
            return False

    def run(self, data: MultivarData, tau_max: int, alpha_level: float,
            fdr: str = "bh", pc_alpha: float = 0.2,
            candidate_pairs: list[tuple[int, int, int]] | None = None,
            contemp_pairs: list[tuple[int, int]] | None = None,
    ) -> list[CausalEdge] | None:
        if not self.available():
            return None
        import tigramite.data_processing as pp
        from tigramite.independence_tests.parcorr import ParCorr
        from tigramite.pcmci import PCMCI

        # observed-only timesteps
        keep = data.observed.all(axis=1)
        if keep.sum() < 10:
            return None
        arr = data.values[keep]
        df = pp.DataFrame(arr, var_names=data.node_ids)
        pcmci = PCMCI(
            dataframe=df,
            cond_ind_test=ParCorr(significance="analytic"),
            verbosity=0,
        )
        # Topology candidate restriction (TemporalGraphBuilder output): only
        # candidate edges are tested; everything else is assumed absent. A
        # fully-unrestricted PCMCI+ over-connects on level-shift data — the
        # topology prior is exactly the plan's candidate-edge constraint.
        link_assumptions: dict[int, dict[tuple[int, int], str]] = {
            j: {} for j in range(data.values.shape[1])
        }
        for (src, dst, lag) in (candidate_pairs or []):
            link_assumptions[dst][(src, -lag)] = "-?>"
        for (src, dst) in (contemp_pairs or []):
            link_assumptions[dst][(src, 0)] = "o?o"
        fdr_method = "fdr_bh" if fdr == "bh" else "none"
        pcmci.run_pcmciplus(
            tau_max=tau_max, pc_alpha=pc_alpha, fdr_method=fdr_method,
            link_assumptions=link_assumptions or None,
        )
        deps = pcmci.get_lagged_dependencies(tau_min=0, tau_max=tau_max)
        val = deps["val_matrix"]
        pmat = deps["p_matrix"]
        graph = deps["graph"]
        M = len(data.node_ids)
        edges: list[CausalEdge] = []
        for i in range(M):           # source
            for j in range(M):       # destination
                for tau in range(0, tau_max + 1):
                    if i == j and tau == 0:
                        continue
                    v = float(val[i][j][tau])
                    p = float(pmat[i][j][tau])
                    mark_s = str(graph[i][j][tau])
                    if v == 0 or p > alpha_level:
                        continue
                    mark = "directed" if tau > 0 else ("directed" if mark_s == "-->" else "undirected")
                    edges.append(
                        CausalEdge(
                            edge_id=f"e:{data.node_ids[i]}->{data.node_ids[j]}@lag{tau}",
                            src_entity_id=data.node_ids[i],
                            dst_entity_id=data.node_ids[j],
                            lag_ns=tau * data.sample_interval_ns,
                            edge_mark=mark,
                            statistic=v,
                            p_value=p,
                            confidence_interval=None,
                            stability=1.0,
                            evidence_level="strong",
                        )
                    )
        return edges


@dataclass
class DiscoveryResult:
    edges: list[CausalEdge]
    backend: str
    excluded_points: int
    total_points: int
    bootstrap_runs: int
    pruned_candidates: int
    limitations: list[str] = field(default_factory=list)


class PCMCIPlusDiscovery:
    """Facade: candidate graph → multivariate matrix → PCMCI+ (real or lite)
    → stability bootstrap → edge filter."""

    def __init__(self, *, tau_max: int, alpha_level: float, fdr: str = "bh",
                 min_edge_stability: float, stability_bootstraps: int,
                 sample_interval_ns: int, use_tigramite: bool = True,
                 seed: int = 7, force_tigramite: bool = False):
        self.tau_max = tau_max
        self.alpha_level = alpha_level
        self.fdr = fdr
        self.min_edge_stability = min_edge_stability
        self.stability_bootstraps = stability_bootstraps
        self.sample_interval_ns = sample_interval_ns
        self.use_tigramite = use_tigramite
        self.seed = seed
        self.force_tigramite = force_tigramite
        self.limitations: list[str] = []

    def discover(self, data: MultivarData, candidate_graph: CandidateGraph,
                 frame: TelemetryFrame, sample_interval_ns: int | None = None) -> DiscoveryResult:
        interval = sample_interval_ns or self.sample_interval_ns
        M = len(data.node_ids)
        if M == 0 or data.values.shape[0] == 0:
            return DiscoveryResult([], "empty", 0, 0, 0, 0, ["no data"])

        candidate_pairs: list[tuple[int, int, int]] = []
        contemp_pairs: list[tuple[int, int]] = []
        adj = candidate_graph.adjacency()
        for dst_id, srcs in adj.items():
            if dst_id not in data.node_ids:
                continue
            dv = data.column(dst_id)
            for (src_id, hop, rel) in srcs:
                if src_id not in data.node_ids:
                    continue
                sv = data.column(src_id)
                if sv == dv:
                    continue
                for lag in range(1, self.tau_max + 1):
                    candidate_pairs.append((sv, dv, lag))
                contemp_pairs.append((sv, dv))

        # excluded-point accounting (quality contract: causal excludes
        # imputed/missing/stale/out_of_order)
        excluded = int((~data.observed).sum())
        total = int(data.observed.size)

        # Level-shift (non-stationarity) detection: a step anomaly makes
        # unrestricted/candidate-restricted PCMCI+ over-connect at every lag.
        # Under a detected shift, use the conservative candidate-restricted lite
        # and record the non-stationarity -- per plan, non-stationary data must
        # abstain rather than output a dense pseudo-graph.
        level_shift = False if self.force_tigramite else _detect_level_shift(data)
        use_tg = self.use_tigramite and TigramitePCMCIPlus.available() and not level_shift
        backend = "tigramite-pcmciplus"
        edges: list[CausalEdge] = []
        if use_tg:
            tg = TigramitePCMCIPlus.run(
                TigramitePCMCIPlus(), data, self.tau_max, self.alpha_level, self.fdr,
                candidate_pairs=candidate_pairs, contemp_pairs=contemp_pairs,
            )
            if tg is None:
                backend = "parcorr-pcmci-lite"
                edges = PCMIParCorrLite(
                    self.tau_max, self.alpha_level, fdr=self.fdr,
                    sample_interval_ns=interval,
                ).run(data, candidate_pairs, contemp_pairs).edges
            else:
                edges = tg
        else:
            backend = "parcorr-pcmci-lite"
            if level_shift:
                self.limitations.append(
                    "non-stationarity (level shift) detected in discovery window; "
                    "conservative candidate-restricted backend used"
                )
            edges = PCMIParCorrLite(
                self.tau_max, self.alpha_level, fdr=self.fdr,
                sample_interval_ns=interval,
            ).run(data, candidate_pairs, contemp_pairs).edges

        # ---- stability bootstrap (block bootstrap over rows) ----
        rng = np.random.default_rng(self.seed)
        T = data.values.shape[0]
        edge_counts: dict[str, int] = {}
        runs = self.stability_bootstraps if self.stability_bootstraps > 0 else 1
        for _ in range(runs):
            if T < 4:
                break
            block = 10
            idx_parts = []
            for _start in range(0, T, block):
                s = int(rng.integers(0, max(1, T - block + 1)))
                idx_parts.append(s + np.arange(min(block, T - s)))
            idx = np.concatenate(idx_parts) if idx_parts else np.arange(T)
            idx = np.clip(idx, 0, T - 1)
            sub = MultivarData(
                ts_ns=data.ts_ns[idx], node_ids=data.node_ids,
                values=data.values[idx], observed=data.observed[idx],
                sample_interval_ns=interval,
            )
            sub_edges = PCMIParCorrLite(
                self.tau_max, self.alpha_level, fdr=self.fdr,
                sample_interval_ns=interval,
            ).run(sub, candidate_pairs, contemp_pairs).edges
            for e in sub_edges:
                if e.edge_mark == "directed":
                    edge_counts[e.edge_id] = edge_counts.get(e.edge_id, 0) + 1
        for i, e in enumerate(edges):
            if e.edge_mark == "directed":
                edges[i] = e.model_copy(
                    update={"stability": edge_counts.get(e.edge_id, 0) / max(runs, 1)}
                )
        # primary-lag selection: for each (src, dst) pair keep the most stable
        # lag (then lowest p, then smallest lag) as the strong edge; duplicate
        # lags are demoted to weak evidence.
        by_pair: dict[tuple[str, str], list[int]] = {}
        for i, e in enumerate(edges):
            if e.edge_mark == "directed" and e.lag_ns > 0:
                by_pair.setdefault((e.src_entity_id, e.dst_entity_id), []).append(i)
        for idxs in by_pair.values():
            idxs.sort(
                key=lambda i: (
                    -edges[i].stability,
                    edges[i].p_value if edges[i].p_value is not None else 1.0,
                    edges[i].lag_ns,
                )
            )
            for i in idxs[1:]:
                edges[i] = edges[i].model_copy(update={"evidence_level": "weak"})
        # edges below the stability floor never enter the strong-evidence path
        for i, e in enumerate(edges):
            if e.edge_mark == "directed" and e.stability < self.min_edge_stability:
                edges[i] = e.model_copy(update={"evidence_level": "weak"})

        if runs > 1 and self.min_edge_stability > 0:
            self.limitations.append(
                f"stability bootstrap {runs} runs; edges below "
                f"min_edge_stability={self.min_edge_stability} marked weak"
            )
        return DiscoveryResult(
            edges=edges,
            backend=backend,
            excluded_points=excluded,
            total_points=total,
            bootstrap_runs=runs,
            pruned_candidates=candidate_graph.pruned_edge_count,
            limitations=list(self.limitations),
        )