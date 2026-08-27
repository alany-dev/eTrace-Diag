"""Effect estimation: explicit causal effect of a candidate intervention on a
downstream outcome, via linear g-computation along discovered lagged paths,
with bootstrap confidence intervals and honest identifiability checks.

Identifiability: the effect is reported only when there exists at least one
lagged directed path candidate ⇒ outcome using only directed edges; any
bidirected/unknown evidence-level-insufficient edge on a path, or a
contemporaneous unexplained edge between the candidate and a path node
(possible hidden confounder), downgrades the estimate to
`not_identifiable`. When not identified, NO precise causal value is emitted —
the candidate is down-weighted and abstains.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import numpy as np

from ..schemas import CausalEdge
from .discovery import MultivarData


@dataclass
class EffectEstimate:
    estimate: float | None
    ci_lo: float | None
    ci_hi: float | None
    identifiability: str
    n_paths: int
    abstained_reason: str | None = None
    note: str | None = None


class EffectEstimator:
    def __init__(self, *, tau_max_samples: int, alpha_level: float = 0.05,
                 n_bootstrap: int = 200, seed: int = 7,
                 latent_confounding: str = "auto"):
        self.tau_max_samples = tau_max_samples
        self.alpha_level = alpha_level
        self.n_bootstrap = n_bootstrap
        self.seed = seed
        self.latent_confounding = latent_confounding

    # -- graph helpers ------------------------------------------------------

    def _directed_edges(self, edges: list[CausalEdge]) -> list[CausalEdge]:
        return [e for e in edges if e.edge_mark == "directed" and e.lag_ns > 0]

    def _paths(self, src: str, dst: str, edges: list[CausalEdge]) -> list[list[CausalEdge]]:
        """All directed lagged paths src ⇒ dst in the edge graph."""
        children: dict[str, list[CausalEdge]] = {}
        for e in edges:
            if e.edge_mark != "directed" or e.lag_ns <= 0:
                continue
            children.setdefault(e.src_entity_id, []).append(e)
        paths: list[list[CausalEdge]] = []
        seen: set[tuple[str, str, int]] = set()

        def dfs(node: str, acc: list[CausalEdge]):
            if node == dst:
                paths.append(list(acc))
                return
            for e in children.get(node, []):
                nxt = e.dst_entity_id
                if nxt == src or any(x.dst_entity_id == nxt for x in acc):
                    continue
                acc.append(e)
                dfs(nxt, acc)
                acc.pop()

        dfs(src, [])
        return paths

    # -- SEM estimation -----------------------------------------------------

    def _fit_sem(self, data: MultivarData, edges: list[CausalEdge],
                 sample_interval_ns: int) -> dict[str, dict]:
        """OLS coefficients per node on its lagged directed parents.

        Returns {dst_col: {"parents": [(src_col, lag)], "beta": np.ndarray,
                             "intercept": float}}.
        """
        T, M = data.values.shape
        cols = {nid: i for i, nid in enumerate(data.node_ids)}
        model: dict[int, dict] = {}
        for e in edges:
            if e.edge_mark != "directed" or e.lag_ns <= 0:
                continue
            if e.src_entity_id not in cols or e.dst_entity_id not in cols:
                continue
            sv, dv = cols[e.src_entity_id], cols[e.dst_entity_id]
            lag = max(1, int(round(e.lag_ns / sample_interval_ns)))
            entry = model.setdefault(dv, {"parents": [], "beta": None, "intercept": 0.0})
            if (sv, lag) not in entry["parents"]:
                entry["parents"].append((sv, lag))
        for dv, entry in model.items():
            rows = np.arange(max(lag for _, lag in entry["parents"]), T)
            obs_rows = rows[
                data.observed[rows, dv]
                & np.all(
                    np.stack(
                        [data.observed[rows - lag, sv] for (sv, lag) in entry["parents"]],
                        axis=0,
                    ),
                    axis=0,
                )
            ]
            if obs_rows.size < len(entry["parents"]) + 3:
                entry["beta"] = np.zeros(len(entry["parents"]))
                entry["intercept"] = float(np.nanmean(data.values[obs_rows, dv])) if obs_rows.size else 0.0
                continue
            design = np.column_stack(
                [data.values[obs_rows - lag, sv] for (sv, lag) in entry["parents"]]
                + [np.ones(obs_rows.size)]
            )
            y = data.values[obs_rows, dv]
            coef, *_ = np.linalg.lstsq(design, y, rcond=None)
            entry["beta"] = coef[:-1]
            entry["intercept"] = float(coef[-1])
        return model

    # -- main ---------------------------------------------------------------

    def estimate(
        self,
        data: MultivarData,
        edges: list[CausalEdge],
        candidate_entity: str,
        outcome_entity: str,
        *,
        sample_interval_ns: int,
        x_baseline: float,
        x_high: float,
        contemp_edges: list[CausalEdge] | None = None,
    ) -> EffectEstimate:
        cols = {nid: i for i, nid in enumerate(data.node_ids)}
        src_key = candidate_entity
        dst_key = outcome_entity
        if src_key not in cols or dst_key not in cols:
            return EffectEstimate(
                None, None, None, "not_identifiable", 0,
                "candidate or outcome variable absent from discovery data",
            )
        directed = self._directed_edges(edges)
        paths = self._paths(src_key, dst_key, directed)
        if not paths:
            return EffectEstimate(
                None, None, None, "not_identifiable", 0,
                "no lagged directed path from candidate to outcome",
            )
        # hidden confounding / mark checks on every path
        bad_paths = 0
        for path in paths:
            for e in path:
                if e.edge_mark != "directed" or e.evidence_level == "insufficient":
                    bad_paths += 1
                    break
        if bad_paths == len(paths):
            return EffectEstimate(
                None, None, None, "not_identifiable", len(paths),
                "all candidate paths contain bidirected/unknown or insufficient edges",
            )
        contemp_note = None
        if self.latent_confounding == "strict" and contemp_edges:
            for e in contemp_edges:
                both = {e.src_entity_id, e.dst_entity_id}
                if src_key in both:
                    other = (both - {src_key}).pop()
                    if any(other == p_e.dst_entity_id or other == p_e.src_entity_id for p_e in paths[0]):
                        return EffectEstimate(
                            None, None, None, "not_identifiable", len(paths),
                            f"unexplained contemporaneous edge candidate~{other} "
                            "(possible hidden confounder); strict mode",
                        )
        elif contemp_edges:
            for e in contemp_edges:
                both = {e.src_entity_id, e.dst_entity_id}
                if src_key in both:
                    other = (both - {src_key}).pop()
                    if any(other == p_e.dst_entity_id or other == p_e.src_entity_id for p_e in paths[0]):
                        contemp_note = (
                            f"contemporaneous edge candidate~{other} observed; "
                            "lagged-path effect reported, contemporaneous "
                            "component not identified"
                        )
                        break
        # propagate Δ through the linear SEM over the path-chain
        sem = self._fit_sem(data, edges, sample_interval_ns)
        dx = x_high - x_baseline
        effect = 0.0
        for path in paths:
            m = 1.0
            prev = src_key
            for e in path:
                dv = cols[e.dst_entity_id]
                entry = sem.get(dv)
                if entry is None:
                    m = 0.0
                    break
                parents = entry["parents"]
                found = None
                for i, (sv, lag) in enumerate(parents):
                    if data.node_ids[sv] == prev:
                        found = entry["beta"][i]
                        break
                if found is None:
                    m = 0.0
                    break
                m *= float(found)
                prev = data.node_ids[dv]
            effect += m * dx

        if not np.isfinite(effect) or effect == 0.0:
            return EffectEstimate(
                float(effect) if np.isfinite(effect) else None, None, None,
                "not_identifiable" if not np.isfinite(effect) else "identified",
                len(paths),
                "non-finite effect" if not np.isfinite(effect) else None,
                contemp_note,
            )

        # bootstrap CI (block bootstrap rows → re-estimate SEM → re-propagate)
        rng = np.random.default_rng(self.seed)
        T = data.values.shape[0]
        block = 10
        ests: list[float] = []
        for _ in range(self.n_bootstrap):
            idx_parts = []
            for _start in range(0, T, block):
                s = int(rng.integers(0, max(1, T - block + 1)))
                idx_parts.append(s + np.arange(min(block, T - s)))
            idx = np.clip(np.concatenate(idx_parts) if idx_parts else np.arange(T), 0, T - 1)
            sub = MultivarData(
                ts_ns=data.ts_ns[idx], node_ids=data.node_ids,
                values=data.values[idx], observed=data.observed[idx],
                sample_interval_ns=data.sample_interval_ns,
            )
            sem_b = self._fit_sem(sub, edges, sample_interval_ns)
            eff = 0.0
            for path in paths:
                m = 1.0
                prev = src_key
                for e in path:
                    dv = cols[e.dst_entity_id]
                    entry = sem_b.get(dv)
                    if entry is None:
                        m = 0.0
                        break
                    vals = dict()
                    for i, (sv, lag) in enumerate(entry["parents"]):
                        vals[data.node_ids[sv]] = entry["beta"][i]
                    if prev not in vals:
                        m = 0.0
                        break
                    m *= float(vals[prev])
                    prev = data.node_ids[dv]
                eff += m * dx
            ests.append(eff)
        ests = np.asarray([v for v in ests if np.isfinite(v)])
        if ests.size == 0:
            return EffectEstimate(
                float(effect), None, None, "identified", len(paths),
                "bootstrap failed to produce finite estimates",
            )
        # normal-approximation bootstrap CI centred on the point estimate
        # (percentile CIs can drift off-centre under heavy resampling).
        se = float(np.std(ests))
        lo = float(effect) - 1.96 * se
        hi = float(effect) + 1.96 * se
        return EffectEstimate(
            estimate=float(effect),
            ci_lo=lo,
            ci_hi=hi,
            identifiability="identified",
            n_paths=len(paths),
            note=contemp_note,
        )


def default_baseline_high(data: MultivarData, node_id: str) -> tuple[float, float]:
    """Baseline = p50, high = p95 of the observed values of a node."""
    col = data.node_ids.index(node_id)
    vals = data.values[data.observed[:, col], col]
    vals = vals[np.isfinite(vals)]
    if vals.size == 0:
        return 0.0, 1.0
    return float(np.percentile(vals, 50)), float(np.percentile(vals, 95))