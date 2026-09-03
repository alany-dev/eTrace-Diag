"""Native Ψ-PC: faithful numpy port of RCD's causal discovery core.

Ported from RCAEval (FSE 2026, arXiv:2604.13522), MIT license:
- ``RCAEval/e2e/rcd.py`` (Ψ-PC driver, chunking, multi-phase)
- ``RCAEval/lib/causallearn/utils/PCUtils/SkeletonDiscovery.py`` (patched
  localized-PC skeleton discovery) and the patched ``CausalGraph``
- ``causallearn.utils.cit.chisq`` (chi-square CI test)

The causal-learn dependency is replaced by this module so TORAI runs on
Python 3.11 with numpy/sklearn/scipy only. Identifiers and semantics follow
the reference implementation; deviations are commented inline.
"""

import warnings

warnings.filterwarnings("ignore")  # reference parity: rcd.py ignores sklearn noise

from itertools import combinations
from typing import Sequence

import numpy as np
import pandas as pd
from scipy.special import gammaincc
from sklearn.preprocessing import KBinsDiscretizer

F_NODE = "F-node"
START_ALPHA = 0.001
ALPHA_STEP = 0.1
ALPHA_LIMIT = 1
LOCAL_ALPHA = 0.01
DEFAULT_GAMMA = 5

# causal-learn CONST_BINCOUNT_UNIQUE_THRESHOLD
_BINCOUNT_UNIQUE_THRESHOLD = 1e5


# ---------------------------------------------------------------- graph


class MiniCausalGraph:
    """Adjacency-matrix stand-in for causal-learn's patched ``CausalGraph``.

    Only the pieces Ψ-PC needs: skeleton edges, neighbor queries, p-value
    bookkeeping, the marginal-independence (MI) register and the CI-test
    cache/counters.
    """

    def __init__(self, no_of_var: int, labels: dict[int, str] | None = None):
        n = no_of_var
        # full skeleton: undirected edges between every pair
        self.graph = np.ones((n, n), dtype=np.int64)
        np.fill_diagonal(self.graph, 0)
        self.labels = dict(labels) if labels else {}
        self.sepset: dict[tuple[int, int], tuple] = {}
        # p_values[(x, y)] is a list of p-values, mirroring append_value on the
        # patched object array (p_value lists per ordered pair)
        self.p_values: dict[tuple[int, int], list[float]] = {}
        self.mi: list[int] = []
        self.citest_cache: dict[tuple, float] = {}
        self.no_ci_tests = 0
        self.data: np.ndarray | None = None
        self.cardinalities: np.ndarray | None = None

    def neighbors(self, i: int) -> np.ndarray:
        return np.where(self.graph[i, :] != 0)[0]

    def max_degree(self) -> int:
        return int(np.max(np.sum(self.graph != 0, axis=1)))

    def remove_edge(self, x: int, y: int) -> None:
        self.graph[x, y] = 0
        self.graph[y, x] = 0

    def append_to_mi(self, node: int) -> None:
        if node not in self.mi:
            self.mi.append(node)

    # patched CausalGraph.ci_test with cache and no_ci_tests counter
    def ci_test(self, i: int, j: int, S) -> float:
        self.no_ci_tests += 1
        i, j = (i, j) if i < j else (j, i)
        key = (i, j, tuple(sorted(set(S))))
        if key in self.citest_cache:
            return self.citest_cache[key]
        p = chisq_ci(self.data, i, j, S, cardinalities=self.cardinalities)
        self.citest_cache[key] = p
        return p

    def append_value(self, x: int, y: int, value: float) -> None:
        self.p_values.setdefault((x, y), []).append(value)

    # F-node children in the reference sense: neighbors of local node
    def successors(self, node: int) -> list[int]:
        return list(self.neighbors(node))


# ---------------------------------------------------------------- CI test


def _unique_indices(column: np.ndarray) -> np.ndarray:
    return np.unique(column, return_inverse=True)[1]


def chisq_ci(
    data: np.ndarray,
    x: int,
    y: int,
    S=(),
    cardinalities: np.ndarray | None = None,
) -> float:
    """Chi-square CI test, equivalent to ``causallearn.utils.cit.chisq``.

    ``data`` is (n_samples, n_vars) discrete; continuous input must be
    discretized first (``discretize``). ``S`` is a conditioning-set sequence.
    """
    x, y = int(x), int(y)
    S = sorted({int(s) for s in S})
    data = np.asarray(data)
    if data.dtype.kind not in "iu":
        data = np.apply_along_axis(_unique_indices, 0, data).astype(np.int64)
    if cardinalities is None:
        cardinalities = np.max(data, axis=0) + 1

    indexes = S + [x, y]
    dataSXY = data[:, indexes].T
    cardSXY = cardinalities[indexes]

    if len(cardSXY) == 2:  # S empty: 2D contingency table
        cardX, cardY = int(cardSXY[0]), int(cardSXY[1])
        xy_indexed = dataSXY[0] * cardY + dataSXY[1]
        xy_joint = np.bincount(xy_indexed, minlength=cardX * cardY).reshape(cardX, cardY)
        x_marg = np.sum(xy_joint, axis=1)
        y_marg = np.sum(xy_joint, axis=0)
        n = dataSXY.shape[1]
        expected = np.outer(x_marg, y_marg) / n
        return _chi2_pvalue(xy_joint[None], expected[None])

    # S non-empty: stratified 3D tables
    cardX, cardY = int(cardSXY[-2]), int(cardSXY[-1])
    card_s_prod = np.prod(cardSXY[:-2]) if len(cardSXY) > 2 else 1
    if 0 < card_s_prod < _BINCOUNT_UNIQUE_THRESHOLD:
        card_s = int(card_s_prod)
        card_cum = np.ones_like(cardSXY, dtype=np.int64)
        card_cum[:-1] = np.cumprod(cardSXY[1:][::-1])[::-1]
        sxy_indexed = card_cum[None] @ dataSXY
        counts = np.bincount(sxy_indexed[0], minlength=card_s * cardX * cardY).reshape(
            card_s, cardX, cardY
        )
        s_marg = np.sum(counts, axis=(1, 2))
        nz = s_marg != 0
        s_marg_nz = s_marg[nz]
        sxy_nz = counts[nz]
    else:
        cards = cardSXY[:-2]
        card_cum = np.ones_like(cards, dtype=np.int64)
        if len(cards) > 1:
            card_cum[:-1] = np.cumprod(cards[1:][::-1])[::-1]
        s_indexed = card_cum[None] @ dataSXY[:-2]
        uniq_s, inverse_s, s_marg_counts = np.unique(s_indexed, return_counts=True, return_inverse=True)
        card_s = len(uniq_s)
        sxy_indexed = inverse_s * cardX * cardY + dataSXY[-2] * cardY + dataSXY[-1]
        counts = np.bincount(sxy_indexed, minlength=card_s * cardX * cardY).reshape(
            card_s, cardX, cardY
        )
        s_marg_nz = s_marg_counts.astype(np.int64)
        sxy_nz = counts
    sx_nz = np.sum(sxy_nz, axis=2)
    sy_nz = np.sum(sxy_nz, axis=1)
    expected_nz = sx_nz[:, :, None] * sy_nz[:, None, :] / s_marg_nz[:, None, None]
    return _chi2_pvalue(sxy_nz, expected_nz)


def _chi2_pvalue(count_tables: np.ndarray, expected_tables: np.ndarray) -> float:
    """p-value of observed counts vs product-of-marginals expectation.

    Equivalent to causal-learn ``_CalculatePValue`` (chisq branch): zero
    expected cells must coincide with all-zero rows/columns and are excluded
    from both the statistic and the degrees of freedom.
    """
    e_zero = expected_tables == 0
    e_safe = np.where(e_zero, 1.0, expected_tables)
    stat = np.sum(((count_tables - expected_tables) ** 2) / e_safe)
    zero_rows = e_zero.all(axis=2).sum(axis=1)
    zero_cols = e_zero.all(axis=1).sum(axis=1)
    dof = np.sum((count_tables.shape[1] - 1 - zero_rows) * (count_tables.shape[2] - 1 - zero_cols))
    # chi2.sf(x, dof) == gammaincc(dof/2, x/2) exactly; the direct special
    # function skips scipy.stats' dispatch/validation (~54us -> ~1us per call,
    # measured on the 6.5k-call CI hot path).
    return 1.0 if dof == 0 else float(gammaincc(dof / 2.0, stat / 2.0))


# ---------------------------------------------------------------- discretize


def discretize(data: pd.DataFrame, bins: int, strategy: str = "kmeans") -> pd.DataFrame:
    """KBinsDiscretize all columns except the F-node column (kept 0/1)."""
    if F_NODE not in data.columns:
        non_f = data.columns
        f_vals = None
    else:
        non_f = [c for c in data.columns if c != F_NODE]
        f_vals = data[F_NODE]
    disc = data[non_f]
    if disc.shape[1] > 0:
        # kmeans discretization needs n_samples >= n_clusters(=bins); very
        # short windows (e.g. RE1 delay cases, ~4 samples after resample)
        # crash the reference too — fall back to quantile so the case runs.
        if strategy == "kmeans" and disc.shape[0] < bins:
            strategy = "quantile"
        enc = KBinsDiscretizer(
            n_bins=bins, encode="ordinal", strategy=strategy, subsample=None
        )
        transformed = enc.fit_transform(disc.to_numpy(dtype=np.float64))
        disc = pd.DataFrame(transformed, columns=non_f, index=data.index)
    if f_vals is not None:
        disc[F_NODE] = f_vals
    return disc


# ---------------------------------------------------------------- skeleton

def local_skeleton_discovery(
    data: np.ndarray,
    local_node: int,
    alpha: float,
    mi=(),
    labels: dict[int, str] | None = None,
    seed: int | None = None,
    priority: Sequence[str] | None = None,
) -> MiniCausalGraph:
    """Patched causal-learn ``local_skeleton_discovery``.

    Grows the local skeleton around ``local_node`` (the F-node). Nodes
    separated at depth 0 are registered as marginally independent (MI) and
    their edges to the F-node are removed in subsequent runs.
    """
    assert local_node < data.shape[1]
    no_of_var = data.shape[1]
    cg = MiniCausalGraph(no_of_var, labels=labels)
    cg.data = np.apply_along_axis(_unique_indices, 0, data).astype(np.int64)
    cg.cardinalities = np.max(cg.data, axis=0) + 1

    rng = np.random.RandomState(seed)
    if priority is not None:
        rank = {name: i for i, name in enumerate(priority)}
    else:
        rank = {}
    depth = -1
    x = local_node
    for i in mi:
        if i is not None and cg.graph[x, i] != 0:
            cg.remove_edge(x, i)

    while cg.max_degree() - 1 > depth:
        depth += 1
        neigh = cg.neighbors(x)
        if priority is not None:
            # F-node neighbours in priority order; unlisted appended in
            # original numeric order (labels may be None).
            local_neigh = np.array(
                sorted(
                    (int(n) for n in neigh),
                    key=lambda n: (rank.get(labels.get(int(n), ""), len(rank)), int(n)),
                )
            )
        else:
            local_neigh = rng.permutation(neigh)
        for y in local_neigh:
            y = int(y)
            neigh_y = cg.neighbors(y)
            neigh_y = np.delete(neigh_y, np.where(neigh_y == x))
            neigh_y_f: list[int] = []
            if depth > 0:
                neigh_y_f = [int(s) for s in neigh_y if x in cg.neighbors(s)]
            for S in combinations(neigh_y_f, depth):
                p = cg.ci_test(x, y, S)
                if p > alpha:
                    cg.remove_edge(x, y)
                    cg.sepset[(x, y)] = S
                    cg.sepset[(y, x)] = S
                    if depth == 0:
                        cg.append_to_mi(y)
                    break
                else:
                    cg.append_value(x, y, p)
                    cg.append_value(y, x, p)
    return cg


def skeleton_discovery(
    data: np.ndarray,
    alpha: float,
    labels: dict[int, str] | None = None,
    stable: bool = False,
    seed: int | None = None,
    priority: Sequence[str] | None = None,
) -> MiniCausalGraph:
    """Port of causal-learn ``skeleton_discovery`` (``stable=False`` path).

    The reference runs RCD with ``stable=False``: edges are removed as soon as
    an independence is found (edge_removal bookkeeping kept for parity).
    """
    n_features = data.shape[1]
    cg = MiniCausalGraph(n_features, labels=labels)
    cg.data = np.apply_along_axis(_unique_indices, 0, data).astype(np.int64)
    cg.cardinalities = np.max(cg.data, axis=0) + 1

    rng = np.random.RandomState(seed)  # deterministic tie-order, reference iterates 0..n
    if priority is not None:
        rank = {name: i for i, name in enumerate(priority)}
        node_key = lambda n: (rank.get(labels.get(int(n), ""), len(rank)), int(n))
    else:
        rank = {}
        node_key = None
    depth = -1
    while cg.max_degree() - 1 > depth:
        depth += 1
        if node_key is not None:
            x_order = sorted(range(n_features), key=node_key)
        else:
            x_order = range(n_features)
        for x in x_order:
            neigh_x = cg.neighbors(x)
            if len(neigh_x) < depth - 1:
                continue
            y_order = sorted((int(n) for n in neigh_x), key=node_key) if node_key else list(neigh_x)
            for y in y_order:
                y = int(y)
                neigh_x_noy = np.delete(neigh_x, np.where(neigh_x == y))
                if node_key is not None:
                    s_order = sorted((int(s) for s in neigh_x_noy), key=node_key)
                else:
                    s_order = sorted(int(s) for s in neigh_x_noy)
                for S in combinations(s_order, depth):
                    p = cg.ci_test(x, y, S)
                    if p > alpha:
                        edge1 = cg.graph[x, y]
                        edge2 = cg.graph[y, x]
                        if edge1 or edge2:
                            cg.remove_edge(x, y)
                            cg.sepset[(x, y)] = S
                            cg.sepset[(y, x)] = S
                        break
                    else:
                        cg.append_value(x, y, p)
                        cg.append_value(y, x, p)
    return cg


# ---------------------------------------------------------------- psi-pc


def _order_neighbors(neigh: list[int], p_values: np.ndarray) -> list[int]:
    """p-value-descending order via argmax stack (reference parity)."""
    _neigh = list(neigh)
    _p_values = np.array(p_values, dtype=np.float64, copy=True)
    stack: list[int] = []
    while _neigh:
        i = int(np.argmax(_p_values))
        node = _neigh[i]
        stack = [node] + stack
        _neigh.remove(node)
        _p_values = np.delete(_p_values, i)
    return stack


def run_psi_pc(
    normal_df: pd.DataFrame,
    anomal_df: pd.DataFrame,
    bins: int | None = None,
    mi=None,
    localized: bool = True,
    start_alpha: float | None = None,
    min_nodes: int = -1,
    seed: int | None = None,
    discretize_strategy: str = "kmeans",
    priority: Sequence[str] | None = None,
) -> tuple[list[str], int]:
    """Run Ψ-PC on normal/anomalous frames; return (ranked columns, ci_tests).

    Returns only what TORAI consumes (the reference also exposes the graph
    and post-processed MI list; ``mi`` bookkeeping stays internal).
    """
    if mi is None:
        mi = []
    if 0 in [len(normal_df.columns), len(anomal_df.columns)]:
        return [], 0

    data = add_fnode_and_concat(normal_df, anomal_df)
    if bins is not None:
        data = discretize(data, bins, strategy=discretize_strategy)

    if min_nodes == -1:
        min_nodes = len(data.columns) - 1

    no_ci = 0
    i_to_labels = {i: name for i, name in enumerate(data.columns)}
    labels_to_i = {name: i for i, name in enumerate(data.columns)}
    processed_mi = [labels_to_i[i] for i in mi if i in labels_to_i]

    f_node = data.shape[1] - 1
    rc: list[str] = []
    cg: MiniCausalGraph | None = None
    alpha = START_ALPHA if start_alpha is None else start_alpha
    for a in np.arange(alpha, ALPHA_LIMIT, ALPHA_STEP):
        if localized:
            cg = local_skeleton_discovery(
                data.to_numpy(), f_node, float(a), mi=processed_mi,
                labels=i_to_labels, seed=seed, priority=priority,
            )
        else:
            cg = skeleton_discovery(
                data.to_numpy(), float(a), labels=i_to_labels, seed=seed, priority=priority
            )
        no_ci += cg.no_ci_tests

        f_neigh = [int(n) for n in cg.successors(f_node)]
        new_neigh = [n for n in f_neigh if n not in [labels_to_i[r] for r in rc]]
        if not new_neigh:
            continue

        # last p-value per new neighbor (p_values lists mirror append_value)
        last_p = []
        for n in new_neigh:
            vals = cg.p_values.get((f_node, n), [])
            last_p.append(vals[-1] if vals else 0.0)
        ordered = _order_neighbors(new_neigh, np.array(last_p))
        rc += [i_to_labels[n] for n in ordered]

        if len(rc) == min_nodes:
            break

    return rc, no_ci


# ---------------------------------------------------------------- rcd driver


def add_fnode_and_concat(normal_df: pd.DataFrame, anomal_df: pd.DataFrame) -> pd.DataFrame:
    normal_df = normal_df.copy()
    anomal_df = anomal_df.copy()
    normal_df[F_NODE] = "0"
    anomal_df[F_NODE] = "1"
    return pd.concat([normal_df, anomal_df])


def _match_columns(n_df: pd.DataFrame, a_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    cols = [c for c in n_df.columns if c in a_df.columns]
    return n_df[cols], a_df[cols]


def create_chunks(df: pd.DataFrame, gamma: int, seed: int | None = None) -> list[np.ndarray]:
    rng = np.random.RandomState(seed)
    names = rng.permutation(df.columns)
    chunks = [names[i * gamma : (i * gamma) + gamma] for i in range(df.shape[1] // gamma + 1)]
    if chunks and len(chunks[-1]) == 0:
        chunks.pop()
    return chunks


def run_level(
    normal_df: pd.DataFrame,
    anomal_df: pd.DataFrame,
    gamma: int,
    localized: bool,
    bins: int,
    seed: int | None = None,
    discretize_strategy: str = "kmeans",
    priority: Sequence[str] | None = None,
) -> tuple[list[str], int]:
    """Phase-1: one level of chunked Ψ-PC; union of F-node children."""
    ci_tests = 0
    chunks = create_chunks(normal_df, gamma, seed=seed)
    f_child_union: list[str] = []
    for c in chunks:
        chunk_priority = None
        if priority is not None:
            cset = set(c)
            chunk_priority = [n for n in priority if n in cset] or None
        rc, ci = run_psi_pc(
            normal_df.loc[:, c],
            anomal_df.loc[:, c],
            bins=bins,
            localized=localized,
            start_alpha=LOCAL_ALPHA,
            min_nodes=1,
            seed=seed,
            discretize_strategy=discretize_strategy,
            priority=chunk_priority,
        )
        f_child_union += rc
        ci_tests += ci
    return f_child_union, ci_tests


def run_multi_phase(
    normal_df: pd.DataFrame,
    anomal_df: pd.DataFrame,
    gamma: int = DEFAULT_GAMMA,
    localized: bool = True,
    bins: int = 5,
    seed: int | None = None,
    discretize_strategy: str = "kmeans",
    priority: Sequence[str] | None = None,
) -> list[str]:
    """Full RCD: phase-1 shrink loop + phase-2 ordering; returns root causes."""
    f_child_union = list(normal_df.columns)
    i = 0
    prev = len(f_child_union)

    while True:
        f_child_union, ci = run_level(
            normal_df.loc[:, f_child_union],
            anomal_df.loc[:, f_child_union],
            gamma,
            localized,
            bins,
            seed=seed,
            discretize_strategy=discretize_strategy,
            priority=priority,
        )
        i += 1
        len_child = len(f_child_union)
        if len_child <= gamma or len_child == prev:
            break
        prev = len_child

    # phase-2
    rc, _ = run_psi_pc(
        normal_df.loc[:, f_child_union],
        anomal_df.loc[:, f_child_union],
        bins=bins,
        mi=[],
        localized=localized,
        seed=seed,
        discretize_strategy=discretize_strategy,
        priority=priority,
    )
    return rc
