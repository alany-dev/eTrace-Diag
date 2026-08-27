"""Neural Granger + DyNOTEARS — causal-discovery contrasts (torch).

- Neural Granger (NeurIPS 2019) — lagged-multilayer-perceptron regression;
  the summed absolute value of the first-layer lag weights is the
  nonlinear-Granger attribution (NOT a causal edge).
- DyNOTEARS (NeurIPS 2020) — dynamic structure learning: continuous DAG
  constraint (NOTEARS) over instantaneous + lagged coefficient matrices; the
  recovered adjacency is a structural equation model estimate, reported as a
  contrast (edges are linear-Granger + acyclicity-constrained, still
  observational).

Both return `CausalEdge` lists marked as contrast (evidence-level weak,
abstained reasons attached at rank time in run_rca)."""
from __future__ import annotations

import numpy as np
import torch
import torch.nn as nn

from ..schemas import CausalEdge


def neural_granger_edges(data, *, tau_max: int = 5, hidden: int = 32,
                         epochs: int = 400, lr: float = 1e-2, l1: float = 1e-2,
                         seed: int = 7, alpha_level: float = 0.05
                         ) -> list[CausalEdge]:
    """Neural Granger: each variable regressed on lags of all variables via a
    1-hidden-layer MLP; mean |W_1[:lag-block → target]| is the Granger score."""
    torch.manual_seed(seed)
    Xc = np.where(np.isfinite(data.values), data.values,
                  np.nanmedian(data.values, axis=0))
    X = torch.tensor(Xc, dtype=torch.float32)
    T, n = X.shape
    # build lag design
    xs, ys = [], []
    for t in range(tau_max, T):
        lag_block = X[t - tau_max : t].flatten()  # (tau_max*n,)
        xs.append(lag_block)
        ys.append(X[t])
    xs = torch.stack(xs)
    ys = torch.stack(ys)
    D = tau_max * n

    class NG(nn.Module):
        def __init__(self):
            super().__init__()
            self.fc1 = nn.Linear(D, hidden)
            self.fc2 = nn.Linear(hidden, n)

        def forward(self, x):
            return self.fc2(torch.tanh(self.fc1(x)))

    model = NG()
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    for _ in range(epochs):
        opt.zero_grad()
        yhat = model(xs)
        loss = nn.functional.mse_loss(yhat, ys) + l1 * torch.norm(model.fc1.weight, 1)
        loss.backward()
        opt.step()
    # Granger attribution: for target j, weight of lag-block i→j summed over lags
    W = model.fc1.weight.detach().numpy()  # (hidden, D)
    out: list[CausalEdge] = []
    for j in range(n):
        for i in range(n):
            block = W[:, i * tau_max : (i + 1) * tau_max]
            granger = float(np.mean(np.abs(block)))
            if i == j or granger < 1e-4:
                continue
            # pick strongest lag in the block as the reported lag
            lag = int(np.argmax(np.mean(np.abs(block), axis=0))) + 1
            out.append(
                CausalEdge(
                    edge_id=f"e:{data.node_ids[i]}->{data.node_ids[j]}@lag{lag}",
                    src_entity_id=data.node_ids[i],
                    dst_entity_id=data.node_ids[j],
                    lag_ns=lag * data.sample_interval_ns,
                    edge_mark="directed",
                    statistic=granger,
                    p_value=None,  # Neural Granger is score-based, not a test
                    confidence_interval=None,
                    stability=0.0,
                    evidence_level="weak",
                )
            )
    return out


def dynotears_edges(data, *, tau_max: int = 5, lamb: float = 0.1,
                    w_thresh: float = 0.05, seed: int = 7) -> list[CausalEdge]:
    """DyNOTEARS: minimize ||X - X Wc - L Wl||^2 + λ||W||_1 s.t.
    h(Wc)=0 (DAG), recovering instantaneous Wc and lagged Wl."""
    torch.manual_seed(seed)
    Xc = np.where(np.isfinite(data.values), data.values,
                  np.nanmedian(data.values, axis=0))
    X = torch.tensor(Xc, dtype=torch.float32)
    T, n = X.shape
    # lag design L: (T-tau_max, tau_max*n)
    rows = []
    for t in range(tau_max, T):
        rows.append(X[t - tau_max : t].flatten())
    L = torch.stack(rows)
    Y = X[tau_max:]
    nl = tau_max * n

    Wc = torch.zeros(n, n, requires_grad=True)
    Wl = torch.zeros(n, nl, requires_grad=True)
    opt = torch.optim.Adam([Wc, Wl], lr=1e-2)
    for _ in range(800):
        opt.zero_grad()
        rec = Y @ Wc.T + L @ Wl.T
        loss = torch.mean((Y - rec) ** 2)
        # NOTEARS DAG constraint h(W) = tr(e^{W∘W}) - n
        M = Wc * Wc
        h = torch.trace(torch.matrix_exp(M)) - n
        loss = loss + lamb * (torch.norm(Wc, 1) + torch.norm(Wl, 1)) + 0.5 * h * h
        loss.backward()
        opt.step()
    Wlnp = Wl.detach().numpy()
    edges: list[CausalEdge] = []
    for j in range(n):
        for i in range(n):
            if i == j:
                continue
            block = Wlnp[j, i * tau_max : (i + 1) * tau_max]  # i -> j
            v = float(np.max(np.abs(block)))
            if v < w_thresh:
                continue
            lag = int(np.argmax(np.abs(block))) + 1
            edges.append(
                CausalEdge(
                    edge_id=f"e:{data.node_ids[i]}->{data.node_ids[j]}@lag{lag}",
                    src_entity_id=data.node_ids[i],
                    dst_entity_id=data.node_ids[j],
                    lag_ns=lag * data.sample_interval_ns,
                    edge_mark="directed",
                    statistic=v,
                    p_value=None,
                    confidence_interval=None,
                    stability=0.0,
                    evidence_level="weak",
                )
            )
    return edges