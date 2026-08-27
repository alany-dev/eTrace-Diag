"""GDN (Graph Deviation Network, AAAI 2021) — attribution CONTRAST only.

Faithful core of the GDN paper: sensor embedding → learned attention adjacency
(top-k sparsified) → graph-attention (GAT) message passing → forecasting, with
per-sensor deviation used as the anomaly level. The learned attention/adjacency
is an ATTRIBUTION contrast — never named a causal edge. RCA ranking is
PageRank over the learned adjacency weighted by per-sensor deviation (the
GDN-style learned-dependency attribution; CausalRCA-style PageRank is recorded
separately in the run_rca output).

Uses torch (CPU). The main RCA pipeline never loads this on the edge path.
"""

from __future__ import annotations

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from ..schemas import RootCauseCandidate
from .shared import MultivarData  # type: ignore


class GDNSensorModel(nn.Module):
    """Sensor embedding + learned attention adjacency + GAT forecast."""

    def __init__(self, n_sensors: int, window: int, *, topk: int = 3, hidden: int = 32):
        super().__init__()
        self.n = n_sensors
        self.window = window
        self.topk = topk
        self.embed = nn.Embedding(n_sensors, hidden)
        nn.init.xavier_uniform_(self.embed.weight)
        # attention query/key per sensor for learned adjacency
        self.q = nn.Linear(hidden, hidden, bias=False)
        self.k = nn.Linear(hidden, hidden, bias=False)
        # forecast head: [window, n] -> [n] (next value per sensor)
        self.out = nn.Linear(window * n_sensors, n_sensors)

    def learned_adjacency(self) -> torch.Tensor:
        e = self.embed.weight  # (N, H)
        logits = torch.einsum("nh,mh->nm", self.q(e), self.k(e)) / np.sqrt(e.shape[1])
        a = torch.relu(torch.tanh(logits))
        # top-k sparsification per node (keep strongest k incoming)
        k = min(self.topk, self.n)
        vals, _ = torch.topk(a, k, dim=0)
        thr = vals[-1, :]  # per-destination threshold
        mask = a >= thr
        a = a * mask
        denom = a.sum(dim=0, keepdim=True) + 1e-8
        return a / denom

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        # x: (B, window, n)
        A = self.learned_adjacency()  # (N, N)
        # GAT-style message passing across sensors within the window (soft):
        # influence from neighbours for each timestep
        xt = x.transpose(1, 2)  # (B, n, window)
        h = torch.einsum("nm,bmw->bnw", A, xt)  # neighbors' values
        h = h.transpose(1, 2).reshape(x.shape[0], -1)  # (B, window*n)
        yhat = self.out(h)  # (B, n)
        return yhat, A


def train_gdn(data, *, window: int = 10, n_sensors: int | None = None,
              epochs: int = 200, lr: float = 1e-2, seed: int = 7) -> GDNSensorModel:
    """Train the GDN sensor model on the observed multivariate series."""
    torch.manual_seed(seed)
    X = data.values
    obs = data.observed
    # complete-case imputation with column median for forecasting inputs
    med = np.nanmedian(X, axis=0)
    Xc = np.where(np.isfinite(X), X, med)
    Xt = torch.tensor(Xc, dtype=torch.float32)
    T, n = Xt.shape
    if n_sensors is None:
        n_sensors = n
    model = GDNSensorModel(n_sensors, window, topk=max(2, min(3, n)))
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    xs, ys = [], []
    for t in range(T - window):
        xs.append(Xt[t : t + window])
        ys.append(Xt[t + window])
    xs = torch.stack(xs)  # (B, window, n)
    ys = torch.stack(ys)  # (B, n)
    for _ in range(epochs):
        opt.zero_grad()
        yhat, A = model(xs)
        loss = F.mse_loss(yhat, ys) + 1e-3 * torch.norm(A, 1)
        loss.backward()
        opt.step()
    return model


def gdn_rank(data, *, window: int = 10, epochs: int = 200, seed: int = 7,
             incident=None, anomalous_metrics: list[str] | None = None,
             top_k: int = 5) -> list[RootCauseCandidate]:
    """GDN-attribution contrast ranking: PageRank over the learned adjacency,
    weighted by per-sensor forecast deviation. NOT a causal graph."""
    model = train_gdn(data, window=window, n_sensors=len(data.node_ids),
                      epochs=epochs, seed=seed)
    torch.manual_seed(seed)
    Xc = np.where(np.isfinite(data.values), data.values, np.nanmedian(data.values, axis=0))
    Xt = torch.tensor(Xc, dtype=torch.float32)
    T, n = Xt.shape
    xs = torch.stack([Xt[t : t + window] for t in range(T - window)])
    ys = torch.stack([Xt[t + window] for t in range(T - window)])
    with torch.no_grad():
        yhat, A = model(xs)
    dev = ((yhat - ys) ** 2).mean(dim=0).numpy()  # per-sensor forecast deviation
    # PageRank over learned adjacency: r = r @ A; take stationary distribution
    Anp = A.detach().numpy().T  # column-stochastic already in learned_adjacency
    r = np.full(n, 1.0 / n)
    for _ in range(200):
        r = 0.85 * (r @ Anp) + 0.15 / n
    score = (dev / (dev.max() + 1e-8)) * 0.5 + r * 0.5
    order = np.argsort(-score)
    out = []
    for rank, idx in enumerate(order[:top_k], start=1):
        nid = data.node_ids[idx]
        metric = nid.split("::")[1]
        direction = incident.directions.get(metric, "mixed") if incident else "mixed"
        out.append(
            RootCauseCandidate(
                entity_id=nid,
                rank=rank,
                score=round(float(score[idx]), 6),
                direction=direction,
                identifiability="not_tested",
                abstained_reason=(
                    "GDN learned-dependency/attention attribution; "
                    "NOT a causal edge (see evaluation-protocol)"
                ),
            )
        )
    return out