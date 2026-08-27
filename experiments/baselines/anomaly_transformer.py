"""Anomaly Transformer (ICLR 2022) baseline — official model code (thuml repo)
run by this project's driver, evaluated with THIS project's no-point-adjust
metrics.

    uv run python -m experiments.baselines.anomaly_transformer \
        --data data/smd_at --num-epochs 3 --win-size 100 --seed 7

Limitations (recorded, not hidden):
- SMD subset (3 of 28 machines) for tractability.
- Official model weights/structure from the thuml/Anomaly-Transformer repo;
  the train loop and metric are this project's (the repo's own eval uses
  point-adjust). Point-adjust F1 is NOT reported as the primary metric.
- OmniAnomaly's official code is TensorFlow 1.x and cannot run on Python 3.11 —
  blocked in the model matrix.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import torch

REPO = "/tmp/attrans-repo"


def _load_model():
    sys.path.insert(0, REPO)
    sys.path.insert(0, str(Path(REPO) / "model"))
    from model.AnomalyTransformer import AnomalyTransformer
    return AnomalyTransformer


def build_windows(data, win_size: int):
    n = data.shape[0]
    xs = []
    for i in range(0, n - win_size + 1, win_size):
        xs.append(data[i : i + win_size])
    return np.asarray(xs, dtype=np.float32)


def run(args) -> dict:
    train = np.load(str(Path(args.data) / "SMD_train.npy"))
    test = np.load(str(Path(args.data) / "SMD_test.npy"))
    label = np.load(str(Path(args.data) / "SMD_test_label.npy"))
    # standardize on train
    mu = train.mean(axis=0, keepdims=True)
    sd = train.std(axis=0, keepdims=True) + 1e-8
    train_c = ((train - mu) / sd).astype(np.float32)
    test_c = ((test - mu) / sd).astype(np.float32)

    torch.manual_seed(args.seed)
    AT = _load_model()
    model = AT(win_size=args.win_size, enc_in=38, c_out=38, d_model=512, n_heads=8,
               e_layers=2, d_ff=512, dropout=0.0, activation="gelu",
               output_attention=True)
    model = model.float()
    opt = torch.optim.Adam(model.parameters(), lr=1e-4)
    criterion = torch.nn.MSELoss()
    train_x = build_windows(train_c, args.win_size)
    # train
    model.train()
    for _ in range(args.num_epochs):
        idx = np.random.permutation(len(train_x))
        for i in range(0, len(idx), args.batch_size):
            batch = torch.tensor(train_x[idx[i : i + args.batch_size]], dtype=torch.float32)
            opt.zero_grad()
            out, series, prior, sigmas = model(batch)
            loss = criterion(out, batch)
            loss.backward()
            opt.step()
    # test anomaly scores (reconstruction error per timestep)
    model.eval()
    cosine = torch.nn.CosineSimilarity(0)
    scores = np.zeros(test.shape[0])
    with torch.no_grad():
        for i in range(0, test.shape[0] - args.win_size + 1, args.win_size):
            w = torch.tensor(test_c[i : i + args.win_size][None], dtype=torch.float32)
            out, series, prior, sigmas = model(w)
            # reconstruction error across dims
            err = torch.mean((out[0] - w[0]) ** 2, dim=-1).numpy()
            scores[i : i + args.win_size] = err
    # normalize scores to [0,1]
    if scores.max() > scores.min():
        score_t = (scores - scores.min()) / (scores.max() - scores.min())
    else:
        score_t = scores
    # label grid alignment
    n = min(len(score_t), len(label))
    score_t = score_t[:n]
    label = label[:n]
    from experiments.run_detection import point_f1, segment_metrics, vus_pr
    pred = np.where(score_t > np.percentile(score_t, 99), 1.0, 0.0)
    pf = point_f1(pred, label)
    seg = segment_metrics(pred, label)
    v = vus_pr(score_t, label)
    return {
        "model": "anomaly_transformer",
        "machines": 3,
        "num_epochs": args.num_epochs,
        "params": sum(p.numel() for p in model.parameters()),
        **pf, **seg, "vus_pr": round(v, 4),
        "note": "official thuml model code; this project's no-adjust metrics; "
                "SMD 3-machine subset",
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--data", required=True)
    p.add_argument("--num-epochs", type=int, default=3)
    p.add_argument("--win-size", type=int, default=100)
    p.add_argument("--batch-size", type=int, default=512)
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args(argv)
    r = run(args)
    import json

    print(json.dumps(r, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())