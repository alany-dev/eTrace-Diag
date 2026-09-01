"""Time-RCD (ICML 2026) zero-shot TSAD baseline driver + module matrix harness.

Frozen Time-RCD checkpoint (`thu-sail-lab/Time-RCD`, Apache-2.0) scores SMD
windows directly — no training, no labels. Each `--module` replaces exactly one
component around the frozen model; every run records point/seg F1 and VUS-PR
honestly, including regressions and failures.

    uv run python -m experiments.baselines.time_rcd --data-root data/smd \
        --limit-machines 3 --module base --output results/time_rcd/base.json

Threshold policy (zero-shot rule, documented in
docs/research/evaluation-protocol.md):
- VUS-PR (threshold-free) is the headline metric.
- point/seg F1 at a FIXED 0.5 threshold for threshold-free modules
  (--threshold overrides the base module only).
- Modules that calibrate a threshold do so ONLY on SMD per-machine TRAIN file
  scores — the SMD train file contains anomalies, so every calibrated run
  records `calibration_basis: "smd-train-contaminated"`. Test labels never
  participate in calibration.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np


def _ewma(x: np.ndarray, alpha: float) -> np.ndarray:
    from scipy.signal import lfilter

    if len(x) == 0:
        return x
    # y[0] = x[0]; y[t] = alpha*x[t] + (1-alpha)*y[t-1]
    zi = np.array([(1.0 - alpha) * x[0]])
    out, _ = lfilter([alpha], [1.0, -(1.0 - alpha)], x, zi=zi)
    return out


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-z))


def _cusum(scores: np.ndarray, k: float, h: float) -> tuple[np.ndarray, np.ndarray]:
    """One-sided CUSUM. Returns (statistic S_t, alarm flags). Reset after alarm."""
    stat = np.zeros(len(scores), dtype=np.float64)
    pred = np.zeros(len(scores), dtype=np.float64)
    s = 0.0
    for t in range(len(scores)):
        s = max(0.0, s + scores[t] - k)
        stat[t] = s
        if s > h:
            pred[t] = 1.0
            s = 0.0
    return stat, pred


def _robust_z(mat: np.ndarray, med: np.ndarray, mad: np.ndarray) -> np.ndarray:
    denom = 1.4826 * np.maximum(mad, 1e-8)
    return np.max(np.abs(mat - med) / denom, axis=1)


def _weighted_quantile(values: np.ndarray, weights: np.ndarray, q: float) -> float:
    order = np.argsort(values)
    cdf = np.cumsum(weights[order]) / weights.sum()
    idx = int(np.searchsorted(cdf, q))
    return float(values[order[min(idx, len(values) - 1)]])


def _minmax01(x: np.ndarray) -> np.ndarray:
    lo, hi = float(x.min()), float(x.max())
    if hi - lo < 1e-12:
        return np.zeros_like(x, dtype=np.float64)
    return (x - lo) / (hi - lo)


def _load_machines(data_root: Path, limit: int) -> list[dict]:
    test_dir = data_root / "test"
    label_dir = data_root / "test_label"
    train_dir = data_root / "train"
    if not (test_dir.is_dir() and label_dir.is_dir() and train_dir.is_dir()):
        raise FileNotFoundError(
            f"SMD not found under {data_root}; use experiments/download_data.py"
        )
    machines = []
    for test_file in sorted(test_dir.glob("machine-*.txt")):
        name = test_file.stem
        label_file = label_dir / f"{name}.txt"
        train_file = train_dir / f"{name}.txt"
        if not (label_file.exists() and train_file.exists()):
            continue
        test = np.loadtxt(test_file, delimiter=",")
        labels = np.loadtxt(label_file).reshape(-1)
        train = np.loadtxt(train_file, delimiter=",")
        if test.ndim == 1:
            test = test.reshape(-1, 1)
        if train.ndim == 1:
            train = train.reshape(-1, 1)
        machines.append({"name": name, "test": test, "labels": labels, "train": train})
        if limit > 0 and len(machines) >= limit:
            break
    return machines


# ---------------------------------------------------------------------------
# Module registry. Each entry: fn(det, test, train, args) -> (final, threshold, extra)
# ---------------------------------------------------------------------------


def _mod_base(det, test, train, args):
    return det.predict(test), args.threshold, {}


def _mod_median(det, test, train, args, size: int):
    from scipy.ndimage import median_filter

    scores = det.predict(test)
    return median_filter(scores, size=size), 0.5, {}


def _mod_ewma(det, test, train, args, alpha: float):
    scores = det.predict(test)
    return _ewma(scores, alpha), 0.5, {}


def _mod_cusum(det, test, train, args):
    train_scores = det.predict(train)
    k = 0.5 * float(np.std(train_scores))
    h = 4.0 * float(np.std(train_scores))
    scores = det.predict(test)
    stat, pred = _cusum(scores, k, h)
    # VUS-PR runs on the CUSUM statistic; point/seg F1 on the alarm flags.
    return {"final": stat, "pred": pred}, h, {"cusum_k": k, "cusum_h": h}


def _mod_temp(det, test, train, args, temp: float):
    _, logits = det.predict(test, return_logits=True)
    return _sigmoid(logits / temp), 0.5, {}


def _mod_quantile(det, test, train, args, q: float):
    train_scores = det.predict(train)
    thr = float(np.quantile(train_scores, q))
    scores = det.predict(test)
    return scores, thr, {}


def _pot_threshold(train_scores: np.ndarray) -> tuple[float, bool]:
    from scipy.stats import genpareto

    smoothed = _ewma(train_scores, 0.2)
    z = float(np.quantile(smoothed, 0.99))
    try:
        excess = smoothed[smoothed > z] - z
        if len(excess) < 4 or float(np.std(excess)) < 1e-4:
            raise ValueError("insufficient exceedances for GPD fit")
        shape, loc, scale = genpareto.fit(excess, floc=0.0)
        tail = z + float(genpareto.ppf(0.999, shape, loc=loc, scale=scale))
        return max(z, tail), False
    except Exception:
        return float(np.quantile(smoothed, 0.995)), True


def _mod_pot_gpd(det, test, train, args):
    train_scores = det.predict(train)
    thr, failed = _pot_threshold(train_scores)
    scores = det.predict(test)
    return scores, thr, {"gpd_fit_failed": failed}


def _mod_conformal(det, test, train, args, tau: float, alpha: float):
    train_scores = det.predict(train)
    n = len(train_scores)
    # exponential decay, most recent heaviest (t=n-1 -> weight 1)
    weights = np.exp(-np.arange(n - 1, -1, -1) / tau)
    thr = _weighted_quantile(train_scores, weights, 1.0 - alpha)
    scores = det.predict(test)
    return scores, thr, {}


def _mod_unifusion(det, test, train, args, mode: str):
    # Per-channel univariate scoring with the uni checkpoint (batch 64), then fuse.
    from time_rcd.detector import TimeRCDDetector

    uni = TimeRCDDetector.from_pretrained(
        variant="uni", win_size=args.win_size, batch_size=64, device=args.device_resolved
    )
    per_channel = np.stack(
        [uni.predict(test[:, c : c + 1]) for c in range(test.shape[1])], axis=1
    )
    fused = per_channel.max(axis=1) if mode == "max" else per_channel.mean(axis=1)
    return fused, 0.5, {"checkpoint": uni.checkpoint_path}


def _mod_multiscale(det, test, train, args):
    from time_rcd.detector import TimeRCDDetector

    half = TimeRCDDetector.from_pretrained(
        variant=args.variant,
        win_size=args.win_size // 2,
        batch_size=args.batch_size,
        device=args.device_resolved,
    )
    s1 = _minmax01(det.predict(test))
    s2 = _minmax01(half.predict(test))
    return 0.5 * (s1 + s2), 0.5, {"checkpoint": half.checkpoint_path}


def _mod_overlap_half(det, test, train, args):
    offset = args.win_size // 2
    s1 = det.predict(test)
    s2 = det.predict(test[offset:])
    out = s1.copy()
    out[offset:] = 0.5 * (s1[offset:] + s2)
    return out, 0.5, {}


def _mod_fusion_robust(det, test, train, args, w: float):
    med = np.median(train, axis=0)
    mad = np.median(np.abs(train - med), axis=0)
    z_train = _robust_z(train, med, mad)
    z_test = _robust_z(test, med, mad)
    q99 = max(float(np.quantile(z_train, 0.99)), 1e-8)
    zn = np.minimum(1.0, z_test / q99)
    scores = det.predict(test)
    return (1.0 - w) * scores + w * zn, 0.5, {}


def _mod_cascade(det, test, train, args, q: float):
    win = args.win_size
    med = np.median(train, axis=0)
    mad = np.median(np.abs(train - med), axis=0)
    z_test = _robust_z(test, med, mad)
    z_train = _robust_z(train, med, mad)

    def window_max(z: np.ndarray) -> np.ndarray:
        return np.array(
            [z[i : i + win].max() for i in range(0, len(z), win)], dtype=np.float64
        )

    gate = float(np.quantile(window_max(z_train), q))
    wm = window_max(z_test)
    flagged = wm > gate
    gate_pass_rate = float(flagged.mean())

    scores = np.zeros(len(z_test), dtype=np.float64)
    slices = []
    for i in range(len(flagged)):
        if flagged[i]:
            slices.append(test[i * win : (i + 1) * win])
    if slices:
        flagged_scores = det.predict(np.concatenate(slices, axis=0))
        pos = 0
        for i in range(len(flagged)):
            if flagged[i]:
                n = min(win, len(z_test) - i * win)
                scores[i * win : i * win + n] = flagged_scores[pos : pos + n]
                pos += n
    return scores, 0.5, {"gate_pass_rate": gate_pass_rate, "gate_threshold": gate}


def _mod_ptq_int8(det, test, train, args):
    import torch

    if not getattr(_mod_ptq_int8, "_done", False):
        det.predict(test)  # warm-up: initializes the lazily-built model
        det._tester.model = torch.ao.quantization.quantize_dynamic(
            det._tester.model, {torch.nn.Linear}, dtype=torch.qint8
        )
        _mod_ptq_int8._done = True
    return det.predict(test), args.threshold, {}


def _apply_stage(stage: str, scores: np.ndarray, test=None, train=None):
    """Apply one post-processing stage to a score series. Stages are the
    accuracy winners of the module matrix (combination stage, see docs)."""
    from scipy.ndimage import median_filter

    if stage == "median-k3":
        return median_filter(scores, size=3)
    if stage == "median-k5":
        return median_filter(scores, size=5)
    if stage == "ewma-a02":
        return _ewma(scores, 0.2)
    if stage == "ewma-a05":
        return _ewma(scores, 0.5)
    if stage in ("fusion-robust-03", "fusion-robust-05"):
        w = 0.3 if stage.endswith("03") else 0.5
        med = np.median(train, axis=0)
        mad = np.median(np.abs(train - med), axis=0)
        z_train = _robust_z(train, med, mad)
        z_test = _robust_z(test, med, mad)
        q99 = max(float(np.quantile(z_train, 0.99)), 1e-8)
        zn = np.minimum(1.0, z_test / q99)
        return (1.0 - w) * scores + w * zn
    raise ValueError(f"unknown combo stage {stage!r}")


def _mod_combo(det, test, train, args, stage_a: str, stage_b: str):
    if stage_a.startswith("temp"):
        temp = float(stage_a.split("-")[1]) / 10.0
        _, logits = det.predict(test, return_logits=True)
        scores = _sigmoid(logits / temp)
    else:
        scores = det.predict(test)
        scores = _apply_stage(stage_a, scores, test, train)
    scores = _apply_stage(stage_b, scores, test, train)
    return scores, 0.5, {"stage_a": stage_a, "stage_b": stage_b}


def _mod_combo_quantile(det, test, train, args, stage: str, q: float):
    """Accuracy combo: stage-smoothed scores + train-calibrated quantile
    threshold (smd-train-contaminated basis, as documented)."""
    train_scores = det.predict(train)
    thr = float(np.quantile(_apply_stage(stage, train_scores, train, train), q))
    scores = det.predict(test)
    scores = _apply_stage(stage, scores, test, train)
    return scores, thr, {"stage": stage}


def _make_registry() -> dict[str, tuple]:
    reg = {
        "base": (_mod_base, "fixed-0.5", "none"),
        "median-k3": (lambda d, t, tr, a: _mod_median(d, t, tr, a, 3), "fixed-0.5", "none"),
        "median-k5": (lambda d, t, tr, a: _mod_median(d, t, tr, a, 5), "fixed-0.5", "none"),
        "ewma-a02": (lambda d, t, tr, a: _mod_ewma(d, t, tr, a, 0.2), "fixed-0.5", "none"),
        "ewma-a05": (lambda d, t, tr, a: _mod_ewma(d, t, tr, a, 0.5), "fixed-0.5", "none"),
        "cusum": (_mod_cusum, "cusum-h", "smd-train-contaminated"),
        "temp-20": (lambda d, t, tr, a: _mod_temp(d, t, tr, a, 2.0), "fixed-0.5", "none"),
        "temp-05": (lambda d, t, tr, a: _mod_temp(d, t, tr, a, 0.5), "fixed-0.5", "none"),
        "quantile-0995": (
            lambda d, t, tr, a: _mod_quantile(d, t, tr, a, 0.995),
            "quantile-0.995-train",
            "smd-train-contaminated",
        ),
        "pot-gpd": (_mod_pot_gpd, "pot-gpd-train", "smd-train-contaminated"),
        "conformal-0005": (
            lambda d, t, tr, a: _mod_conformal(d, t, tr, a, 500.0, 0.005),
            "conformal-0.005-train",
            "smd-train-contaminated",
        ),
        "unifusion-max": (
            lambda d, t, tr, a: _mod_unifusion(d, t, tr, a, "max"),
            "fixed-0.5",
            "none",
        ),
        "unifusion-mean": (
            lambda d, t, tr, a: _mod_unifusion(d, t, tr, a, "mean"),
            "fixed-0.5",
            "none",
        ),
        "multiscale": (_mod_multiscale, "fixed-0.5", "none"),
        "overlap-half": (_mod_overlap_half, "fixed-0.5", "none"),
        "fusion-robust-03": (
            lambda d, t, tr, a: _mod_fusion_robust(d, t, tr, a, 0.3),
            "fixed-0.5",
            "smd-train-contaminated",
        ),
        "fusion-robust-05": (
            lambda d, t, tr, a: _mod_fusion_robust(d, t, tr, a, 0.5),
            "fixed-0.5",
            "smd-train-contaminated",
        ),
        "cascade-g095": (
            lambda d, t, tr, a: _mod_cascade(d, t, tr, a, 0.95),
            "cascade-gate-0.95-train",
            "smd-train-contaminated",
        ),
        "cascade-g099": (
            lambda d, t, tr, a: _mod_cascade(d, t, tr, a, 0.99),
            "cascade-gate-0.99-train",
            "smd-train-contaminated",
        ),
        "ptq-int8-dynamic": (_mod_ptq_int8, "fixed-0.5", "none"),
    }
    reg.update(_make_combo_entries())
    return reg


def _make_combo_entries() -> dict[str, tuple]:
    """Combination-stage entries: two-module chains from the accuracy winners
    of the module matrix, plus one threshold-calibrated combo."""
    combos = {
        "combo-med5-ewma02": ("median-k5", "ewma-a02", None),
        "combo-ewma02-fusion03": ("ewma-a02", "fusion-robust-03", None),
        "combo-med5-fusion03": ("median-k5", "fusion-robust-03", None),
        "combo-fusion03-med5": ("fusion-robust-03", "median-k5", None),
        "combo-temp20-ewma02": ("temp-20", "ewma-a02", None),
        "combo-ewma05-med5": ("ewma-a05", "median-k5", None),
    }
    out = {}
    for name, (a, b, _q) in combos.items():
        out[name] = (
            (lambda d, t, tr, args, sa=a, sb=b: _mod_combo(d, t, tr, args, sa, sb)),
            "fixed-0.5",
            "smd-train-contaminated" if "fusion" in a or "fusion" in b else "none",
        )
    out["combo-ewma02-q0995"] = (
        lambda d, t, tr, args: _mod_combo_quantile(d, t, tr, args, "ewma-a02", 0.995),
        "quantile-0.995-train",
        "smd-train-contaminated",
    )
    return out


MODULE_NOTES = {
    "base": None,
    "median-k3": "3-point median smoothing",
    "median-k5": "5-point median smoothing",
    "ewma-a02": "EWMA alpha=0.2",
    "ewma-a05": "EWMA alpha=0.5",
    "cusum": "one-sided CUSUM on raw scores; reset after alarm",
    "temp-20": "temperature-scaled logits, T=2.0",
    "temp-05": "temperature-scaled logits, T=0.5",
    "quantile-0995": "threshold = quantile 0.995 of smd train-file scores",
    "pot-gpd": "Telemanom-style POT/GPD on EWMA(0.2)-smoothed train scores",
    "conformal-0005": "simplified W1-ACAS: decay-weighted (tau=500) 0.995 quantile of train scores",
    "unifusion-max": "per-channel uni checkpoint, max fusion across 38 channels",
    "unifusion-mean": "per-channel uni checkpoint, mean fusion across 38 channels",
    "multiscale": "win 5000 + 2500 detectors, min-max normalized, averaged",
    "overlap-half": "two shifted passes (offset=win/2), averaged where both cover",
    "fusion-robust-03": "robust-z fusion, w=0.3",
    "fusion-robust-05": "robust-z fusion, w=0.5",
    "cascade-g095": (
        "window gate on robust-z (q=0.95 of train window-max); non-flagged windows "
        "score 0; concatenating non-contiguous windows changes context"
    ),
    "cascade-g099": (
        "window gate on robust-z (q=0.99 of train window-max); non-flagged windows "
        "score 0; concatenating non-contiguous windows changes context"
    ),
    "ptq-int8-dynamic": "dynamic INT8 PTQ on Linear layers; failure recorded honestly",
    "combo-med5-ewma02": "combo: median-k5 then EWMA a=0.2",
    "combo-ewma02-fusion03": "combo: EWMA a=0.2 then robust-z fusion w=0.3",
    "combo-med5-fusion03": "combo: median-k5 then robust-z fusion w=0.3",
    "combo-fusion03-med5": "combo: robust-z fusion w=0.3 then median-k5",
    "combo-temp20-ewma02": "combo: temperature T=2.0 then EWMA a=0.2",
    "combo-ewma05-med5": "combo: EWMA a=0.5 then median-k5",
    "combo-ewma02-q0995": "combo: EWMA a=0.2 scores + quantile-0.995 train threshold",
}


def run(args) -> dict:
    import torch

    from experiments.run_detection import point_f1, segment_metrics, vus_pr
    from time_rcd.detector import TimeRCDDetector

    data_root = Path(args.data_root)
    machines = _load_machines(data_root, args.limit_machines)
    if not machines:
        raise SystemExit(f"no SMD machines found under {data_root}")

    device = args.device_resolved
    if args.checkpoint_local:
        det = TimeRCDDetector.from_local(
            args.checkpoint_local,
            variant=args.variant,
            win_size=args.win_size,
            batch_size=args.batch_size,
            device=device,
        )
    else:
        try:
            det = TimeRCDDetector.from_pretrained(
                variant=args.variant,
                win_size=args.win_size,
                batch_size=args.batch_size,
                device=device,
            )
        except Exception as e:
            print(
                "Time-RCD checkpoint download failed. Hints:\n"
                "  - HF_ENDPOINT=https://hf-mirror.com uv run python -m "
                "experiments.baselines.time_rcd ...\n"
                "  - or pass a manually downloaded pth via --checkpoint-local",
                file=sys.stderr,
            )
            raise
    print(f"resolved checkpoint: {det.checkpoint_path}")

    registry = _make_registry()
    fn, threshold_rule, calibration_basis = registry[args.module]

    rows = []
    total_wall = 0.0
    for m in machines:
        test = m["test"]
        train = m["train"]
        if args.channel_top_k > 0:
            var = train.var(axis=0)
            top = np.argsort(var)[::-1][: args.channel_top_k]
            test = test[:, top]
            train = train[:, top]
        t0 = time.time()
        final, threshold, extra = fn(det, test, train, args)
        wall = time.time() - t0
        total_wall += wall

        if isinstance(final, dict):  # modules with an explicit pred override
            score_series = final["final"]
            pred = final["pred"].astype(np.float64)
        else:
            score_series = np.asarray(final, dtype=np.float64)
            pred = (score_series > threshold).astype(np.float64)

        n = min(len(score_series), len(m["labels"]))
        score_series = score_series[:n]
        labels = m["labels"][:n].astype(np.float64)
        if getattr(args, "dump_scores", None):
            dump_dir = Path(args.dump_scores)
            dump_dir.mkdir(parents=True, exist_ok=True)
            np.savez_compressed(
                dump_dir / f"{args.experiment}_{m['name']}.npz",
                scores=score_series,
                pred=pred,
                labels=labels,
                threshold=np.asarray(threshold, dtype=np.float64),
            )


        pf = point_f1(pred, labels)["point_f1"]
        seg = segment_metrics(pred, labels)["seg_f1"]
        v = vus_pr(score_series, labels)
        row = {
            "machine": m["name"],
            "point_f1": round(float(pf), 4),
            "seg_f1": round(float(seg), 4),
            "vus_pr": round(float(v), 4),
            "threshold": round(float(threshold), 6),
            "wall_s": round(float(wall), 2),
        }
        for k in ("gate_pass_rate", "gate_threshold", "gpd_fit_failed"):
            if k in extra:
                row[k] = extra[k]
        rows.append(row)

    summary = {
        "experiment": args.experiment,
        "module": args.module,
        "variant": args.variant,
        "win_size": args.win_size,
        "batch_size": det.batch_size,
        "device": device,
        "threshold_rule": threshold_rule,
        "calibration_basis": calibration_basis,
        "channel_top_k": args.channel_top_k,
        "status": "ok",
        "note": MODULE_NOTES.get(args.module),
        "checkpoint": det.checkpoint_path,
        "machines": len(rows),
        "wall_s": round(total_wall, 2),
        "mean_point_f1": round(float(np.mean([r["point_f1"] for r in rows])), 4),
        "mean_seg_f1": round(float(np.mean([r["seg_f1"] for r in rows])), 4),
        "mean_vus_pr": round(float(np.mean([r["vus_pr"] for r in rows])), 4),
        "machine_rows": rows,
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2))
    return summary


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="experiments.baselines.time_rcd")
    p.add_argument("--data-root", default="data/smd")
    p.add_argument("--variant", choices=["uni", "multi"], default="multi")
    p.add_argument("--win-size", type=int, default=5000)
    p.add_argument("--batch-size", type=int, default=None)
    p.add_argument("--device", default="auto")
    p.add_argument("--limit-machines", type=int, default=3)
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument("--module", default="base")
    p.add_argument("--experiment", default=None)
    p.add_argument("--channel-top-k", type=int, default=0)
    p.add_argument("--autocast", choices=["off", "bf16", "fp16"], default="off")
    p.add_argument("--checkpoint-local", default=None)
    p.add_argument("--output", default=None)
    p.add_argument("--dump-scores", default=None)
    args = p.parse_args(argv)

    import torch

    if args.device == "auto":
        args.device_resolved = "cuda" if torch.cuda.is_available() else "cpu"
    else:
        args.device_resolved = args.device

    args.experiment = args.experiment or args.module
    if args.output is None:
        args.output = f"results/time_rcd/{args.experiment}.json"

    registry = _make_registry()
    if args.module not in registry:
        p.error(f"unknown module {args.module}; available: {sorted(registry)}")

    from time_rcd.detector import TimeRCDDetector

    if args.autocast != "off":
        dtype = torch.bfloat16 if args.autocast == "bf16" else torch.float16
        orig_predict = TimeRCDDetector.predict

        def autocast_predict(self, data, return_logits=False):
            with torch.autocast(device_type="cpu", dtype=dtype):
                return orig_predict(self, data, return_logits=return_logits)

        TimeRCDDetector.predict = autocast_predict

    try:
        r = run(args)
    except Exception as e:
        if args.module == "ptq-int8-dynamic":
            # Honest recording: a PTQ failure is a data point, not a crash.
            r = {
                "experiment": args.experiment,
                "module": args.module,
                "status": "failed",
                "note": f"ptq-int8-dynamic failed: {type(e).__name__}: {e}",
                "machines": 0,
            }
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(json.dumps(r, indent=2))
        else:
            raise
    print(json.dumps(r, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
