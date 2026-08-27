"""Model 1 detection benchmark runner.

    uv run python -m experiments.run_detection \
        --config configs/benchmark.yaml \
        --dataset smd --models shesd,fits,edge_cascade --seed 7 --output results/smd

Dataset loaders keep a manifest (name, version, checksum); large datasets are
never committed. Metrics: point F1 (no point-adjust), segment/range P/R/F1,
VUS-PR, average detection delay, false alarms/hour, parameter count, p50/p95
single-window latency, peak RSS. Thresholds are fit on train/validation only —
test labels never participate in calibration.
"""

from __future__ import annotations

import argparse
import csv
import json
import time
from pathlib import Path

import numpy as np
import yaml

from alg_models.data.replay import load_replay
from alg_models.detection import DETECTOR_REGISTRY, get_detector
from alg_models.schemas import TelemetryFrame, TelemetryPoint


# --------------------------------------------------------------------------
# Dataset loaders
# --------------------------------------------------------------------------

def load_smd(root: str, seed: int) -> dict:
    """OmniAnomaly ServerMachineDataset. Files: train/machine-{i}-{j}.txt,
    test/machine-{i}-{j}.txt, test_label/machine-{i}-{j}.txt. 28 machines,
    38 dims. Returns per-machine train/test/labels frames."""
    root = Path(root)
    train_dir = root / "train"
    test_dir = root / "test"
    label_dir = root / "test_label"
    if not (train_dir.exists() and test_dir.exists() and label_dir.exists()):
        raise FileNotFoundError(
            f"SMD dataset not found at {root}; use experiments/download_data.py "
            "to fetch it (manifest + checksum recorded)."
        )
    out: dict[str, list] = {"train": [], "test": [], "labels": []}
    for train_file in sorted(train_dir.glob("machine-*.txt")):
        name = train_file.stem
        test_file = test_dir / f"{name}.txt"
        label_file = label_dir / f"{name}.txt"
        if not (test_file.exists() and label_file.exists()):
            continue
        train = np.loadtxt(train_file, delimiter=",")
        test = np.loadtxt(test_file, delimiter=",")
        labels = np.loadtxt(label_file, delimiter=",")
        if train.ndim == 1:
            train = train.reshape(-1, 1)
        if test.ndim == 1:
            test = test.reshape(-1, 1)
        out["train"].append((name, train))
        out["test"].append((name, test))
        out["labels"].append((name, labels))
    return out


def _frame_from_matrix(name: str, mat: np.ndarray, interval_ns: int,
                       start_ns: int = 0, source: str = "replay") -> TelemetryFrame:
    T, D = mat.shape
    pts = []
    for i in range(T):
        for d in range(D):
            pts.append(
                TelemetryPoint(
                    ts_ns=start_ns + i * interval_ns,
                    entity_id=f"machine:{name}",
                    entity_type="host",
                    metric_id=f"dim_{d}",
                    value=float(mat[i, d]),
                    source=source,
                    sample_interval_ns=interval_ns,
                )
            )
    return TelemetryFrame(points=tuple(pts))


def load_local(name: str, fixtures: Path) -> dict:
    """Deterministic local fixture dataset with synthetic labels (host_spike)."""
    path = fixtures / f"{name}.jsonl"
    if not path.exists():
        raise FileNotFoundError(f"fixture dataset {name} not found at {path}")
    frame = load_replay(path)
    ts = sorted({p.ts_ns for p in frame.points})
    anom_start = int(4200 * 1e9)
    anom_end = int(4500 * 1e9)
    labels = np.asarray([1.0 if anom_start <= t < anom_end else 0.0 for t in ts])
    out = {
        "train": [("local", np.zeros((0, 1)))],
        "test": [],
        "labels": [("local", labels)],
        "_frame": frame,
        "_anomaly": (anom_start, anom_end),
    }
    return out


DATASET_LOADERS = {
    "smd": load_smd,
    "host_spike": lambda root, seed: load_local("host_spike", Path("tests/fixtures")),
    "causal_disk_chain": lambda root, seed: load_local("causal_disk_chain", Path("tests/fixtures")),
}


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

def segment_metrics(score_t: np.ndarray, labels: np.ndarray) -> dict:
    """Range/segment P/R/F1 (overlap ≥1 predicted point in a labeled segment)."""
    pred = score_t > 0
    true = labels > 0
    # labeled segments
    segs: list[tuple[int, int]] = []
    in_seg = False
    for i, v in enumerate(true):
        if v and not in_seg:
            segs.append([i, i])
            in_seg = True
        elif v and in_seg:
            segs[-1][1] = i
        elif not v:
            in_seg = False
    # predicted segments
    psegs: list[tuple[int, int]] = []
    in_seg = False
    for i, v in enumerate(pred):
        if v and not in_seg:
            psegs.append([i, i])
            in_seg = True
        elif v and in_seg:
            psegs[-1][1] = i
        elif not v:
            in_seg = False
    if not segs or not psegs:
        return {"seg_precision": 0.0, "seg_recall": 0.0, "seg_f1": 0.0}
    tp_seg = sum(1 for (a, b) in psegs if any(a <= c <= b or a <= d <= b for (c, d) in segs) or any(c <= a <= d for (c, d) in segs))
    prec = tp_seg / len(psegs)
    rec = tp_seg / len(segs)
    return {
        "seg_precision": prec,
        "seg_recall": rec,
        "seg_f1": 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0,
    }


def point_f1(score_t: np.ndarray, labels: np.ndarray) -> dict:
    pred = score_t > 0
    true = labels > 0
    tp = int((pred & true).sum())
    fp = int((pred & ~true).sum())
    fn = int((~pred & true).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"point_precision": prec, "point_recall": rec, "point_f1": f1}


def vus_pr(score_t: np.ndarray, labels: np.ndarray, n_thresh: int = 100) -> float:
    """Volume under the precision-recall surface (interval-aware proxy:
    precision/recall at each threshold with a one-point forgiveness)."""
    pred_vals = score_t
    true = labels > 0
    # segment forgiveness: a prediction inside a labeled segment is a hit
    prs = []
    for q in np.linspace(0.0, 1.0, n_thresh):
        thr = float(np.quantile(pred_vals, 1 - q)) if pred_vals.size else 0.0
        pred = pred_vals >= thr
        tp = int((pred & true).sum())
        fp = int((pred & ~true).sum())
        fn = int((~pred & true).sum())
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        prs.append((prec, rec))
    # trapezoidal area
    area = 0.0
    for i in range(1, len(prs)):
        area += 0.5 * (prs[i][0] + prs[i - 1][0]) * abs(prs[i][1] - prs[i - 1][1])
    return area


def delay_and_fa(score_t: np.ndarray, labels: np.ndarray, interval_s: float) -> dict:
    true = labels > 0
    pred = score_t > 0
    # detection delay: first predicted point within each labeled segment
    delays: list[float] = []
    in_seg = False
    for i, v in enumerate(true):
        if v and not in_seg:
            seg_start = i
            in_seg = True
        elif v and in_seg:
            hit = np.where(pred[seg_start : i + 1])[0]
            if hit.size:
                delays.append(float(hit[0]))
                in_seg = False
    avg_delay = float(np.mean(delays)) * interval_s if delays else float("nan")
    # false alarms per hour: FP runs (contiguous false positive runs)
    fp_runs = 0
    in_run = False
    for i, v in enumerate(pred):
        if v and not true[i] and not in_run:
            in_run = True
        elif v and not true[i] and in_run:
            pass
        elif not (v and not true[i]):
            if in_run:
                fp_runs += 1
            in_run = False
    if in_run:
        fp_runs += 1
    hours = len(true) * interval_s / 3600.0
    return {
        "avg_detection_delay_s": avg_delay,
        "false_alarms_per_hour": fp_runs / hours if hours else float("nan"),
    }


def score_series(incidents: list, labels_times: list[int], interval_ns: int) -> np.ndarray:
    """Map detected incidents onto a per-timestamp binary score vector over the
    label timeline."""
    if not labels_times:
        return np.zeros(0)
    t0, t1 = labels_times[0], labels_times[-1]
    n = len(labels_times)
    out = np.zeros(n, dtype=float)
    for inc in incidents:
        for i, t in enumerate(labels_times):
            if inc.start_ts_ns <= t <= inc.end_ts_ns:
                out[i] = inc.severity
    return out


def run_detection(args: argparse.Namespace, cfg: dict) -> dict:
    dataset = args.dataset
    loader = DATASET_LOADERS.get(dataset)
    if loader is None:
        raise ValueError(f"unknown dataset {dataset!r}; available {sorted(DATASET_LOADERS)}")
    data = loader(args.root or "data", args.seed)
    if "_frame" in data:
        # local fixture: one continuous timeline, labels on its own grid
        frame: TelemetryFrame = data["_frame"]
        ts = sorted({p.ts_ns for p in frame.points})
        interval_ns = max(1, min((b - a for a, b in zip(ts, ts[1:]) if b > a), default=1))
        split = cfg.get("split", {"train_frac": 0.6, "val_frac": 0.2})
        from alg_models.cli import split_by_time

        train, val, test = split_by_time(frame, split["train_frac"], split["val_frac"])
        labels = data["labels"][0][1]
        return _evaluate_machine(
            "local", train, val, test, labels, ts, interval_ns, args, cfg
        )
    # SMD: per-machine train/test/label files. SMD samples at 60 s — a 60 s
    # window would hold a single sample (no trend ring); use 1 h windows.
    smd_window_ns = 3_600_000_000_000
    smd_stride_ns = 1_800_000_000_000
    results = []
    machines = list(zip(data["train"], data["test"], data["labels"]))
    if args.limit_machines:
        machines = machines[: args.limit_machines]
    for (name, train_mat), (_, test_mat), (_, labels) in machines:
        train = _frame_from_matrix(name, train_mat, 60_000_000_000)
        T = train_mat.shape[0]
        split = cfg.get("split", {"train_frac": 0.6, "val_frac": 0.2})
        from alg_models.cli import split_by_time

        tr, va, _ = split_by_time(train, split["train_frac"], split["val_frac"])
        # test timeline starts at 0 so incidents line up with the label grid
        test_frame = _frame_from_matrix(name, test_mat, 60_000_000_000, start_ns=0)
        ts = [i * 60_000_000_000 for i in range(test_mat.shape[0])]
        results.append(
            _evaluate_machine(
                name, tr, va, test_frame, labels, ts, 60_000_000_000, args, cfg,
                window_ns=smd_window_ns, stride_ns=smd_stride_ns,
            )
        )
    return {"machines": results}


def _evaluate_machine(name, train, val, test, labels, ts, interval_ns, args, cfg,
                      window_ns=None, stride_ns=None):
    metrics_rows = []
    for mname in args.models.split(","):
        det_cls = get_detector(mname)
        sig = det_cls.__init__.__code__.co_varnames
        kwargs = {k: v for k, v in cfg.get("detector", {}).items() if k in sig and k != "self"}
        if window_ns is not None:
            kwargs["window_ns"] = window_ns
            kwargs["stride_ns"] = stride_ns
        det = det_cls(**kwargs)
        t0 = time.perf_counter()
        card = det.fit(train, val, seed=args.seed)
        fit_ms = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter()
        incidents = det.score(test)
        score_ms = (time.perf_counter() - t0) * 1000
        score_t = score_series(incidents, ts, interval_ns)
        labels_arr = np.asarray(labels)
        if score_t.size == 0:
            score_t = np.zeros(labels_arr.size)
        pf = point_f1(score_t, labels_arr)
        seg = segment_metrics(score_t, labels_arr)
        vus = vus_pr(score_t, labels_arr)
        dl = delay_and_fa(score_t, labels_arr, interval_ns / 1e9)
        rows = {
            "machine": name,
            "model": mname,
            "params": card.params,
            "fit_ms": round(fit_ms, 3),
            "score_ms": round(score_ms, 3),
            **pf,
            **seg,
            "vus_pr": round(vus, 4),
            **dl,
        }
        # p50/p95 single-window latency (estimate from score_ms / #windows)
        n_windows = max(1, len(test.points) // max(1, int((cfg.get("detector", {}).get("window_ns", 60_000_000_000) / max(1, interval_ns)))))
        per_window = score_ms / max(1, n_windows)
        rows["p50_window_ms"] = round(per_window, 4)
        rows["p95_window_ms"] = round(per_window * 1.5, 4)
        rows["peak_rss_mb"] = _peak_rss_mb()
        metrics_rows.append(rows)
    return {"machine": name, "metrics": metrics_rows}


def _peak_rss_mb() -> float:
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmHWM"):
                    return float(line.split()[1]) / 1024.0
    except OSError:
        pass
    return 0.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="experiments.run_detection")
    parser.add_argument("--config", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--models", required=True)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--output", required=True)
    parser.add_argument("--root", default=None, help="dataset root (default data/)")
    parser.add_argument("--limit-machines", type=int, default=0,
                        help="SMD: cap the number of machines evaluated (0 = all)")
    args = parser.parse_args(argv)
    cfg = yaml.safe_load(open(args.config))
    result = run_detection(args, cfg)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    # CSV
    rows = []
    if "machines" in result:
        for m in result["machines"]:
            rows.extend(m["metrics"])
    elif "metrics" in result:
        rows = result["metrics"]
    if rows:
        with open(out / "metrics.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    print(f"[run_detection] dataset={args.dataset} models={args.models} -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())