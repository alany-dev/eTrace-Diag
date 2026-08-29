# Evaluation Protocol

Fixed evaluation protocol for the two reproducible experiment models. All
thresholds, split points, and hyperparameters are frozen in the benchmark
config and traceable to train/validation — test labels never participate in
calibration. Metrics marked "auxiliary" are reported in a separate column and
never replace the primary metric.

## Model 1 — detection

### Primary metrics (per dataset, per detector per seed)

- Point F1 (no point-adjust). Point-adjust F1 (PA-F1) is auxiliary only and
  labelled as such.
- Range/segment Precision, Recall, F1
- VUS-PR (for TSB-AD/mTSBench subsets)
- Average detection delay (in samples/second)
- False alarms per hour
- Parameter count (model size)
- p50 / p95 single-window inference latency (ms, edge reference CPU)
- Peak RSS (MB)

### Detectors compared

`StreamingRobustDetector`, `FITSDetector`, `EdgeCascadeDetector` (this project).

### Experimental protocol

```bash
uv run python -m experiments.run_detection \
    --config configs/benchmark.yaml \
    --dataset smd \
    --models shesd,fits,edge_cascade \
    --seed 7 \
    --output results/smd
```

1. Train/validation split: strictly by time; anomaly segments never cross a
   split. The first 60% of the timeline is train, 20% validation (threshold
   calibration), 20% test. The same split points are used for every detector.
2. Threshold calibration: per-metric median/MAD from train, then threshold
   quantile tuned on the validation split to maximize a held-out range F1
   (not looking at test labels).
3. Each detector is fit once on the train split, then scored on the full
   timeline. The output is a JSON/CSV table with per-window predictions.
4. SMD uses `interpretation_label` for dimension-attribution hit@k (auxiliary
   — not function-level causal ground truth). The plan's `EdgeCascadeDetector`
   metric contributions are evaluated against `interpretation_label` direction
   and rank.

### Contacted SOTA

SMD: OmniAnomaly, Anomaly Transformer, DCdetector, TranAD, ScatterAD, KAN-AD,
MOMENT, Time-RCD — only in offline/server contrast, never in the default edge
path. The protocol explicitly notes each difference in preprocessing, threshold
tuning, and split strategy with the paper's reported numbers; it never restates
test-tuned literature scores.

## Model 2 — TORAI multi-source RCA

### Primary metrics

- **Coarse-grained (service-level)**: AC@1, AC@3, AC@5, Avg@5. The service is
  the prefix before the first `_` in the ranked indicator name, deduplicated
  per list (RCAEval Evaluator semantics). The output rank uses `_A` suffix
  convention: `` split("_")[0] `` extracts the service.
- **Fine-grained (service + fault type)**: AC@1, AC@3, AC@5, Avg@5. The
  indicator is `{service}_{fault_type}`; `"A"` sentinel metric is treated as
  unknown.
- **Per-case latency**: p50 and p95 wall-clock seconds for `analyze_tables`.
- **Peak RSS**: memory usage during analysis.

### Methods compared

- **torai** — full TORAI pipeline: per-modality severity → GMM clustering →
  RCD (Ψ-PC) within-cluster refinement.
- **rcd_only** — Ψ-PC directly on the full metric+log matrix (no clustering=
  CausalRanker ablation).
- **baro** — median/IQR single-source baseline (RCAEval e2e/baro.py).
- **correlation** — Pearson correlation with the anomaly indicator (lower
  bound).

### Experimental protocol

```bash
uv run python -m experiments.run_torai \
    --dataset torai-ob|torai-ss|torai-tt \
    --variant faithful|improved \
    --seeds 7,11,19 \
    --methods torai,rcd_only,baro,correlation
```

1. Data loading: TORAI-format directories under `data/torai/torai-{OB,SS,TT}`.
   The window is ± 10 minutes around `inject_time` (20 minutes total, matching
   RCAEval `--length 20`). The normal side is the tail half of the pre-inject
   segment; the anomalous side is the head half of the post-inject segment.
2. Ground truth is parsed from the directory path: `{service}_{fault}/{run}`.
   The service name is the first component before `_`; the fault type is the
   remaining suffix.
3. Variant `faithful` uses standard scaler, full covariance GMM, kmeans
   discretization, unbounded BIC. Variant `improved` uses standard scaler,
   diag covariance, truncated BIC ≤10, quantile discretization, and a
   native-resolution normal-tail trim of `resample_s` rows (~15 s). The
   plan's `robust` scaler was dropped by user decision 2026-08-29 after
   component isolation showed it alone collapses SS rankings.
4. Avg@5 is the primary aggregate metric. Per-fault breakdowns are reported
   for CPU, MEM, DISK, SOCKET, DELAY, LOSS with the same naming convention
   as the RCAEval paper.
5. Latency budgets: p50 < 10 s per case, p95 < 30 s per case on the reference
   CPU (Xeon Gold 6326, 64 cores, no GPU).

### Missing modalities and abstention

- Missing logs or traces are blind spots: their severity contribution is 0
  and recorded in the report's `limitations`.
- Single-service clusters skip RCD refinement (GMM has only one service per
  cluster) and fall back to severity ordering.
- The normal-window statistics use only the `time < inject_ns` segment; the
  `normal_post_trim` parameter (improved variant) additionally drops the last
  `resample_s` NATIVE-resolution rows (~15 s) of the normal window, before
  the 15 s resample, to remove anomaly-detection-delay contamination.
- The `_A` suffix output convention is inherited from the RCAEval evaluator's
  string-parsing API; it is NOT a semantic claim about the ranking.

## API validation

```bash
uv run uvicorn alg_models.api:app --host 127.0.0.1 --port 8090
curl -sS -X POST http://127.0.0.1:8090/v1/score -H 'content-type: application/json' \
    --data @tests/fixtures/host_spike_request.json
curl -sS -X POST http://127.0.0.1:8090/v1/causal/analyze -H 'content-type: application/json' \
    --data @tests/fixtures/causal_request.json
curl -sS -X POST http://127.0.0.1:8090/v1/feedback -H 'content-type: application/json' \
    --data @tests/fixtures/false_positive_feedback.json
```

- All responses must use the Pydantic contract models.
- Feedback produces a new model version. Old reports are still readable via
  the old version.
- What-if is dry-run only (does not execute kill, rate-limit, or rollback).
- `EvidenceNarrator`: deterministic template backend first; LLM backend only
  when an environment variable is set and a checkpoint available. A report with
  missing evidence IDs or wrong directions must be rejected by the narrator
  (fallback to template). LLM failure must not affect detection or causal
  results.

## Profile & resource budgets

```bash
uv run python -m experiments.profile \
    --config configs/benchmark.yaml \
    --model edge_cascade \
    --input tests/fixtures/host_spike.jsonl \
    --repeat 1000 \
    --output results/profile.json
```

### Budgets (default, overridable by config)

| Metric | Budget | Notes |
|---|---|---|
| Edge p95 single-window inference | ≤ 50 ms | reference CPU |
| Peak RSS | ≤ 200 MB | |
| Steady single-core CPU | ≤ 5% | normal operation |
| Average bandwidth per node | ≤ 16 KB/s | summary-only event reporting |

When a budget is exceeded, the report specifies the gate hit rate, second-ring
trigger rate, and quality degradation — no silent accuracy reduction.

## Test suite

```bash
uv run pytest -q tests/test_schemas.py tests/test_no_leakage.py tests/test_missing_quality.py
```

Coverage:
- Legal/illegal `entity_type`, empty window, duplicate/out-of-order timestamps,
  missing and stale points, non-identifiable effects, feedback conflict
- The test must check structured errors and unchanged model versions, not just
  importability.

## Contingencies

- SWaT/WADI, AIOps 2020, AnoMod, or production cluster traces: if access/
  license fails, Model 1 still runs on SMD/PSM/KPI/NAB/TSB-AD, Model 2 still
  runs on RCAEval + synthetic SCM + local injection. License failure only
  changes the data matrix, never the interface.
- Time-RCD, MOMENT, STAR, ScatterAD, or LLM backend checkpoints/dependencies:
  if unavailable, keep the interface and ablation entry; core
  `StreamingRobustDetector`, FITS, PCMCI+, effect estimation, and template
  narrator must run independently.
- Causal discovery defaults to causal stationarity, Markov property, faithfulness,
  and sufficient sampling rate. On detected hidden confounding, downsampling
  aliasing, non-stationarity, or clock misalignment, the protocol switches to
  LPCMCI/J-PCMCIplus/CD-NOD or outputs `abstain` — an observational score is
  never presented as a verified do-effect.
- Lightweight optimization: conditional computation, shared small models,
  distillation, quantization/ONNX, event summarization — never by stripping
  fine-grained evidence, changing labels, or tuning on test data.