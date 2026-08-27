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

## Model 2 — causal discovery & RCA

### Primary metrics

- **Graph-level**: edge SHD, precision, recall, lag recovery error, edge
  stability (bootstrap frequency across background windows)
- **RCA-level**: root-cause hit@1, hit@3, Mean Reciprocal Rank (MRR), effect
  CI coverage, abstention precision, abstention coverage
- Graph scores and RCA scores are reported in separate columns.

### Methods compared

- Correlation ranking (baseline lower bound)
- GDN (attention-based attribution — explicitly NOT causal)
- PCMCI+ (real PCMCI+ from tigramite when available; built-in ParCorr PCMCI
  lite as fallback)
- LPCMCI / Neural Granger (contrast, only when dependencies/conditions met)
- `CausalGraphRCA` (this project: staged graph builder → PCMCI+ discovery →
  stability bootstrap → effect estimation → rank combination)

### Experimental protocol

```bash
uv run python -m experiments.run_rca \
    --config configs/benchmark.yaml \
    --dataset rcaeval \
    --suite re1 \
    --methods correlation,gdn,pcmci_plus,causal_graph_rca \
    --seed 7 \
    --output results/rcaeval-re1
```

1. Candidates are restricted to the same host, `contains`/`calls`/
   `communicates`/`shares_resource` edges and a finite hop limit. The number
   of pruned candidate edges is reported for audit.
2. Background data is the window around the anomaly ± 2× max lag. The same
   split/background window is used for every method.
3. `tau_max`, `alpha_level`, FDR method, `min_edge_stability`, and rank weights
   are calibrated only on train/validation or synthetic SCM ground truth.
4. On RCAEval, RE1/RE2/RE3 use their ground truth and AC@1/AC@3/Avg@5.
5. AIOps 2020: only after written license obtained; otherwise skip.
6. Controlled injection (DeathStarBench + Chaos Mesh): per service × fault
   type, ≥3 runs, record injection start/end, target, config, clock offset,
   recovery action. The protocol reports the mean and std of all metrics.

### Identifiability and abstention

- When no valid adjustment set exists, data is non-identifiable, or the path
  graph contains only bidirected/unknown edges, `EffectEstimator` returns
  `not_identifiable` and the candidate is down-weighted (not excluded entirely
  but marked as "insufficient evidence").
- When hidden confounding is detected by LPCMCI/FCI, a `bidirected`/`unknown`
  edge mark triggers `evidence_level = "insufficient"`.
- When J-PCMCIplus fails (dependency/data condition not met), the report
  falls back to per-device graphs and explicitly states "not jointly identified"
  — no claimed distributed causal graph.

## API validation

```bash
uv run uvicorn alg_models.api:app --host 127.0.0.1 --port 8090
curl -sS -X POST http://127.0.0.1:8090/v1/score -H 'content-type: application/json' \
    --data @tests/fixtures/host_spike_request.json
curl -sS -X POST http://127.0.0.1:8090/v1/causal/analyze -H 'content-type: application/json' \
    --data @tests/fixtures/causal_request.json
curl -sS -X POST http://127.0.0.1:8090/v1/feedback -H 'content-type: application/json' \
    --data @tests/fixtures/false_positive_feedback.json
curl -sS -X POST http://127.0.0.1:8090/v1/what-if -H 'content-type: application/json' \
    --data @tests/fixtures/what_if_request.json
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