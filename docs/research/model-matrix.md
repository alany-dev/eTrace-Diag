# Model Matrix

Method selection and provenance for the two reproducible experiment models.
Every entry records: year, paper URL, official code URL, available commit/tag,
input/output, supervision assumption, parameter/runtime cost, license,
reproduction command, and known limitations. Method choices are grounded in
papers and official code; external search results are only candidate indexes,
never SOTA claims. A single benchmark's best score is never presented as
universal SOTA.

License review status: `pending` = must review before vendoring/using as a
dependency; `ok` = reviewed, usable; `blocked` = cannot be used, keep only as
an equivalence-preserving external benchmark adapter. Python version noted per
implementation; this project targets Python 3.11.

## Model 1 — edge detection

| Method | Year | Role | Paper | Code | Commit/tag | In/Out | License | Status |
|---|---|---|---|---|---|---|---|---|
| FITS | ICLR 2024 | Edge long-period main branch (frequency-domain complex linear reconstruction) | <https://arxiv.org/abs/2307.03756> | <https://github.com/VEWOXIC/FITS> | t.b.d. at vendoring | windowed multivariate series → per-timestep anomaly score; ~4.5K–10K params, rFFT/low-pass/complex amp-phase interpolation | MIT (verify) | pending |
| S-H-ESD | — | Zero-parameter streaming statistical lower bound | — | <https://github.com/twitter/AnomalyDetection> | t.b.d. | univariate series → anomaly points | Apache-2.0 (verify) | pending |
| OmniAnomaly | KDD 2019 | Model 1 precision/training reference (server/offline only) | <https://dl.acm.org/doi/10.1145/3292500.3330653> | <https://github.com/NetManAIOps/OmniAnomaly> | t.b.d. | multivariate → per-timestep score + variable contribution | verified limitation in repo per year | pending |
| Anomaly Transformer | ICLR 2022 | precision reference (offline) | <https://arxiv.org/abs/2110.02642> | <https://github.com/thuml/Anomaly-Transformer> | t.b.d. | multivariate → score | MIT (verify) | pending |
| DCdetector | KDD 2023 | precision reference (offline) | <https://arxiv.org/abs/2306.03881> | <https://github.com/DAMO-DI-ML/KDD2023-DCdetector> | t.b.d. | multivariate → score | MIT (verify) | pending |
| TranAD | VLDB 2022 | precision reference (offline) | <https://arxiv.org/abs/2202.10050> | <https://github.com/imperial-qore/TranAD> | t.b.d. | multivariate → score | MIT (verify) | pending |
| ScatterAD | NeurIPS 2025 | precision reference (offline) | / | <https://github.com/jk-sounds/ScatterAD> | t.b.d. | multivariate → score | verify | pending |
| KAN-AD | ICML 2025 | precision reference (offline) | / | <https://github.com/qzhou/KAN-AD> | t.b.d. | multivariate → score | verify | pending |
| MOMENT | ICML 2024 | offline teacher / zero-shot transfer (never loaded at edge runtime) | <https://arxiv.org/abs/2402.03885> | <https://github.com/moment-timeseries-foundation-model/moment> | t.b.d. | series → embeddings/scores | MIT (verify) | pending |
| Time-RCD | ICML 2026 | offline teacher / zero-shot per-timestep score contrast | / | <https://github.com/thu-sail-lab/Time-RCD> | t.b.d. | series → per-timestep score | verify | pending |
| STAR | 2025 | state-conditioning reference (state identity / variable identity encoding, conditional adapter, numeric–state matching) | <https://arxiv.org/html/2510.16014v1> | — | — | time series + discrete state → conditioned scores | paper-only | reference |

### Model 1 design decisions

- `StreamingRobustDetector`: per-metric train-period median/MAD, EWMA/POT
  threshold derived only from train/validation; signed robust residual gives
  `up`/`down` and per-metric contribution.
- `FITSDetector`: numpy adapter of the FITS rFFT → low-pass → complex linear
  interpolation → time-domain reconstruction; fixed input shape, patch/window,
  threshold protocol. `Real_FITS`/ONNX is an optional backend only after
  license/dependency confirmation. Third-party test numbers are never reported
  as this project's results.
- `EdgeCascadeDetector` (this project's contribution): cross-band evidence
  fusion + uncertainty-triggered conditional computation — resident event ring
  (median/MAD residual, change points, short-window band energy, missing/stale
  rate, detector confidence) catches interrupts/futex/lock-wait/IO burst; the
  FITS-style frequency trend ring runs only on `uncertain` windows; the
  cross-scale consistency gate requires both rings to agree for confident
  anomaly, otherwise emits `uncertain`/lower severity; state-conditioning branch
  encodes numerical metrics and discrete state separately (STAR-style), never
  missing state as 0 (emits `state_unobserved` limitation instead).

## Model 2 — causal discovery and RCA (TORAI)

| TORAI (Ψ-PC + GMM + RCD) | FSE 2026 | Main causal RCA model (multi-source: metrics + logs + traces, no service-call-graph dependency) | arXiv:2604.13522 (RCAEval) | <https://github.com/phamquiluan/RCAEval> | `RCAEval/e2e/torai.py` + `rcd.py` + patched causal-learn localized-PC | metric/log/trace tables + inject time → service-ranked root causes + per-modality severity + symptom clusters | MIT (verified, LICENSE-CausalLearn/README) | ported (native numpy, py3.11) |
| BARO | FSE 2024 | RCA contrast: median/IQR single-source baseline | <https://dl.acm.org/doi/10.1145/3663529.3663808> | <https://github.com/phamquiluan/baro> | `RCAEval/e2e/baro.py` | series → cause ranking | MIT (verify) | ported |
| CausalRCA | — | RCA contrast: gradient graph + PageRank | <https://arxiv.org/abs/2110.10178> | <https://github.com/AXinx/CausalRCA_code> | t.b.d. | metrics + topology → ranked root causes | (verify) | reference only |
| LLM-TSAD | NeurIPS 2025 | explainer design reference (statistical decomposition, index-aware prompting, LLM temporal localization weakness) | / | <https://github.com/junwoopark92/LLM-TSAD> | t.b.d. | series → natural language | (verify) | reference |

### Model 2 design decisions (TORAI)

- The causal core is **TORAI** (`src/alg_models/causal/torai.py`): per-modality
  anomaly severity (vectorized max-|z|), fine→coarse aggregation (addup for
  metric/traces, highest for logs), GMM symptom clustering with BIC selection,
  and RCD (Ψ-PC) within-cluster refinement to order cluster members. The
  output is service-ranked with `_A` suffix (RCAEval evaluator convention).
- **Ψ-PC** (`src/alg_models/causal/psi_pc.py`) is a native numpy port of RCD's
  chi-square conditional-independence skeleton search over discretized data —
  no causal-learn dependency, runs on Python 3.11. `chisq_ci` is bit-exact vs
  causal-learn (120/120 CI-test cases).
- Missing modalities (no logs/traces) are blind spots: their severity
  contributions are zero and recorded in `limitations`; severity never assumes
  absence == 0.
- Normal-window statistics are fitted only on the pre-inject (`time < inject`)
  segment; post-inject samples never leak into normal statistics.
- Two variants are supported: `faithful` (standard scaler, full covariance,
  kmeans discretization, unbounded BIC — reproduces the paper) and `improved`
  (standard scaler, diag covariance, truncated BIC ≤10, quantile
  discretization, native-resolution normal-tail trim — latency/accuracy
  improvements). The plan's `robust` scaler was dropped by user decision
  2026-08-29: on SS its IQR≈0 fallback inflates sparse log-count z-scores and
  collapses the ranking (Avg@5 0.59 vs faithful 0.93; component isolation
  proved the scaler alone responsible).
- `EffectEstimator` / PCMCI+ / topology-graph priors are removed; the causal
  claim is the TORAI ranking + per-modality severity + symptom clusters, never
  a verified do-effect.

## Interaction / LLM

- `EvidenceNarrator` is a template renderer by default (no LLM). LLM backend
  only on explicit config; input is restricted to structured evidence from
  `CausalReport`; every causal sentence must cite ≥1 edge, metric, time window
  and statistic/intervention evidence; un-cited, non-existent, direction-
  inconsistent or identifiability-exceeding sentences are rejected and fall
  back to the template. Chain-of-thought is never used as evidence or persisted.
- Post-training (`training/explanation_posttrain.py`, not part of this
  deliverable) would optimize only evidence constraints on the report
  generator (LoRA/DPO or constrained RL with schema-validity, evidence-citation
  exactness, report consistency, counterfactual consistency, correct abstention
  rewards; unsupported-claim penalty) — never the causal graph, and never to
  substitute statistical tests with "reasoning traces".

## Convention

- A matrix update MUST accompany any method entering or leaving the
  experiments; the reproduction command must be runnable from a clean env with
  the pinned commit/tag when the implementation is used as a dependency or
  vendored. Unlicensed or unverifiable implementations are referenced as
  external benchmark adapters only, never copied.
## Implementation status (verified runs, 2026-08-27)

Reproduction is against this repo's lock; real backbones/baselines below were
executed — this supersedes the "pending" license/vendoring rows above only for
the items listed.

### Real backbones / contrasts run

| Component | Implementation | Backend | Verified result |
|---|---|---|---|
| Anomaly Transformer | official thuml model code (CUDA→CPU port, `output_attention=True`), this project's train loop + no-adjust metric | torch CPU | SMD 3-machine subset, 2 epochs: point F1 0.243 (no point-adjust), seg F1 0.746 |

### Model 1 detection comparison (SMD: machine-1-1..1-3)

| Model | point F1 (no adjust) | segment F1 |
|---|---|---|
| StreamingRobustDetector | 0.244 | 0.370 |
| FITSDetector | 0.210 | 0.351 |
| EdgeCascadeDetector | 0.116 | 0.160 |
| Anomaly Transformer (official) | 0.243 | 0.746 |

Preprocessing differences recorded (not test-tuned): this project's detectors use
1-hour sliding windows on SMD's 60 s sampling (a 60 s window would hold one
sample); Anomaly Transformer uses `win_size=100` (1 h 40 min) with train-fit
standardization. Literature scores are never restated as this project's results.

### Model 2 RCA — TORAI reproduction (RCAEval torai-ob, derived-from-re2)

`uv run python -m experiments.run_torai --dataset torai-ob --variant faithful --seeds 7,11,19`

Coarse Avg@5 per fault (3 seeds, 90 cases); paper reference = RCAEval README
(torai-ob, original Figshare dataset). Runtime per case (wall clock):

| Metric | faithful | improved | paper (README torai-ob) |
|---|---|---|---|
| CPU | 0.807 | 0.844 | 0.96 |
| MEM | 0.918 | 0.956 | 0.93 |
| DISK | 0.933 | 0.978 | 1.0 |
| SOCKET | 0.807 | 0.830 | 0.93 |
| DELAY | 0.845 | 0.911 | 0.8 |
| LOSS | 0.826 | 0.889 | 0.84 |
| **AVERAGE** | **0.896** | **0.901** | ~0.91 |
| latency p50/p95 (s/case) | 0.96 / 2.06 | 0.27 / 0.55 | — |
| peak RSS (MB) | 218 | 216 | — |

Baselines (faithful, seed 7): rcd_only 0.893, baro 0.656, correlation 0.900.
Derived-from-re2 threshold (AVERAGE ≥ 0.75, same-direction ordering) met:
AVERAGE 0.896, DELAY/LOSS exceed the paper reference. The improved variant
(standard scaler + diag GMM + BIC≤10 + quantile discretization + native
resolution trim) keeps Avg@5 ≥ faithful on this dataset while cutting p95
latency ~73% (2.06 → 0.55 s).


Full three-dataset faithful vs improved (3 seeds, 90 cases each, coarse Avg@5):

| Dataset | faithful avg5 | improved avg5 | faithful p95 (s) | improved p95 (s) |
|---|---|---|---|---|
| torai-ob | 0.896 | 0.901 | 2.06 | 0.55 |
| torai-ss | 0.925 | 0.911 | 2.34 | 0.94 |
| torai-tt | 0.785 | 0.803 | 13.90 | 2.39 |

Recorded honestly (user policy 2026-08-29: improvements are exploratory, no
forced acceptance): improved ≥ faithful on ob/tt, −0.014 on ss; p95 latency
cut 60–83% on all three datasets. Paper reference per fault only exists for
torai-ob (table above); ss/tt reference values not published in the README.

### Blocked

- **OmniAnomaly** official code is TensorFlow 1.x (`tfsnippet`) and cannot run on
  Python 3.11; recorded as blocked — no paper-equivalent VAE adapter fabricated.
- **AIOps 2020** still requires a non-commercial research license; unchanged.
- The authoritative TORAI Figshare dataset is blocked by AWS WAF for direct
  download from this host; the equivalent layout is derived from the local
  RCAEval RE2 parquet snapshot (`experiments/torai_data.py`, manifest records
  `source: derived-from-re2`). Reproduction thresholds for derived data:
  AVERAGE Avg@5 ≥ 0.75 with same-direction ordering.

## Real-data runs (user-provided archives, 2026-08-27)

### RCAEval RE2 (TORAI-derived, 90-case per system)

`uv run python -m experiments.run_torai --dataset torai-ob|torai-ss|torai-tt --variant faithful --seeds 7,11,19`

See the TORAI reproduction table above (per-fault Avg@5, coarse + fine, with
p50/p95 per-case latency recorded in `results/torai/*.json`).

### AIOps 2020 预赛（用户提供 archive，非商业科研许可）

`uv run python -m experiments.aiops2020 --archive data/AIOps挑战赛2020预赛数据.zip --object docker`

docker 故障子集 hit@3≈0.22 / hit@1≈0.09；catalog log_time 与 metric timestamp 是
偏移时钟域，网络类故障 kpi 为空、100+ 号走揭晓机制，均已记录为限制。
