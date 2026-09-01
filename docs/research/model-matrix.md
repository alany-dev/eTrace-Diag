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
| Time-RCD | ICML 2026 | primary Model-1 zero-shot baseline (0-sample generalization; module matrix in `time-rcd-module-results.md`) | <https://arxiv.org/abs/2509.21190> | <https://github.com/thu-sail-lab/Time-RCD> | `372bb980426b2f67007311c6f3165ab789c79bef` (uv.lock) | series → per-timestep score | Apache-2.0 (verified) | ok |
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

Architecture deep-dive (module-by-module, from-zero background):
`torai-architecture.md`; measured metrics (per fault/system/case):
`torai-benchmark-results.md`.

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
| Time-RCD (multi, zero-shot) | official `time_rcd` package + HF checkpoint `pretrain_checkpoint_best_multi` (win 5000, batch 1), no training, no labels | torch CPU | SMD 3-machine subset: point F1 0.305 (no adjust, fixed 0.5 prior), seg F1 0.7605, VUS-PR 0.383 (threshold-free headline) |
| Time-RCD combo-fusion03-med5 (combination stage) | frozen checkpoint + robust-z fusion w=0.3 then median-k5 (numpy post-processing) | torch CPU | SMD 3-machine subset: point F1 0.3158, seg F1 0.8389, VUS-PR 0.5248 (headline +0.142 vs base); calibration basis smd-train-contaminated |

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

### Model 2 RCA — TORAI reproduction (not run: official dataset unavailable)

The TORAI multi-source benchmark is published on Figshare
(DOI 10.6084/m9.figshare.31925976, torai-OB/SS/TT). This host cannot download
it (AWS WAF JS challenge blocks the ndownloader endpoint). Per project policy,
NO derived/fabricated substitute is used: the earlier `derived-from-re2`
re-aggregation of the local RCAEval RE2 parquet was a mistake and has been
removed (`experiments/torai_data.py`, `data/torai/`, `results/torai/`). The
official RCAEval datasets (RE1/RE2/RE3, 735 cases) remain the primary real-data
benchmark; TORAI faithful reproduction on the official torai-* datasets is
pending until the Figshare archive is obtainable.

`uv run python -m experiments.run_torai --dataset torai-ob --variant faithful --seeds 7,11,19`
(requires `data/torai/torai-OB/...` from the official Figshare zip, see
`experiments/download_torai_data.py` for the acquisition procedure).

### TORAI on official RCAeval RE1/RE2/RE3 (direct parquet, cases.parquet GT)

`uv run python -m experiments.run_torai_rcaeval --suite RE1|RE2|RE3 --variant faithful|improved [--logs --traces]`

No derived dataset: each case's `metrics.parquet`/`logs.parquet`/`traces.parquet`
is read directly; ground truth = `cases.parquet` (root_cause_service +
inject_time); window ±10 min (main.py `--length 20`). Coarse service-level
AC@k / Avg@5, RCAEval Evaluator semantics (`split("_")[0]`, `-db` stripped).

| Suite | cases | modalities | faithful Avg@5 (s) | improved Avg@5 (s) |
|---|---|---|---|---|
| RE1 | 375 | metric | 0.866 (373/375, 937 s) | 0.867 (373/375, 208 s) |
| RE2 | 270 | metric+log+trace | 0.814 (270/270, 4632 s) | 0.820 (270/270, 4232 s) |
| RE3 | 90 | metric+log+trace | 0.870 (90/90, 828 s) | 0.874 (90/90, 492 s) |

Notes: 2 RE1 cases have all-constant metrics in the normal window → excluded
("empty severity matrix (no signal)"). improved keeps Avg@5 ≥ faithful on all
suites; RE1 speedup 4.5× (faithful 937 s → improved 208 s). Ψ-PC kmeans
discretization falls back to quantile when samples < bins (short windows the
reference would crash on); empty severity matrices return an empty ranking
instead of raising.

### Blocked

- **OmniAnomaly** official code is TensorFlow 1.x (`tfsnippet`) and cannot run on
  Python 3.11; recorded as blocked — no paper-equivalent VAE adapter fabricated.
- **AIOps 2020** still requires a non-commercial research license; unchanged.
- **TORAI Figshare dataset**: AWS WAF blocks the download from this host; no
  derived/fabricated substitute is created (policy 2026-08-29).

## Real-data runs (user-provided archives, 2026-08-27)

### RCAEval RE1/RE2/RE3 (official parquet, 735 cases)

The official RCAEval real-data benchmark (`data/rca_eval/cases.parquet` + per-case
`metrics.parquet`/`logs.parquet`/`traces.parquet`) is the primary real-data
suite for Model 2 evaluation. TORAI faithful reproduction on the official
torai-* Figshare layout is pending until that archive is obtainable.

### AIOps 2020 预赛（用户提供 archive，非商业科研许可）

`uv run python -m experiments.aiops2020 --archive data/AIOps挑战赛2020预赛数据.zip --object docker`

docker 故障子集 hit@3≈0.22 / hit@1≈0.09；catalog log_time 与 metric timestamp 是
偏移时钟域，网络类故障 kpi 为空、100+ 号走揭晓机制，均已记录为限制。
