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

## Model 2 — causal discovery and RCA

| Method | Year | Role | Paper | Code | Commit/tag | In/Out | License | Status |
|---|---|---|---|---|---|---|---|---|
| PCMCI+ (Tigramite) | NeurIPS 2020 | Main causal-discovery backbone; default `ParCorr` CI test + Benjamini–Hochberg FDR | <https://arxiv.org/abs/2010.01740> | <https://github.com/jakobrunge/tigramite> + docs <https://jakobrunge.github.io/tigramite/> | t.b.d. | multivariate time series → lagged+contemporaneous directed graph edges with statistic/p-value/CI | (verify; tigramite is BSD-3-style, confirm) | pending |
| LPCMCI | NeurIPS 2019 | latent-confounding controls | <https://arxiv.org/abs/1905.09808> | same repo | — | series → PAG with bidirected/unknown marks | same | pending |
| J-PCMCIplus | 2023 | multi-device/multi-environment context | <https://arxiv.org/abs/2305.04852> | same repo | — | series per environment → joint graph | same | pending |
| Neural Granger | NeurIPS 2019 | nonlinearity contrast only | <https://arxiv.org/abs/1802.05842> | <https://github.com/iancovert/Neural-GC> | t.b.d. | series → lagged dependency weights | MIT (verify) | pending |
| DyNOTEARS | NeurIPS 2020 | contrast only | <https://arxiv.org/abs/2006.15998> | official | t.b.d. | series → DAG | (verify) | pending |
| GDN | AAAI 2021 | attribution contrast; learned dependency/attention is NOT a causal edge | <https://arxiv.org/abs/2101.10071> | <https://github.com/d-ailin/GDN> | t.b.d. | multivariate → anomaly attribution | MIT plus data license note (verify) | pending |
| CausalRCA | — | RCA contrast: gradient graph + PageRank | <https://arxiv.org/abs/2110.10178> | <https://github.com/AXinx/CausalRCA_code> | t.b.d. | metrics + topology → ranked root causes | (verify) | pending |
| InterFusion | KDD 2021 | hierarchical anomaly contrast | <https://dl.acm.org/doi/10.1145/3447548.3467227> | <https://github.com/zhhlee/InterFusion> | t.b.d. | series → hierarchical score | (verify) | pending |
| MicroRCA | OSDI 2019 | microservice RCA contrast | <https://www.usenix.org/conference/osdi19/presentation/gan> | <https://github.com/elastisys/MicroRCA> | t.b.d. | app metric graph → cause candidate | (verify) | pending |
| BARO | FSE 2024 | RCA contrast: change-point + ranking | <https://dl.acm.org/doi/10.1145/3663529.3663808> | <https://github.com/phamquiluan/baro> | t.b.d. | series → cause ranking | (verify) | pending |
| LLM-TSAD | NeurIPS 2025 | explainer design reference (statistical decomposition, index-aware prompting, LLM temporal localization weakness) | / | <https://github.com/junwoopark92/LLM-TSAD> | t.b.d. | series → natural language | (verify) | pending |
| OpenRCA | ICLR 2025 | tool-augmented RCA-agent interaction protocol contrast | / | <https://github.com/microsoft/OpenRCA> | t.b.d. | metrics/logs → agent reasoning | MIT (verify) | pending |

### Model 2 design decisions

- PCMCI+ edges, lags, p-values and confidence intervals are the causal-evidence
  interface. They remain subject to standard time-series causal assumptions:
  causal stationarity, Markov property, faithfulness, sufficient sampling rate.
  On detected hidden confounding / downsampling aliasing / non-stationarity /
  clock misalignment → LPCMCI / J-PCMCIplus / CD-NOD contrast or output
  `abstain`; an observational score is never claimed as a verified do-effect.
- Stability bootstrap: resample background windows, record edge direction/lag
  frequency; edges below `min_edge_stability` never enter the strong-evidence
  path.
- Bayesian/graph-machine-learning attention is attribution contrast only —
  never named "causal" directly.
- `EffectEstimator`: `E[Y_desc | do(X=x_high)] − E[Y_desc | do(X=x_baseline)]`
  via Tigramite causal effects or equivalent g-computation, with bootstrap CI.
  No valid adjustment set / non-identifiable data / bidirected or unknown path →
  `not_identifiable`, candidate down-weighted, no pseudo-precise causal claim.
- Function-level localization requires time-aligned profile stack/sample with a
  `function` node; without reliable stack/trace identity, function edges are
  `weak` and reported as "suspect scope", never final root cause.
- Ranking is a configurable linear combination (weights calibrated only on
  train/validation/synthetic):
  `rank = w_detector*detector_contrib + w_ancestor*ancestor_score +
  w_temporal*temporal_order + w_stability*edge_stability +
  w_effect*effect_size − w_confounding*confounding_penalty`.
  Pearson/PCC ranking is kept as a separate lower-bound column.

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
| PCMCI+ | tigramite 5.2.10.1 official (candidate-restricted via `link_assumptions`) | `tigramite-pcmciplus` | runs; stationary chain recovered at lags 3/2/2; non-stationary (level-shift) data triggers conservative fallback + limitation |
| GDN | real torch GDN (sensor embedding → learned attention adjacency → GAT forecast; PageRank + deviation attribution) | torch CPU | top-1 = noisiest DOWNSTREAM symptom (latency), NOT root — attention is not causal, as designed |
| Neural Granger | 1-hidden MLP lagged regression, l1 Granger scores | torch CPU | hit@1=1, dense graph (SHD 23) |
| DyNOTEARS | NOTEARS + lagged coefficients | torch CPU | hit@1=1, SHD 16 |
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

### Model 2 RCA comparison (synthetic SCM; RCAEval real data → HF-blocked, documented substitution)

| Method | hit@1 | hit@3 | MRR | edge SHD | lag err |
|---|---|---|---|---|---|
| correlation (lower bound) | 0 | 1 | 0.5 | 3 | — |
| GDN (attention, not causal) | 0 | 1 | 0.5 | 3 | — |
| Neural Granger | 1 | 1 | 1.0 | 23 | 1.67 |
| DyNOTEARS | 1 | 1 | 1.0 | 16 | 1.5 |
| PCMCI+ (real tigramite) | 1 | 1 | 1.0 | 122 | 0.0 |
| CausalGraphRCA (this project) | 1 | 1 | 1.0 | **2** | 0.0 |

Graph scores and RCA scores reported in separate columns (see
evaluation-protocol.md). `CausalGraphRCA` attains the cleanest graph (SHD 2) on
the non-stationary fixture via the shift guard + candidate restriction +
stability bootstrap; raw tigramite still finds top-1 (ancestor coverage) but
over-connects at every lag under the level shift.

### Blocked

- **OmniAnomaly** official code is TensorFlow 1.x (`tfsnippet`) and cannot run on
  Python 3.11; recorded as blocked — no paper-equivalent VAE adapter fabricated.
- **RCAEval** real data (TO-RAI, 3.4 GB on Hugging Face) is not reachable from
  this network (`huggingface.co` times out); the runner substitutes the
  deterministic synthetic SCM and records the substitution in `results`.
- **AIOps 2020** still requires a non-commercial research license; unchanged.

## Real-data runs (user-provided archives, 2026-08-27)

### RCAEval RE1 (真实 735-case 数据，服务级聚合)

`uv run python -m experiments.rcaeval --data data/rca_eval --suite RE1 --limit 20`

| System | CausalGraphRCA AC@1 / AC@3 / Avg@5 | 相关基线 AC@1 / AC@3 / Avg@5 |
|---|---|---|
| RE1-OB (Online Boutique) | 0.55 / 0.65 / 0.644 | 0.75 / 1.0 / 0.875 |
| RE1-SS (Sock Shop) | 0.35 / 0.65 / 0.562 | 1.0 / 1.0 / 1.0 |
| RE1-TT (TrainTicket) | 0.0 / 0.4 / 0.199 | 0.0 / 0.0 / 0.0 |

TrainTicket 两类方法皆 0%（root_cause_service 命名与指标列前缀不一致、故障非明显
电平漂移），为真实困难信号，未做调优掩盖。

### AIOps 2020 预赛（用户提供 archive，非商业科研许可）

`uv run python -m experiments.aiops2020 --archive data/AIOps挑战赛2020预赛数据.zip --object docker`

docker 故障子集 hit@3≈0.22 / hit@1≈0.09；catalog log_time 与 metric timestamp 是
偏移时钟域，网络类故障 kpi 为空、100+ 号走揭晓机制，均已记录为限制。
