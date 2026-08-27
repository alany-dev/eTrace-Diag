# Data Matrix

Provenance, licensing, split policy, and usage for every dataset referenced by
the two experiment models. Data connectors and download scripts only keep a
manifest (name, version, checksum); large datasets are never committed to the
repo. Access/license failures only change the data matrix, never the
interfaces.

## Model 1 (detection) — benchmark order

| Dataset | Source | Content | Labels | Use | License/access | Status |
|---|---|---|---|---|---|---|
| SMD | OmniAnomaly official `ServerMachineDataset` | 28 servers, 38 dims, server CPU/mem/disk/network | per-point + `interpretation_label` | host-scenario primary; dimension-attribution hit@k via `interpretation_label` (NOT function-level ground truth) | OmniAnomaly MIT (data redistributed in repo; verify) | pending |
| PSM | eBay | multivariate server metrics | per-point | multivariate server supplement | (verify) | pending |
| KPI | KPI AD Challenge | sparse streaming anomaly | per-point | sparse streaming anomaly | (verify) | pending |
| NAB | Numenta | AWS host streams | labeled anomaly windows | online latency / false-alarm eval; standard / reward-low-FP / reward-low-FN profiles | BSD-3 (verify) | pending |
| TSB-AD | <https://github.com/TheDatumOrg/TSB-AD> | many univariate/multivariate series | point + range | horizontal reproduction subset containing server/multivariate series | (verify) | pending |
| mTSBench | <https://plan-lab.github.io/mtsbench> | multivariate series collection | point | horizontal reproduction subset | (verify) | pending |

Range metrics (VUS-PR etc.) are used for interval-aware evaluation on
TSB-AD/mTSBench subsets and never substitute host-oriented data.

## Model 2 (RCA) — benchmark order

| Dataset | Source | Content | Labels | Use | License/access | Status |
|---|---|---|---|---|---|---|
| RCAEval | <https://github.com/phamquiluan/RCAEval> | 9 datasets, 735 failure cases, 11 fault classes, 15 reproducible RCA baselines (paper+README checked) | RE1 metric-only, RE2 metric+log/trace, RE3 code-level faults | primary; reuse its readers and AC@k; do not alter ground truth | (verify) | pending |
| AIOps Challenge 2020 | <https://github.com/NetManAIOps/AIOps-Challenge-2020-Data> | microservice metric/trace failure data | incident root cause | only after non-commercial research license; otherwise record in matrix and skip | non-commercial research | blocked-until-license |
| AnoMod | <https://arxiv.org/html/2601.22881v1>; Zenodo DOI `10.5281/zenodo.18342898` | multi-modal: metrics / traces / code coverage / API response | anomaly + root cause | 2026 multi-modal supplement; skip if data/license unavailable (does not block RCAEval) | verify | pending |
| DeathStarBench / Online Boutique / Sock Shop / TrainTicket + Chaos Mesh / ChaosStarBench | <https://github.com/delimitrou/DeathStarBench> | controlled multi-device injected faults | injection ground truth (start/end, target service/container/pid, config, clock offset, recovery action) | controlled end-to-end; ≥3 runs per service × fault type; priority: CPU, memory, disk, network delay/loss, socket/lock | (verify) | pending |

## Contracted causal chain (this project)

`tests/fixtures/causal_disk_chain.jsonl`: deterministic SCM replay —
`host.disk.io_wait` controlled root cause → `process.io_wait` →
`thread.off_cpu` → `service.request_latency` with known lags; one synchronous
but non-root CPU metric is included as a confounder trap. Used for the Model 2
smoke test and effect-sign / identifiability checks.

## Host detection fixture

`tests/fixtures/host_spike.jsonl`: deterministic replay of normal
CPU/memory/disk/network segments followed by CPU-utilization rise and disk
IO-wait rise. Used for Model 1 smoke, all-detector comparison, and feedback
update.

## Split and calibration policy

- Data is always split strictly by time; anomaly segments never cross a split.
- Thresholds, `tau_max`, FDR `alpha`, and rank weights are calibrated ONLY on
  train/validation or synthetic ground truth — test labels never participate.
- License failures change only the matrix and skip the dataset; the core
  `StreamingRobustDetector`, FITS, PCMCI+, effect estimation and template
  narrator must run independently of any blocked dataset.

## Manifest convention

Every dataset consumed by an experiment is recorded with: exact source URL,
version/tag/date, SHA-256 of the downloaded archive, license text location,
reproduction command, and the specific subset used. A checksum mismatch or
missing license note blocks the experiment and is reported, not silently
worked around.