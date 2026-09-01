# Time-RCD Module Matrix + Combination Stage — Measured Results

Zero-shot Time-RCD baseline (`thu-sail-lab/Time-RCD`, Apache-2.0, ICML 2026,
pinned `372bb980426b2f67007311c6f3165ab789c79bef`) on SMD machines
machine-1-1/1-2/1-3. Checkpoint: `best_model/pretrain_checkpoint_best_multi.pth`
(snapshot `0880420070a524efe14d7e163b34dcca90d2be1b`), win_size 5000, batch 1,
CPU. Evaluation protocol per `evaluation-protocol.md` (zero-shot rule):
**VUS-PR is the headline metric** (threshold-free); point/segment F1 at fixed
0.5 threshold (declared prior, calibrated on nothing). Threshold-calibrated
modules use ONLY the SMD per-machine train-file scores, which CONTAIN
anomalies — `calibration_basis: smd-train-contaminated` is recorded per run and
the caveat applies. Test labels never participate in calibration.

Seriality: every run executed strictly one at a time via
`experiments/queue_time_rcd_modules.sh` / `queue_time_rcd_combos.sh`
(plain sequential `run()` calls; queue.log shows one START→DONE pair per
experiment, never two STARTs before a DONE). Nothing was re-run to cherry-pick;
every queue row appears exactly once.

## Module matrix (verbatim from `results/time_rcd/module_matrix.csv`)

| experiment | module | status | machines | mean_point_f1 | mean_seg_f1 | mean_vus_pr | wall_s | threshold_rule | calibration_basis | note |
|---|---|---|---|---|---|---|---|---|---|---|
| autocast-bf16 | base | failed | 0 |  |  |  |  |  |  | OOM-killed (rc=137) during queue run; no scores produced. Deferred: efficiency variants revisited after combination stage. |
| autocast-fp16 | base | failed | 0 |  |  |  |  |  |  | Aborted after ~5h (CPU fp16 emulation no native path); user priority change: combination before quantization. |
| base | base | ok | 3 | 0.305 | 0.7605 | 0.383 | 1208.46 | fixed-0.5 | none |  |
| batch-b4 | base | failed | 0 |  |  |  |  |  |  | OOM-killed (rc=137) during queue run; no scores produced. Deferred: efficiency variants revisited after combination stage. |
| batch-b8 | base | failed | 0 |  |  |  |  |  |  | OOM-killed (rc=137) during queue run; no scores produced. Deferred: efficiency variants revisited after combination stage. |
| cascade-g095 | cascade-g095 | ok | 3 | 0.0914 | 0.651 | 0.2561 | 267.88 | cascade-gate-0.95-train | smd-train-contaminated | window gate on robust-z (q=0.95 of train window-max); non-flagged windows score 0; concatenating non-contiguous windows changes context |
| cascade-g099 | cascade-g099 | ok | 3 | 0.0914 | 0.651 | 0.2561 | 270.94 | cascade-gate-0.99-train | smd-train-contaminated | window gate on robust-z (q=0.99 of train window-max); non-flagged windows score 0; concatenating non-contiguous windows changes context |
| channel-top-k16 | base | ok | 3 | 0.2814 | 0.5235 | 0.3564 | 219.68 | fixed-0.5 | none |  |
| channel-top-k24 | base | ok | 3 | 0.3502 | 0.6485 | 0.3662 | 503.04 | fixed-0.5 | none |  |
| channel-top-k8 | base | ok | 3 | 0.1943 | 0.3412 | 0.1548 | 68.68 | fixed-0.5 | none |  |
| combo-ewma02-fusion03 | combo-ewma02-fusion03 | ok | 3 | 0.3182 | 0.9542 | 0.4984 | 1281.34 | fixed-0.5 | smd-train-contaminated | combo: EWMA a=0.2 then robust-z fusion w=0.3 |
| combo-ewma02-q0995 | combo-ewma02-q0995 | ok | 3 | 0.262 | 0.7879 | 0.4755 | 1985.41 | quantile-0.995-train | smd-train-contaminated | combo: EWMA a=0.2 scores + quantile-0.995 train threshold |
| combo-ewma05-med5 | combo-ewma05-med5 | ok | 3 | 0.3093 | 0.7753 | 0.4645 | 1012.25 | fixed-0.5 | none | combo: EWMA a=0.5 then median-k5 |
| combo-fusion03-med5 | combo-fusion03-med5 | ok | 3 | 0.3158 | 0.8389 | 0.5248 | 1037.88 | fixed-0.5 | smd-train-contaminated | combo: robust-z fusion w=0.3 then median-k5 |
| combo-med5-ewma02 | combo-med5-ewma02 | ok | 3 | 0.3028 | 0.6427 | 0.4808 | 1240.04 | fixed-0.5 | none | combo: median-k5 then EWMA a=0.2 |
| combo-med5-fusion03 | combo-med5-fusion03 | ok | 3 | 0.3145 | 0.893 | 0.4778 | 1135.16 | fixed-0.5 | smd-train-contaminated | combo: median-k5 then robust-z fusion w=0.3 |
| combo-temp20-ewma02 | combo-temp20-ewma02 | ok | 3 | 0.3057 | 0.7 | 0.4757 | 1043.07 | fixed-0.5 | none | combo: temperature T=2.0 then EWMA a=0.2 |
| conformal-0005 | conformal-0005 | ok | 3 | 0.3223 | 0.5423 | 0.383 | 1687.55 | conformal-0.005-train | smd-train-contaminated | simplified W1-ACAS: decay-weighted (tau=500) 0.995 quantile of train scores |
| cusum | cusum | ok | 3 | 0.362 | 0.871 | 0.3621 | 2050.83 | cusum-h | smd-train-contaminated | one-sided CUSUM on raw scores; reset after alarm |
| ewma-a02 | ewma-a02 | ok | 3 | 0.3017 | 0.6965 | 0.4755 | 1009.37 | fixed-0.5 | none | EWMA alpha=0.2 |
| ewma-a05 | ewma-a05 | ok | 3 | 0.3091 | 0.8003 | 0.4513 | 1013.1 | fixed-0.5 | none | EWMA alpha=0.5 |
| fusion-robust-03 | fusion-robust-03 | ok | 3 | 0.31 | 0.8373 | 0.4157 | 1162.36 | fixed-0.5 | smd-train-contaminated | robust-z fusion, w=0.3 |
| fusion-robust-05 | fusion-robust-05 | ok | 3 | 0.3169 | 0.4036 | 0.3832 | 1114.69 | fixed-0.5 | smd-train-contaminated | robust-z fusion, w=0.5 |
| median-k3 | median-k3 | ok | 3 | 0.3136 | 0.7889 | 0.4427 | 1117.12 | fixed-0.5 | none | 3-point median smoothing |
| median-k5 | median-k5 | ok | 3 | 0.312 | 0.7667 | 0.4493 | 1049.04 | fixed-0.5 | none | 5-point median smoothing |
| multiscale | multiscale | ok | 3 | 0.3081 | 0.7768 | 0.386 | 2239.74 | fixed-0.5 | none | win 5000 + 2500 detectors, min-max normalized, averaged |
| overlap-half | overlap-half | ok | 3 | 0.2939 | 0.7742 | 0.3971 | 2551.57 | fixed-0.5 | none | two shifted passes (offset=win/2), averaged where both cover |
| pot-gpd | pot-gpd | ok | 3 | 0.087 | 0.5328 | 0.383 | 1858.09 | pot-gpd-train | smd-train-contaminated | Telemanom-style POT/GPD on EWMA(0.2)-smoothed train scores |
| ptq-int8-dynamic | ptq-int8-dynamic | failed | 0 |  |  |  |  |  |  | Deferred: quantization postponed until after combination stage beats base (user directive 2026-08-31). |
| quantile-0995 | quantile-0995 | ok | 3 | 0.1961 | 0.8071 | 0.383 | 2424.87 | quantile-0.995-train | smd-train-contaminated | threshold = quantile 0.995 of smd train-file scores |
| temp-05 | temp-05 | ok | 3 | 0.305 | 0.7605 | 0.3765 | 1082.92 | fixed-0.5 | none | temperature-scaled logits, T=0.5 |
| temp-20 | temp-20 | ok | 3 | 0.305 | 0.7605 | 0.413 | 1023.31 | fixed-0.5 | none | temperature-scaled logits, T=2.0 |
| unifusion-max | unifusion-max | ok | 3 | 0.1578 | 0.1166 | 0.1671 | 52.74 | fixed-0.5 | none | per-channel uni checkpoint, max fusion across 38 channels |
| unifusion-mean | unifusion-mean | ok | 3 | 0.0668 | 0.42 | 0.3233 | 57.42 | fixed-0.5 | none | per-channel uni checkpoint, mean fusion across 38 channels |

## Headline rules

- VUS-PR is the primary accuracy headline; wall_s is the lightweight headline.
- A module is "feasible" if it runs end-to-end, regardless of direction; a
  module only enters the final model if it beats `base` on the headline.
- No module was selected into the final model here; the combination stage
  below is the candidate list the user picks from.

## Module feasibility findings (delta vs base: VUS 0.383 / point 0.305 / seg 0.7605 / wall 1208 s)

Accuracy direction (VUS-PR):

- `median-k5`: VUS +0.066 / wall −159 s — cheap win, feasible.
- `median-k3`: VUS +0.060 / wall −91 s — feasible.
- `ewma-a02`: VUS +0.093 / point −0.003 / wall −199 s — best single-module VUS gain, feasible.
- `ewma-a05`: VUS +0.068 / seg +0.040 / wall −195 s — feasible.
- `temp-20`: VUS +0.030 / wall −185 s — small win, feasible.
- `fusion-robust-03`: VUS +0.033 / seg +0.077 / wall −46 s — feasible.
- `fusion-robust-05`: VUS +0.000 / seg −0.357 / point +0.012 — null/regression on seg F1, recorded.
- `cusum`: point +0.057 / seg +0.111 but VUS −0.021 / wall +842 s — regression on headline, recorded.
- `quantile-0995`: point −0.109 / VUS +0.000 / wall +1216 s — regression, recorded.
- `pot-gpd`: point −0.218 / seg −0.228 / wall +650 s — regression, recorded.
- `conformal-0005`: point +0.017 / seg −0.218 / VUS +0.000 — null/regression, recorded.
- `overlap-half`: VUS +0.014 / wall +1343 s — marginal, expensive; recorded.
- `multiscale`: VUS +0.003 / wall +1031 s — null, expensive; recorded.
- `unifusion-max/mean`: VUS −0.216 / −0.060 — regression, recorded (per-channel uni loses cross-channel context).
- `cascade-g095/g099`: VUS −0.127 / wall −940 s — 4.5× faster but large accuracy regression; feasible as a gate, not as-is.
- `channel-top-k8/16/24`: point/VUS regression at 8/16, k24 point +0.045 but VUS −0.017 — recorded.

Lightweight direction (wall_s):

- `autocast-bf16`, `batch-b4`, `batch-b8`: failed — OOM-killed (rc=137) under
  host memory pressure; no scores produced. Deferred, not silently dropped.
- `autocast-fp16`: aborted after ~5 h — CPU fp16 has no native path, emulation
  is pathologically slow; aborted by user priority change (combination first).
- `ptq-int8-dynamic`: deferred by user directive 2026-08-31 — quantization is
  considered only after the combination stage beats `base`; not run yet.

## Combination stage (user directive 2026-08-31: combine winners first, quantize later)

7 two-module chains from the accuracy winners, same protocol, strictly serial.
**Every combo beats base on VUS-PR (0.383).**

| combo | point F1 | seg F1 | VUS-PR | wall_s | vs base VUS |
|---|---|---|---|---|---|
| combo-fusion03-med5 | 0.3158 | 0.8389 | 0.5248 | 1037.88 | +0.1418 |
| combo-ewma02-fusion03 | 0.3182 | 0.9542 | 0.4984 | 1281.34 | +0.1154 |
| combo-med5-ewma02 | 0.3028 | 0.6427 | 0.4808 | 1240.04 | +0.0978 |
| combo-med5-fusion03 | 0.3145 | 0.8930 | 0.4778 | 1135.16 | +0.0948 |
| combo-temp20-ewma02 | 0.3057 | 0.7000 | 0.4757 | 1043.07 | +0.0927 |
| combo-ewma02-q0995 | 0.2620 | 0.7879 | 0.4755 | 1985.41 | +0.0925 |
| combo-ewma05-med5 | 0.3093 | 0.7753 | 0.4645 | 1012.25 | +0.0815 |

Notes:

- Best combo: **combo-fusion03-med5** — VUS-PR 0.5248 (+0.142 vs base),
  point F1 0.3158 (+0.011), seg F1 0.8389 (+0.078), wall 1038 s (−170 s). One
  fusion pass costs nothing at scoring time beyond base.
- combo-ewma02-fusion03 has the best seg F1 (0.9542) and point F1 (0.3182) but
  lower VUS than fusion03-med5.
- Fusion combos calibrate on smd-train-contaminated statistics (robust-z from
  train file) — caveat applies; threshold remains fixed 0.5.
- combo-ewma02-q0995 calibrates its threshold on the contaminated train file
  (basis recorded) and is 64% slower (double predict) for no headline gain
  over the fixed-threshold EWMA combo — recorded, not hidden.
- No combo was re-run; each appears exactly once. The user selects the final
  combination from this table; quantization (ptq-int8) remains deferred until
  the selected combination beats base.
