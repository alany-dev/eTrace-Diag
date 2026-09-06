# ADR-0002: 模型分支精简范围（只保留基准与选定改进模型）

- 状态：已采纳（2026-09-05）

## 背景

`dev_models` 承载完整算法演进史：多代检测器、TORAI 多变体、模块消融矩阵、
多数据集基准与配套文档。最终交付只保留两个方向上的基准 + 选定改进：

- 异常检测：基准 **Time-RCD**（冻结 HF checkpoint 零样本），改进 **Time-RCD-Fuse**（Robust-z 跨通道融合 w=0.3 + median-k5 中值平滑，VUS-PR 0.383 → 0.525）。
- 因果推断：基准 **TORAI faithful** + **TORAI 轻量化加速**（向量化 severity，输出与 faithful 完全一致）。**TORAI-QT 模块改进版作废**：全因子消融（commit 858ba3a）结论保持原始 TORAI，robust scaler 单独导致 Avg@5 0.93→0.59（`torai-architecture.md` §5.1），tail/guided/consensus 模块主效应为负（`torai-benchmark-results.md` 否决表）。

## 决策

1. **归档 = 删除**：所有历史对比文件直接从工作树删除，靠 `dev_models` git 历史保留（用户裁决：不保留树内 archive/）。模块否决证据先摘录进本 ADR 再删除文档。
2. **保留面**：
   - `src/`：全部保留（detection 各模块是 Fuse/EdgeCascade 组件；`causal/torai.py` 重做为 `variant: faithful|fast` 双变体，见 ADR-0003）。
   - `experiments/`：仅保留 `make_fixtures.py`、`baselines/time_rcd.py`（Time-RCD 基准 + Fuse 组合矩阵唯一运行器）。删除 run_detection.py、run_torai*.py、torai_ablation_matrix.py、torai_aggregate.py、aiops2020.py、profile.py、download_*.py、queue_*.sh、baselines/{anomaly_transformer,time_rcd_matrix,plot_*}.py。
   - `configs/`：仅保留 `smoke.yaml`（torai 段改为双变体字段）；删除 `benchmark.yaml`。
   - `tests/`：删除 `test_ablation_matrix.py`；`test_torai.py` 更新为双变体 + parity 断言。
   - `docs/research/`：保留 `time-rcd-fuse-report.md`、`time-rcd-module-results.md`、`evaluation-protocol.md`、`data-matrix.md`（数据许可/归属声明）；删除 `model-matrix.md`、`torai-architecture.md`、`torai-benchmark-results.md`、`torai-rca-report.md` 及其 assets。
   - `models/README.md` 重写，去除指向已删文档的链接与 QT/消融描述。

## 后果

- 最终交付物不含死代码与历史结论；所有被删内容经 `git show <sha>:<path>` 可完整找回。
- `data-matrix.md` 保留原因：SMD、AIOps 2020、RCAEval 数据许可与出处声明，删除会丢失合规归属。
