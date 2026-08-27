# eTrace-Diag

分布式微服务/主机系统的分层时序异常检测与可解释因果根因定位。

本项目在 `dev_models` 分支承载完整实现（Python 3.11，CPU 默认可运行）：

- **Model 1 — 边缘检测**：`StreamingRobustDetector`（median/MAD + EWMA/POT 下界）、
  `FITSDetector`（频域 rFFT/低通/复线性插值重建）、`EdgeCascadeDetector`（事件环 →
  不确定性门控 → FITS 频域趋势环 → 跨尺度一致性门控 → 状态条件分支，本项目创新）。
- **Model 2 — 因果 RCA**：`TemporalGraphBuilder` 拓扑候选图 → PCMCI+（tigramite 官方实现，
  非平稳自动回退保守后端）→ 稳定性 bootstrap → g-computation 效应估计 →
  配置化线性组合排序 → `CausalReport` 证据链。
- **交互闭环**：FastAPI（score / causal / feedback / what-if dry-run / incidents）、
  证据约束解释器（默认模板，LLM 可选且逐句校验）、版本化反馈与冲突保留。
- **采集与分布式**：OTLP / eBPF 采集适配（能力门控，无权限即回放）、
  EdgeAgent（仅 Model 1 + 事件摘要）与 Coordinator（时钟校正 + 联合分析）。
- **对照基线**：GDN、Neural Granger、DyNOTEARS、Anomaly Transformer（真实运行）。

研究出处、数据许可、评估协议见 `docs/research/`（model-matrix / data-matrix /
evaluation-protocol）。

## 安装与验证

```bash
uv sync --extra dev            # CPU 核心依赖
uv run pytest -q tests/        # 契约 / 无泄漏 / 缺失质量 / 解释器 / 分布式
uv run python -m alg_models.cli detect --config configs/smoke.yaml --input tests/fixtures/host_spike.jsonl --seed 7
uv run python -m alg_models.cli causal --config configs/smoke.yaml --input tests/fixtures/causal_disk_chain.jsonl --top-k 3 --seed 7
uv run uvicorn alg_models.api:app --host 127.0.0.1 --port 8090
```

核心 CPU 路径不安装 GPU/LLM 依赖；`causal`（tigramite）、`torch`、`llm` 均为可选
extras。