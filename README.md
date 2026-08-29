# eTrace-Diag

分布式微服务/主机系统的分层时序异常检测与可解释因果根因定位。

本项目在 `dev_models` 分支承载完整实现（Python 3.11，CPU 默认可运行）：

- **Model 1 — 边缘检测**：`StreamingRobustDetector`（median/MAD + EWMA/POT 下界）、
  `FITSDetector`（频域 rFFT/低通/复线性插值重建）、`EdgeCascadeDetector`（事件环 →
  不确定性门控 → FITS 频域趋势环 → 跨尺度一致性门控 → 状态条件分支，本项目创新）。
- **Model 2 — TORAI 因果 RCA**：多源（指标 + 日志 + 轨迹）无监督根因定位，不依赖
  服务调用图。`ToraiRCA`（`src/alg_models/causal/torai.py`）：逐模态异常严重度 →
  细粒度→粗粒度聚合 → GMM 症状聚类 → RCD（Ψ-PC，`src/alg_models/causal/psi_pc.py`
  原生 numpy 移植）簇内精排 → 按服务排序的根因 + 每模态严重度矩阵 + 症状簇。
  faithful/improved 两变体（improved = diag GMM / BIC 截断 / quantile 离散化 /
  正常尾裁剪，scaler 保持 standard）——改进变体在保持 Avg@5 不降的前提下降低
  p95 延迟 ≥30%。
- **交互闭环**：FastAPI（score / causal / feedback / incidents）、
  证据约束解释器（默认模板，LLM 可选且逐句校验）、版本化反馈与冲突保留。
- **采集与分布式**：OTLP / eBPF 采集适配（能力门控，无权限即回放）、
  EdgeAgent（仅 Model 1 + 事件摘要）与 Coordinator（时钟校正 + TORAI 联合分析）。
- **对照基线**：TORAI（faithful 复现）、rcd_only（CausalRanker 消融）、BARO
  （median/IQR 单源）、correlation（Pearson 下界）、Anomaly Transformer（真实运行）。

研究出处、数据许可、评估协议见 `docs/research/`（model-matrix / data-matrix /
evaluation-protocol）。

TORAI 复现：`experiments/run_torai.py --dataset torai-ob --variant faithful --seeds 7,11,19`
（数据由本地 RCAEval RE2 快照按 TORAI §3.1 派生，见 `experiments/torai_data.py`；
Figshare 官方数据被 AWS WAF 拦截，记录在 `data/torai/build_manifest.json`）。

## 安装与验证

```bash
uv sync --extra dev            # CPU 核心依赖
uv run pytest -q tests/        # 契约 / 无泄漏 / 缺失质量 / 解释器 / TORAI / 分布式
uv run python -m alg_models.cli detect --config configs/smoke.yaml --input tests/fixtures/host_spike.jsonl --seed 7
uv run python -m alg_models.cli causal --config configs/smoke.yaml --input tests/fixtures/causal_disk_chain.jsonl --top-k 3 --seed 7
uv run uvicorn alg_models.api:app --host 127.0.0.1 --port 8090
```

核心 CPU 路径不安装 GPU/LLM 依赖；`torch`、`llm` 均为可选 extras。Model 2 依赖
`scikit-learn`（GMM/KBinsDiscretizer），无 tigramite/lingam。
