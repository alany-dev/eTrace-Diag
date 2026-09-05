# eTrace-Diag — 异常检测与因果根因定位模型

分布式微服务/主机系统的分层时序异常检测与可解释因果根因定位。

本目录在 `dev_models` 分支承载实现（Python 3.11+，CPU 默认可运行）：

- **Model 1 — 异常检测**：
  - 基准 **Time-RCD**（ICML 2026，Apache-2.0，HF 官方 checkpoint
    `thu-sail-lab/Time-RCD`，零样本泛化 —— 无逐任务训练、无标签，直接对
    (T,C) 窗口打分）。
  - 改进 **Time-RCD-Fuse**（冻结 Time-RCD 主干 + Robust-z 跨通道融合 w=0.3
    + median-k5 中值平滑；SMD 3 机 VUS-PR 0.383 → 0.525，详见
    `docs/research/time-rcd-fuse-report.md`；模块矩阵实测
    `docs/research/time-rcd-module-results.md`）。
  - 联调运行时：`TimeRCDFuseDetector`（`src/alg_models/detection/time_rcd_fuse.py`，
    WS 服务的 /anomaly 端点实机路径，需 `uv sync --extra torch`）；
    仓库自研 numpy 检测器 `StreamingRobustDetector`、`FITSDetector`、
    `EdgeCascadeDetector`（事件环 → FITS 频域趋势环 → 跨尺度一致性门控）
    作为 CPU-only 校准/降级路径与因果输入的事件检测器。
- **Model 2 — TORAI 因果 RCA**：多源（指标 + 日志 + 轨迹）无监督根因定位，
  不依赖服务调用图。`ToraiRCA`（`src/alg_models/causal/torai.py`）：逐模态
  异常严重度 → 细粒度→粗粒度聚合 → GMM 症状聚类 → RCD（Ψ-PC，
  `src/alg_models/causal/psi_pc.py` 原生 numpy 移植）簇内精排 → 按服务排序的
  根因 + 每模态严重度矩阵 + 症状簇。两个变体（数值一致）：
  - `variant="faithful"`：参考逐列 StandardScaler 严重度循环；
  - `variant="fast"`（默认）：向量化严重度，输出与 faithful 完全一致，宽表更快。
  - TORAI-QT 模块改进版与消融模块已移除：全因子消融结论保持原始 TORAI
    管线（robust scaler 单独致 SS Avg@5 0.93→0.59；tail/guided/consensus
    主效应为负），证据与决策见主仓库 `docs/adr/0002-model-trim-scope.md`。
- **交互与联调**：FastAPI HTTP（`score` / `causal` / `feedback` / `incidents`）、
  **WebSocket 服务**（`ws://<host>:9000/anomaly` + `/causal`，与 eBPF 采集器
  的协议 v1 契约，见主仓库 `docs/adr/0003-ws-integration-contract.md`）、
  证据约束解释器（默认模板，LLM 可选且逐句校验）、版本化反馈与冲突保留。
- **采集与分布式**：OTLP / eBPF 采集适配（能力门控，无权限即回放）、
  EdgeAgent（仅 Model 1 + 事件摘要）与 Coordinator（时钟校正 + TORAI 联合分析）。

研究出处、数据许可、评估协议见 `docs/research/`（data-matrix /
evaluation-protocol）。

## 安装与验证

```bash
uv sync --extra dev            # CPU 核心依赖
uv sync --extra torch          # Time-RCD-Fuse 实机路径（time-rcd + HF checkpoint）
uv run pytest -q tests/        # 契约 / 无泄漏 / 缺失质量 / 解释器 / TORAI / 分布式
uv run python -m alg_models.cli detect --config configs/smoke.yaml --input tests/fixtures/host_spike.jsonl --seed 7
uv run python -m alg_models.cli causal --config configs/smoke.yaml --input tests/fixtures/causal_disk_chain.jsonl --top-k 3 --seed 7
uv run uvicorn alg_models.api:app --host 127.0.0.1 --port 8090        # HTTP 面
uv run python -m alg_models.ws_server --host 127.0.0.1 --port 9000    # WS 联调面
```

核心 CPU 路径不安装 GPU/LLM 依赖；`torch`、`llm` 均为可选 extras。Model 2
依赖 `scikit-learn`（GMM/StandardScaler），无 tigramite/lingam。

## 联调契约（与 eBPF 采集器）

- `/anomaly`：接收采集器逐 tick 的 AnomalyFeatures（host/ebpf/top_tasks/
  network/gpu/cgroup 快照），缓冲预热后按 stride 滑窗用 Time-RCD-Fuse 打分，
  返回 `{is_anomaly, type, confidence, indicators}` 驱动采集器 BASE→DEEP。
- `/causal`：接收 DEEP 证据包（per-target 序列 / syscall 热点 / runq 时延 /
  锁竞争 / OOM 事件），映射为 TORAI 多模态输入（实体 = host/proc_<pid>/
  dev_<majmin>），返回结构化 CausalReport 由采集器写入会话 diagnosis.json。
- 完整契约与证据映射：主仓库 `docs/adr/0003-ws-integration-contract.md`、
  `docs/adr/0004-causal-evidence-adaptation.md`、`docs/glossary.md`。
