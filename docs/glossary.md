# eTrace-Diag 术语表（Glossary）

联调与最终交付中统一使用的术语。符号/缩写按主题分组。

## 采集侧（eBPF）

| 术语 | 含义 |
|---|---|
| BASE 阶段 | 常驻基线采集：主机指标、飞行记录器、异常检测特征，逐 tick 产出 |
| DEEP 阶段 | 异常后的细粒度证据采集：on/off-CPU 画像、syscall 热点、锁竞争、run-queue 延迟、热点文件 I/O |
| PhaseManager | BASE/DEEP 状态机（异常起止、去抖、合并、pre/post 窗口） |
| 会话（session） | 一次采集运行：输出目录含 `etrace.sqlite3`（22 表单文件库）与 summary |
| AnomalyFeatures | 采集器逐 tick 发送给 /anomaly 的宿主+进程+网络/GPU/cgroup 特征快照 |
| CausalContext | 采集器在 DEEP finalize 时发送给 /causal 的证据包（ADR-0004 打包后含本体数据） |
| 飞行记录器 | 内核环形缓冲持续记录近期事件，DEEP 时回放 pre 窗口 |

## 异常检测（Model 1）

| 术语 | 含义 |
|---|---|
| Time-RCD | 基准模型：零样本时序异常检测主干（arXiv:2509.21190，ICML 2026，Apache-2.0，HF checkpoint `thu-sail-lab/Time-RCD`，pin `372bb98…`），无逐任务训练 |
| Robust-z 融合 | Time-RCD-Fuse 模块 1：`z_t = max_c |x−med_c|/(1.4826·MAD_c)`，按 train 段 q99 截断归一，`s_t ← 0.7·s_t + 0.3·ẑ_t` |
| median-k5 | Time-RCD-Fuse 模块 2：`s_t ← median(s_{t−2..t+2})` 中值平滑，抑制孤立尖峰 |
| Time-RCD-Fuse | 改进模型 = 冻结 Time-RCD + Robust-z(w=0.3) + median-k5，SMD 3 机 VUS-PR 0.383→0.525（头条指标） |
| VUS-PR | Volume Under Surface, PR 曲线下体积：零样本检测的无阈值头条指标 |
| EdgeCascadeDetector | 本仓库 numpy 检测器（事件环 + FITS 频域趋势环 + 跨尺度一致性门控），CPU-only，联调中的降级/对照路径 |
| 预热（warmup） | WS 连接后缓冲 BASE 流以估计通道 med/MAD/q99 的阶段，期间不报异常 |

## 因果推断（Model 2）

| 术语 | 含义 |
|---|---|
| TORAI | Multi-Source Root Cause Analysis（RCAEval e2e/torai.py MIT 移植）：逐模态异常严重度 → GMM 症状聚类 → RCD 簇内精排 → 服务级根因 |
| TORAI faithful | 基准变体：逐列 StandardScaler 循环 severity、full GMM、BIC 1..N、kmeans 离散化 |
| TORAI fast | 轻量化加速变体：severity 全向量化（输出与 faithful 完全一致），联调默认 |
| TORAI-QT | 已作废模块改进版（diag GMM / BIC≤10 / quantile 离散化 / normal 尾裁剪）：消融结论保持原始 TORAI，不作为交付变体 |
| Ψ-PC | psi_pc.py 中基于偏相关的 PC 因果发现（RCD 变体），在 GMM 症状簇内重排实体 |
| fine→coarse | TORAI 聚合约定：实体 = 指标名前缀（`_` 前），细粒度指标严重度按实体聚合排序；实体名不得含下划线（`host` / `proc<pid>` / `dev<major>m<minor>`） |
| 盲点语义 | 缺失模态 severity 记 0：没数据 ≠ 没异常 |
| CausalReport | /causal 的结构化响应：incident_id、根因候选（实体+多模态严重度+置信）、症状簇、abstained_reason |

## 联调与工程

| 术语 | 含义 |
|---|---|
| WS 契约 v1 | 采集器↔模型消息协议：/anomaly 与 /causal 两端点 JSON 行（ADR-0003） |
| diagnosis.json | 采集端会话目录中的最终结构化诊断文件（CausalReport 原样落盘） |
| 轻量注入 | 赛题要求.md §46-49 四个场景的缩减版：stress-ng CPU / fio randrw / stress-ng vm / stress-ng mutex，时长与负载下调，用于 WSL2 本机联调 |
| subtree 合并 | dev_models 以 `--prefix=models` 并入 main，保留完整模型历史（ADR-0001） |
