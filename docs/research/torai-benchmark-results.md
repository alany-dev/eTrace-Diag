# TORAI 基准版（faithful）与改进版（improved）实验指标详录

> 数据来源：官方 RCAeval RE1/RE2/RE3（`data/rcaeval` parquet + `cases.parquet`
> 真值）与 AIOps Challenge 2020 预赛（用户提供 archive）。所有数字由
> `experiments/run_torai_rcaeval.py` / `experiments/run_torai_aiops.py` 实测，
> seed=7，不依赖服务调用图。粗粒度服务级 AC@k / Avg@5，评估语义与 RCAEval
> `Evaluator` 一致：服务 = `split("_")[0].replace("-db","")` 去重，
> `Avg@5 = (AC@1 + AC@3 + AC@5) / 3`。
> 架构与逐项变体差异解释见 `docs/research/torai-architecture.md`。
> 逐案例明细（每个 case 的 root/top3/rank/hit）见
> `results/rcaeval/{RE1,RE2,RE3}-{faithful,improved}-cases.json`。

---

## 1. 实验环境

| 项 | 值 |
|---|---|
| CPU | Intel Xeon Gold 6326（64 核），无 GPU |
| Python / 依赖 | 3.11；numpy、pandas 3.0.5、scikit-learn 1.9.0、scipy 1.17.1 |
| 指标窗口 | inject_time ± 10 min（RCAEval main.py `--length 20`） |
| 重采样 | metric 1 s → 15 s（`iloc[::15]`） |
| 真值 | `cases.parquet` 的 `root_cause_service` + `inject_time` |
| 变体差异 | 见 `torai-architecture.md` §5（improved = diag GMM + BIC≤10 + quantile 离散化 + normal 尾裁剪；scaler 均 standard） |

---

## 2. 官方 RCAeval RE1（375 案例，metric-only）

### 2.1 汇总

| 变体 | 可评案例 | ac@1 | ac@3 | ac@5 | avg@5 | 总耗时 |
|---|---|---|---|---|---|---|
| faithful | 373 / 375 | 0.692 | 0.930 | 0.976 | **0.866** | 840 s |
| improved | 373 / 375 | 0.692 | 0.933 | 0.976 | **0.867** | **252 s（3.3× 提速）** |

被排除案例（如实记录，不计入分母）：

| case | root | 原因 |
|---|---|---|
| re1ob_currencyservice_loss_1 | currencyservice | empty severity matrix（normal 窗 59/60 指标列全常数，无信号） |
| re1ob_productcatalogservice_cpu_3 | productcatalogservice | 同上 |

### 2.2 分故障（by fault）

| 故障 | n | ac@1 | ac@3 | ac@5 | avg@5 |
|---|---|---|---|---|---|
| cpu | 74 | 0.770 | 1.000 | 1.000 | 0.923 |
| mem | 75 | 0.853 | 0.987 | 0.987 | 0.942 |
| delay | 75 | 0.760 | 0.960 | 0.987 | 0.902 |
| disk | 75 | 0.667 | 0.987 | 1.000 | 0.884 |
| loss | 74 | 0.405 | 0.716 | 0.905 | 0.676 |

improved 差异仅：disk ac@3 0.973、loss n=73 且 avg@5 0.685——其余格与
faithful 逐格一致。

### 2.3 分系统（by system）

| 系统 | n | ac@1 | ac@3 | ac@5 | avg@5 |
|---|---|---|---|---|---|
| ob（Online Boutique） | 123 | 0.659 | 0.927 | 0.976 | 0.854 |
| ss（Sock Shop） | 125 | 0.864 | 0.968 | 0.992 | 0.941 |
| tt（Train Ticket） | 125 | 0.552 | 0.896 | 0.960 | 0.803 |

improved 差异仅：ob ac@1 0.650、ss n=124 且 avg@5 0.946、ob ac@3 0.935；
tt 完全一致。

---

## 3. 官方 RCAeval RE2（270 案例，metric+log+trace 全模态）

### 3.1 汇总

| 变体 | 可评案例 | ac@1 | ac@3 | ac@5 | avg@5 | 总耗时 |
|---|---|---|---|---|---|---|
| faithful | 270 / 270 | 0.693 | 0.844 | 0.904 | **0.814** | 5159 s |
| improved | 270 / 270 | 0.696 | 0.852 | 0.911 | **0.820** | **3803 s** |

无失败案例。modalities = metric+log+trace（OB/TT 有轨迹；SS 无轨迹 = 盲点，
severity 归 0 语义，见架构文档 §1.3）。

### 3.2 分故障（by fault）

| 故障 | faithful avg@5 | improved avg@5 | faithful ac@1 | improved ac@1 |
|---|---|---|---|---|
| cpu | 0.837 | 0.837 | 0.711 | 0.689 |
| mem | 0.867 | 0.867 | 0.822 | 0.822 |
| delay | 0.778 | 0.800 | 0.644 | 0.667 |
| disk | 0.881 | 0.889 | 0.822 | 0.822 |
| loss | 0.763 | 0.741 | 0.556 | 0.489 |
| socket | 0.756 | 0.785 | 0.600 | 0.689 |

每故障 n=45。improved 在 delay/socket 上提升（+0.022/+0.030），loss 上
回落（-0.022）。

### 3.3 分系统（by system）

| 系统 | faithful avg@5 | improved avg@5 | faithful ac@1 | improved ac@1 |
|---|---|---|---|---|
| ob | 0.907 | 0.911 | 0.789 | 0.800 |
| ss | 0.941 | 0.926 | 0.878 | 0.833 |
| tt | 0.593 | 0.622 | 0.411 | 0.456 |

每系统 n=90。tt 显著难（盲点：轨迹模态缺失 + 根因信号弱），improved 三系统
ac@1 两升一降、avg@5 总体持平略升。

---

## 4. 官方 RCAeval RE3（90 案例，metric+log+trace 全模态）

### 4.1 汇总

| 变体 | 可评案例 | ac@1 | ac@3 | ac@5 | avg@5 | 总耗时 |
|---|---|---|---|---|---|---|
| faithful | 90 / 90 | 0.667 | 0.956 | 0.989 | **0.870** | 462 s |
| improved | 90 / 90 | 0.667 | 0.967 | 0.989 | **0.874** | 613 s |

### 4.2 分故障（by fault，代码级故障 f1..f5）

| 故障 | n | faithful avg@5 | improved avg@5 | faithful ac@1 |
|---|---|---|---|---|
| f1 | 26 | 0.897 | 0.897 | 0.731 |
| f2 | 13 | 0.974 | 0.974 | 0.923 |
| f3 | 26 | 0.808 | 0.821 | 0.577 |
| f4 | 19 | 0.842 | 0.842 | 0.526 |
| f5 | 6 | 0.889 | 0.889 | 0.667 |

improved 仅 f3 提升（ac@3 0.923→0.962，avg@5 0.808→0.821），其余一致。

### 4.3 分系统（by system）

| 系统 | n | faithful avg@5 | improved avg@5 | faithful ac@1 |
|---|---|---|---|---|
| ob | 30 | 0.833 | 0.833 | 0.600 |
| ss | 30 | 0.789 | 0.800 | 0.433 |
| tt | 30 | 0.989 | 0.989 | 0.967 |

improved 仅 ss ac@3 0.933→0.967（avg@5 0.789→0.800），其余一致。

---

## 5. AIOps Challenge 2020（预赛，24 案例可评 / 81 目录）

### 5.1 汇总（`--max-cols 50`）

| 变体 | 可评案例 | ac@1 | ac@3 | ac@5 | avg@5 | 总耗时 |
|---|---|---|---|---|---|---|
| faithful | 24 | 0.417 | 0.625 | 0.750 | **0.597** | 456 s |
| improved | 24 | 0.417 | 0.625 | 0.750 | **0.597** | **282 s（1.6× 提速）** |

### 5.2 分对象（by object）

| 对象 | 可评例数 | ac@1 | ac@3 | ac@5 | avg@5 |
|---|---|---|---|---|---|
| db | 6 | 1.000 | 1.000 | 1.000 | **1.000** |
| docker | 13 | 0.077 | 0.308 | 0.769 | 0.385 |
| os | 5 | 0.200 | 0.600 | 0.600 | 0.467 |

faithful 与 improved 逐格一致（仅耗时不同）。db 的 KPI 强信号（会话连接数
阶跃）让 Ψ-PC 精确命中；docker 的 network delay/loss 类故障无 KPI 指示列
时严重度信噪比低。

### 5.3 不可评案例分布（81 目录）

| reason | 数量 |
|---|---|
| 当日 zip 缺失（catalog 日期无对应日数据） | 27 |
| 故障时刻在每日 6h 指标窗口外 | 9 |
| 其他（no docker metrics 等） | 21 |

注：每日 zip 仅含本地 00:00–06:00 的 6 小时窗口；os/db 全展开 598–1122 列
导致 RCD 组合膨胀，适配器 `--max-cols` 按方差截断到 50 列后全部可评。

---

## 6. 变体对比总结

| 数据集 | faithful avg@5 | improved avg@5 | Δ | faithful 耗时 | improved 耗时 | 提速 |
|---|---|---|---|---|---|---|
| RCAeval RE1 | 0.866 | 0.867 | +0.001 | 840 s | 252 s | 3.3× |
| RCAeval RE2 | 0.814 | 0.820 | +0.006 | 5159 s | 3803 s | 1.36× |
| RCAeval RE3 | 0.870 | 0.874 | +0.004 | 462 s | 613 s | 0.75×（变慢，见注） |
| AIOps 2020 | 0.597 | 0.597 | 0.000 | 456 s | 282 s | 1.6× |

结论（如实记录，用户方针 2026-08-29：改进为探索性，不强制达标）：

- **指标**：improved 在全部 4 个数据源上 Avg@5 ≥ faithful（RE1/RE2/RE3
  略升，AIOps 持平）；分故障/分系统层面有升有降（RE2 loss -0.022、
  delay/socket +0.022/+0.030）。
- **延迟**：指标轻场景（RE1、AIOps）提速显著（3.3×/1.6×，quantile
  离散化直接命中 Ψ-PC 的 kmeans 热点）；RE2 含日志+轨迹大表提速 1.36×；
  RE3 小样本（90 例）上 improved 反而慢 0.75×（GMM diag 的 BIC 截断收益
  被 RE3 小簇数场景摊薄，quantile 在短窗口的常数收益不足以覆盖固定开销）。
- **robust scaler 否决记录**：见架构文档 §5.1（SS 数据集隔离实验证据）。

---

## 7. 复现命令

```bash
cd eTrace-Diag && uv sync --extra dev
# RCAeval
uv run python -m experiments.run_torai_rcaeval --suite RE1 --variant faithful [--logs --traces]
uv run python -m experiments.run_torai_rcaeval --suite RE1 --variant improved
# AIOps
uv run python -m experiments.run_torai_aiops --archive data/AIOps挑战赛2020预赛数据.zip \
    --object all --variant faithful --max-cols 50
```

---

## 8. 因果模块消融（2026-09-03）：结论为不采纳，保持原始 TORAI

> 消融计划与执行记录：全因子 16 组合 screen（seed 7）+ 前三组合/full/双基线
> confirmation（seeds 7/11/19），产物在
> `results/torai_ablation/{screen,confirm}/`、
> `results/torai_ablation/{screen,confirm}-summary/`（含
> `confirm-summary-vs-torai/`，即以原始 TORAI（faithful+none）为基准的
> paired 重裁定）。判据与判定代码：`experiments/torai_ablation_matrix.py`
> （`--baseline-variant faithful`）。

### 8.1 决策

**不采纳任何新模块，因果推断算法保持原始 TORAI（faithful）不变。**
依据用户方针（2026-09-03）：以原始 TORAI 为基准的改进不满足采纳条件——
唯一正收益模块（onset）在 RE1 上有 −1.8pt 的一致回退，且未通过预注册的
逐 suite "AC@1 不下降" 判据；组合形态无跨 suite 稳定叠加收益。

### 8.2 四个候选模块与结果

| 模块 | 机制 | 判定 |
|---|---|---|
| tail（empirical-tail 严重度） | normal 窗 median/尾部 p 值评分 | **否决**：主效应 −22.8pt，含 tail 的 8 个组合全部垫底（RE1 −19pt 起） |
| guided（CI 检验优先序） | severity 降序作 Ψ-PC 检验访问序 | **否决**：主效应 −1.7pt，与 onset 叠加仅改变 1/579 案例 |
| onset（时间前兆） | post 段首个 \|z\|≥2 连续触发 onset → 0.25 权重融合严重度 | **唯一正收益但未采纳**：RE2 +4.4pt / RE3 +1.7pt / AIOps +6.1pt，RE1 −1.8pt（逐 seed 一致） |
| consensus（时序块共识） | 3 个 block view 的 Ψ-PC 排名 1/r 投票 | **否决**：suite 特异（仅 RE3 +），RE1 放大回退至 −7pt |

### 8.3 关键证据（确认集，paired vs faithful+none，seeds 7/11/19 均值）

| suite | onset | guided+onset | onset+consensus | full | improved+none（对照） |
|---|---|---|---|---|---|
| RE1 | −1.8pt | −1.9pt | −7.0pt | −54.2pt | −0.2pt |
| RE2 | **+4.4pt**（AC@1 +7.1） | +4.4pt | +3.3pt | −44.6pt | +0.3pt |
| RE3 | +1.7pt | +1.5pt | +2.4pt | −36.0pt | +2.0pt |
| AIOps | +6.1pt | +6.1pt | +6.1pt | +11.1pt | ±0 |

全因子主效应（screen）：tail −22.8pt、consensus −2.1pt、guided −1.7pt、
onset −0.2pt（onset 的收益来自与基线的交互，非平均主效应）。screen 排名
前四全部为不含 tail 的 onset 系组合；组合叠加无跨 suite 稳定增益
（onset+consensus 在 RE3 +6.9pt 但 RE1 −7pt）。

### 8.4 判据说明与保留意见

- 预注册判据为"≥2 suite paired Avg@5 ≥ +0.01 且逐 suite AC@1 不下降、
  每 suite p95 ≤ 30 s、总耗时 ≤ 1.5× 基线"。onset 系未通过：RE1 AC@1
  −1.3pt（逐 suite 判）；RE2 p95 67 s 超 30 s 绝对上限——但原始 TORAI
  自身在 RE2 的 p95 即 65 s（logs+traces 全模态固有成本，onset/基线比
  1.03×），该预算对任何配置都不可达。
- 若按 macro AC@1（+1.3pt）或相对 p95 口径重判，onset 会被标为候选改进；
  本节按预注册逐 suite 口径如实记录为"观察到的回归/零结果"。
- improved 变体继续作为工程选项保留（速度/健壮性），但其排名收益
  （+0.1~0.6pt）在本消融口径下不构成对原始 TORAI 的精度改进。

### 8.5 遗留产物与复现

```bash
# 以原始 TORAI 为基准的 paired 裁定（冷重算，无需重跑实验）
uv run python -m experiments.torai_ablation_matrix \
    --input-dir results/torai_ablation/confirm \
    --output-dir results/torai_ablation/confirm-summary-vs-torai \
    --baseline-variant faithful
# 完整复现：bash experiments/queue_torai_ablation.sh --screen && --confirm ...
```

消融模块代码保留在 `src/alg_models/causal/{torai,psi_pc}.py`（默认关闭，
开关经 `ToraiConfig`），管线行为与原始 TORAI 完全一致（回归测试覆盖：
`tests/test_torai.py`、`tests/test_no_leakage.py`、`tests/test_ablation_matrix.py`）。

### 8.6 轻量化（2026-09-03）：三项零语义差异优化

单案例延迟（原始 TORAI，faithful，确认集实测）：RE1 p50 0.47 s / p95 3.7 s；
RE2 p50 4.4 s / p95 60 s；RE3 p50 4.5 s / p95 13 s；AIOps p50 0.35 s。
瓶颈剖析（cProfile，RE2 最重案例 371 metric + 934 log 列）：GMM BIC 扫描
~1.4 s、KBinsDiscretizer(kmeans) ~0.9 s、Ψ-PC 骨架/CI ~1.9 s，其余为预处理。

已实施（结果逐字节一致，回归测试 90 项全过）：

1. **BLAS/OpenMP 线程池上限 4**（`analyze_tables` 内 `threadpool_limits(4)`，
   threadpoolctl 为 sklearn 既有依赖，无新依赖）：默认 64 线程在小矩阵上
   纯空转——最重 RE2 案例 CPU 68 s vs 墙钟 5.6 s；上限 4 后 CPU 14.7 s
   （↓4.6×），墙钟不变，负载下的尾部延迟（队列曾观测 85 s p95）显著收敛；
   4 线程在重/轻两条路径均实测最快（RE2 4.10 s vs 默认 5.40 s）。
2. **GMM BIC 复用最优估计器**：BIC 扫描后不再用同参数重拟合（同数据/同
   seed/同参数 → 标签逐位一致，已验证），省 1/N 次拟合。
3. **Ψ-PC CI 缓存键** `frozenset(S)` → `tuple(sorted(set(S)))`：等价唯一性、
   更省哈希（6558 次 CI 调用的热路径）。
4. **χ² 尾概率直调 `scipy.special.gammaincc`**：恒等式
   `chi2.sf(x, dof) == gammaincc(dof/2, x/2)`（10 档自由度 × 200 点
   max|diff|=0），跳过 scipy.stats 分布框架的参数校验/分发——6558 次调用
   0.33 s → 0.006 s（54 µs → 1 µs/次）。端到端 A/B：新旧路径 ranks/evidence/
   severity/clusters 逐项一致。

**端到端验证**（优化后全量重跑 RE1 faithful 373 案例）：ac@1=0.6917、
ac@3=0.9303、ac@5=0.9759、**avg@5=0.8660** —— 与历史 faithful 基准数字
完全一致（结果零漂移），1.13 s/案例。

评估过但否决的选项：BIC 扫描并行化（线程/进程池在 threadpool 上限下实测
仅 1.03 vs 1.08 s，复杂度不值）；KBinsDiscretizer 内部 1-D KMeans 为
固定初始化 Lloyd，本身已廉价；CI 缓存命中率为 0%（每次检验均唯一），
保留缓存仅为接口兼容。

未动的语义项（保持原始 TORAI 输出不变）：BIC 全扫描 1..N、kmeans 离散化
策略、骨架发现随机序、CI 判定阈值。队列 85 s 尾部为线程超订下 CPU 争用，
非算法复杂度问题；优化后重跑预期 p95 收敛至个位~十几秒（RE2 除外）。
