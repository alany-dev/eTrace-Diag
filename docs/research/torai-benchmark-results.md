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
