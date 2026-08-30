# TORAI 架构详解：基准版（faithful）与改进版（improved）从零入门

> 本文面向从零读者：先交代问题背景与必要的基础概念，再逐模块拆解本项目
> `src/alg_models/causal/torai.py`（管线）与 `src/alg_models/causal/psi_pc.py`
> （Ψ-PC 因果发现核心）的实现，最后对比基准版与改进版的每一处差异及原因。
> 配套实验指标见 `docs/research/torai-benchmark-results.md`；算法出处为
> TORAI（FSE 2026, arXiv:2604.13522，RCAEval 仓库，MIT）。

---

## 1. 问题背景：为什么需要 TORAI

### 1.1 微服务故障根因定位（RCA）

一个微服务系统由几十个服务组成（如电商的购物车、下单、支付服务）。某个
时刻系统出现故障（例如支付延迟骤增），运维需要回答两个问题：

1. **哪个服务是根因**（root cause service）？
2. **它发生了什么**（CPU 打满？内存泄漏？网络丢包？磁盘 IO 异常？）

这就是 Root Cause Analysis（RCA）。做得好，MTTR（平均修复时间）从小时级
降到分钟级；做不好，运维在十几个服务之间瞎猜。

### 1.2 传统方法的痛点：依赖"服务调用图"

2019-2021 年的经典方法（MicroRCA、Microscope、CloudRanger 等）都假设运维
**能拿到服务调用图**（service call graph）：谁调用谁、调用链长什么样。
它们把异常指标当作图上节点，沿边传播（随机游走/PageRank/因果推断）找根因。

但真实场景中调用图经常**缺失或不可靠**：

- 服务网格/链路追踪未全量开启；
- 异步消息队列（Kafka/RabbitMQ）让"调用"关系含糊；
- 服务混部、动态伸缩使拓扑持续漂移。

TORAI 的卖点就是**完全不依赖调用图**：只靠每个服务自己的多源遥测
（指标 + 日志 + 轨迹），用无监督学习把根因服务排出来。

### 1.3 多源遥测与"盲点"（blind spot）

| 模态 | 内容 | 粒度 |
|---|---|---|
| metric（指标） | CPU/内存/磁盘/网络等数值序列 | 每服务 × 每指标，1 s 一条 |
| log（日志） | 文本日志按模板聚合成计数序列 | 每服务 × 每模板，15 s 一个计数 |
| trace（轨迹） | 调用链 span 的错误数、时延 | 每服务，15 s 一个聚合值 |

不同系统只有部分模态可用（例如 Sock Shop 没有轨迹数据）——缺失模态叫
"盲点"。TORAI 的设计语义是：**缺哪个模态，那个模态的得分就是 0**，其余
模态照常工作，绝不把"没有数据"当成"没有异常"。

---

## 2. 基础概念速成（读代码前必须理解）

### 2.1 z 分数（z-score）与标准化

```
z = (x - μ) / σ      μ: 均值  σ: 标准差
```

含义：某个观测值离"正常水平"有几个标准差。正常窗口拟合出 μ 和 σ，异常
窗口的每个值都换算成 z，|z| 越大越异常。这是 TORAI 严重度（severity）的
基础。

### 2.2 条件独立与卡方检验（chi-square test）

Ψ-PC（RCD 的因果发现核心）要回答的问题：**给定变量集合 S，X 和 Y 是否
独立？** 即 `X ⊥ Y | S`。

对离散数据（TORAI 把连续指标先离散化成 5 个桶），标准做法是卡方检验：

1. 按 S 的每种取值组合分层，每层内做一个 X×Y 列联表（计数表）；
2. 若 X、Y 独立，期望计数 = 行合计 × 列合计 / 总数；
3. 卡方统计量 `χ² = Σ (观测 - 期望)² / 期望` 越大，越不可能独立；
4. `p = P(χ²_df ≥ 观测值)` 越小，越有把握说"相关"。

TORAI 用法：p 值 > 显著性水平 α（如 0.001）→ 判定独立（没有边）；
p 值 ≤ α → 判定相关（保留边）。

### 2.3 因果发现（PC 算法的思路）

PC 算法（以人名 Peter Spirtes / Clark Glymour 命名）从**全连接无向图**
出发，逐层用条件独立检验删边：

- 深度 0：检验 `X ⊥ Y`（无条件独立），删掉独立的边；
- 深度 1：检验 `X ⊥ Y | 单个节点`；
- 深度 2：检验 `X ⊥ Y | 两个节点`；……
- 直到剩余图的最大度数 ≤ 当前深度。

核心直觉：两个节点真的相关，就很难找到使它们独立的"分离集"（separation
set）；虚假的间接相关（X→Z→Y），控制住中介 Z 后 X、Y 就独立了，边被删。

### 2.4 根因的特殊处理：F-node（故障虚拟节点）

RCD/TORAI 的巧思：把"是否处于故障时段"做成一个**虚拟变量 F**——

- 正常窗口的所有行：`F = 0`
- 异常窗口的所有行：`F = 1`

然后把 F 当作第 n+1 个变量拼进数据，跑因果发现。**与 F 直接相关（无法
被其他变量分离）的指标，就是故障时段真正发生了分布偏移的指标**——即
根因候选。这一步把"找根因"变成了"找 F 的孩子节点"，整个因果发现只需要
跑**局部骨架发现**（local skeleton），不用在完整图上找方向。

### 2.5 GMM 与 BIC（症状聚类）

高斯混合模型（Gaussian Mixture Model）：假设数据由 K 个高斯分布混合
生成，EM 算法估计每类的均值/协方差与归属概率。TORAI 用它把服务聚成
"症状簇"（同一故障的受害者服务们往往有相似的严重度模式）。

BIC（Bayesian Information Criterion）：
```
BIC = k·ln(n) - 2·ln(L)      k: 参数个数  n: 样本数  L: 似然
```
BIC 越小越好；前半项惩罚模型复杂度，后半项奖励拟合度。TORAI 从 K=1 扫到
K=N（服务数），取 BIC 最小的 K 作为簇数——**自动定簇数**，无需超参。

### 2.6 离散化（discretization）

Ψ-PC 的卡方检验要求离散数据。KBinsDiscretizer 把每列连续值切成 bins 个桶：

- `kmeans` 策略：对每列单独跑 1 维 KMeans（k=bins），桶边界=聚类中心中点；
- `quantile` 策略：按分位数切桶（每桶样本数大致相等）。

kmeans 更贴分布形状但慢（每列一次 KMeans 迭代），且要求样本数 ≥ bins；
quantile 快且稳定。

---

## 3. TORAI 基准版（faithful）：忠实移植 RCAEval `torai()`

> 目标：逐行等价 RCAEval 的 `e2e/torai.py`，保证论文指标可复现。
> 实现：`src/alg_models/causal/torai.py`。

### 3.1 总览数据流

```
metric(1s)  logts(15s)  tracets_err(15s)  tracets_lat(15s)
   │             │              │              │
   │ iloc[::15]  │ drop_constant│ ffill+0      │ ffill+0
   ▼             ▼              ▼              ▼
正常窗口(时间<inject)  /  异常窗口(时间>=inject)
   │             │              │              │
   ▼             ▼              ▼              ▼
每列拟合 μ/σ → 异常窗口 max|z| → 每模态细粒度严重度排序
   │
   ├─ metric/trace: fine2coarse_addup（按服务求和）
   └─ log: fine2coarse_highest（按服务取最高，再归一化）
   ▼
服务 × 模态 严重度矩阵 m (fillna(0))
   ▼
GMM 聚类（BIC 定簇数，full 协方差）
   ▼
逐簇：单成员簇直接通过；
      多成员簇 → 先按簇内严重度排序 aa，再对簇内 metric+logts 子集跑 RCD
      （Ψ-PC 多阶段）→ 若 RCD 恰好返回全部簇成员则用 RCD 序，否则回退 aa 序
   ▼
service_ranks: ["adservice_A", "cartservice_A", ...]（_A 后缀，评估器约定）
```

### 3.2 模块一：数据准备（`analyze_tables` 前半段）

```python
metric = metric.iloc[:: cfg.resample_s, :]     # 1s 重采样到 15s（隔15取1）
normal_metric = metric[metric["time"] < inject_s]
anomal_metric = metric[metric["time"] >= inject_s]
```

然后 `_preprocess`（忠实移植 RCAEval `io/time_series.py`）：

1. `drop_time`：去掉 time 列；
2. `convert_mem_mb`：`*_mem` 列除以 1e6（字节→MB，数值尺度对齐）；
3. `drop_constant`：删掉全程不变的列（`(df != df.iloc[0]).any()`），
   **连续做两次**（先删一次再删一次，与参考实现一致）。

日志/轨迹侧：

- `logts`：`drop_constant` 后按时间切 normal/anomal；
- `traces_err`：`ffill().fillna(0)` → `drop_constant` → 切分，且
  **normal 侧再删最后 2 行**（`[:-2]`，参考实现的细节，防边界污染）；
- `traces_lat`：同上但 normal 侧不删行。

### 3.3 模块二：严重度评分（`severity_scores`）

参考实现是逐列 `StandardScaler().fit(normal).transform(anomal)` 取 max|z|，
本项目改为**一次性 numpy 向量化**（数值等价）：

```python
a = normal 列矩阵; b = anomal 列矩阵
μ = mean(a, axis=0); σ = std(a, axis=0)（σ=0 的列用 1 兜底）
z = |(b - μ) / σ| 的最大值（每列）
分数 = 列 max|z| / 所有列 max|z| 之和     # 归一化到和为 1
```

返回 `[(列名, 分数), ...]` 按分数降序。

### 3.4 模块三：细→粗聚合（fine2coarse）

列名约定 `{service}_{metric}`（如 `adservice_cpu`），服务 = 第一个 `_` 前的
前缀（本项目实现 `split("_")[0]`，与参考一致）。

- **metric/trace 用 addup**：同服务所有指标分数**求和**。一个服务 CPU 和
  磁盘都异常，得分叠加，理应排名靠前；
- **log 用 highest**：同服务所有日志模板**取最高**，再按服务去重、按总和
  归一化。理由：日志模板数众多且稀疏，求和会被"模板多"的服务霸榜，取
  最高只看"最异常的那一条模板"，更稳健。

另有参考实现的细节：`frontendservice` 重命名为 `frontend`（历史命名兼容）。

### 3.5 模块四：服务×模态矩阵 m 与症状聚类

```
m = DataFrame(index=服务, columns=[metric, log, trace_lat, trace_err])
    = 各模态 coarse 分数，缺失填 0
```

`X = m.to_numpy()`，行=服务，列=模态。**GMM 聚在这 4 维严重度向量上**。

```python
for n_comp in range(1, N+1):          # N = 服务数
    GMM(n_comp, covariance_type="full", max_iter=50, random_state=0)
    BIC 记录
K = argmin(BIC) + 1                    # 最优簇数
labels = GMM(K).fit_predict(X)
cluster_rank: 每簇按"簇内服务 mean 严重度"降序排列
```

### 3.6 模块五：簇内 RCD 精排（核心创新点）

对 cluster_rank 里的每个簇：

- **单成员簇**：直接输出该服务；
- **多成员簇**：
  1. 先按簇内严重度降序排出 `aa`（备选序）；
  2. 取该簇的 metric 子列（列名前缀 ∈ 簇成员）+ logts 子列，拼上 time；
  3. 调用 `_rcd_multimodal`：内部再 `iloc[::15]`、按 inject 切 normal/anomal、
     预处理、`_match_columns`、加 F-node（normal=0 / anomal=1）、
     `run_multi_phase`（Ψ-PC 多阶段，见 §4）；
  4. RCD 返回的列名去掉 `_metric` 后缀得到服务序，**去重**；
  5. **裁决规则**：若 RCD 序恰好覆盖了全部簇成员（长度相等）→ 用 RCD 序；
     否则 → 回退 `aa` 严重度序（RCD 对这个簇没有完整结论，不信它）。

直觉：GMM 把"症状相同"的服务圈在一起；簇内谁是真根因，用因果发现（Ψ-PC
找 F 的孩子）再裁一次，比纯严重度排序更准。

### 3.7 输出与评估约定

```python
service_ranks = [f"{svc}_A" for svc in 最终服务序]
```

- `_A` 后缀是 RCAEval 评估器的字符串约定（`split("_")[0]` 取服务名）；
- 评估（论文式 AC@k / Avg@5）：粗粒度服务 = `split("_")[0].replace("-db","")`
  去重后看真值服务是否落在前 k；
  ```
  Avg@5 = (AC@1 + AC@3 + AC@5) / 3
  ```

---

## 4. Ψ-PC 因果发现核心（`psi_pc.py`）——基准版的引擎

> 目标：原生 numpy 等价替换因果学习包 causal-learn 的 patched
> `local_skeleton_discovery`（RCAEval 依赖 py3.8 的旧 causal-learn），
> Python 3.11 直接运行。`chisq_ci` 与 causal-learn 做过 120/120 位级对照。

### 4.1 常量与配置

```python
F_NODE = "F-node"
START_ALPHA = 0.001      # α 扫描起点
ALPHA_STEP = 0.1         # α 步长
ALPHA_LIMIT = 1          # α 上限（开区间）
LOCAL_ALPHA = 0.01       # 分块阶段（phase-1）的 α 起点
DEFAULT_GAMMA = 5        # 分块大小
```

### 4.2 数据结构：`MiniCausalGraph`（等价替代 causal-learn `CausalGraph`）

只保留 Ψ-PC 需要的部分：

- `graph`：邻接矩阵（初值全连接无向）；
- `neighbors(i)` / `max_degree()` / `remove_edge(x, y)`；
- `p_values[(x,y)]`：每次"判相关"的 p 值列表（append 语义）；
- `mi`：边际独立（marginal independence）寄存器——深度 0 就被分离掉的节点；
- `ci_test(x, y, S)`：带 `(x,y,frozenset(S))` 缓存 + 检验次数计数，
  与 patched `CausalGraph.ci_test` 等价。

### 4.3 `chisq_ci`：卡方条件独立检验（位级等价 causal-learn）

输入已离散化的数据矩阵（连续输入先 `_unique_indices` 转 0..card-1）：

- **S 为空**：直接 X×Y 列联表 → `χ²` → `chi2.sf(stat, df)`；
- **S 非空**：先给 S 的取值组合编号（bincount 或 unique 两种路径，
  阈值 `1e5` 与 causal-learn 一致），每层一个 X×Y 表，分层求和 χ²；
- **自由度修正**：期望表中全零的行/列不计入自由度（causal-learn 的
  `_CalculatePValue` 细节，防止退化 df=0 → p=1）。

### 4.4 `discretize`：KBinsDiscretizer 包装

- 除 F-node 外的所有列做 `KBinsDiscretizer(n_bins, encode="ordinal",
  strategy=kmeans/quantile)`；
- F-node 保持 0/1 不参与离散化（它是二值虚拟变量）；
- 健壮性修复（§6）：kmeans 且样本数 < bins 时退 quantile。

### 4.5 `local_skeleton_discovery`：局部骨架发现（patched 版）

与经典 PC 的区别：**只关心 F-node 周围的边**，大幅省算力：

```python
depth = -1; x = F-node 的下标
先移除 mi 里节点与 F-node 的边（上一轮已知独立的，不用再测）
while max_degree - 1 > depth:
    depth += 1
    for y in permutation(F-node 的邻居):        # 随机序（seed 固定可复现）
        S 候选 = y 的邻居中与 F-node 也相邻者（depth>0 时）的 depth 元组合
        for S in combinations(...):
            p = ci_test(x, y, S)
            if p > alpha:                       # 独立 → 删边
                remove_edge(x, y); 记 sepset
                if depth == 0: append_to_mi(y)  # 深度0就独立 → 记入 MI
                break
            else:
                记 p 值（供 _order_neighbors 用）
```

关键点：

- **深度 0 就被分离的节点进 MI 表**，下一轮骨架发现直接跳过它俩的边
  （patched causal-learn 的 `mi` 机制，加速核心）；
- 邻居遍历顺序 `np.random.permutation`（seed 贯穿，结果可复现）；
- p 值**升序入栈**：`_order_neighbors` 反复 `argmax(p)` 弹出节点、头插栈，
  最终栈序 = 越相关（p 越小）越靠前——这就是 F 孩子节点的排名。

### 4.6 `run_psi_pc`：α 扫描

```python
for alpha in np.arange(start_alpha, 1, 0.1):    # 0.001 → 0.001,0.101,0.201,...
    cg = local_skeleton_discovery(data, F-node, alpha, mi=已处理的)
    取 F 的邻居中新出现的节点，按 p 值升序（argmax 栈序）追加到 rc
    直到 rc 长度达到 min_nodes 或 α 扫描完毕
```

α 越大越宽松（更容易判相关、保留更多边）。**从松到紧**扫描的意义：α 很小
时可能一个孩子都找不到；逐步放宽直到找到足够的孩子。每个 α 只把**新**
出现的孩子按该轮 p 值排序追加（已排过的顺序不被覆盖）。

### 4.7 `run_multi_phase`：RCD 两阶段

```
phase-1（分块收缩）:
  f_child = 全部列
  循环:
    create_chunks(f_child, gamma=5)          # 列随机排列，每 5 列一块
    每块独立 run_psi_pc(start_alpha=0.01, min_nodes=1) → 收集 F 孩子
    f_child = 并集（每块至少 1 个孩子，或没有）
    直到 len(f_child) <= gamma 或 与上轮相等（收敛）

phase-2（精排）:
  在幸存列 f_child 上跑一次完整 run_psi_pc（无 min_nodes 限制）
  → 按 p 值排序的孩子列表 = 最终根因序
```

直觉：phase-1 像"锦标赛淘汰"——5 列一组找出各自的疑似根因，合并后再比，
把候选列压缩到 ≤5 个；phase-2 在这 ≤5 个候选上用完整 α 扫描精排。
这样避免在几百列上跑全量 PC（指数级条件集组合）。

### 4.8 数据流细节（忠实移植 rcd.py）

- `add_fnode_and_concat`：normal 加 `F=0` 列，anomal 加 `F=1` 列，纵向拼接；
- `_match_columns`：normal/anomal 取列交集（防预处理后列不一致）；
- 分块用的是 `np.random.permutation(df.columns)`（seed 固定）。

---

## 5. 改进版（improved）与基准版的逐项差异

> 目标：在 Avg@5 不降的前提下大幅降低延迟（实测 RCAeval RE1 提速 4.5×、
> AIOps 提速 38%，三套官方数据 Avg@5 全部 ≥ 基准版）。
> 实现：`ToraiRCA._variant_cfg("improved")` 覆盖配置。

| 组件 | 基准版 faithful | 改进版 improved | 为什么改 |
|---|---|---|---|
| scaler | standard（μ/σ） | **standard（保留）** | 计划原想用 robust（median/IQR），实测在 SS 上排序崩坏（稀疏日志计数列 IQR≈0 落入 1.0 兜底，z 值被放大数倍，日志模态吞掉严重度矩阵；Avg@5 0.59 vs faithful 0.93），用户决策保留 standard |
| covariance_type | full | **diag** | 对角协方差参数从 d(d+1)/2 降到 d，EM 每轮更快、数值更稳；服务数大时几乎无精度损失 |
| n_components_max | None（BIC 扫 1..N） | **10** | 簇数不可能超过 10（服务级严重度模式有限），截断 BIC 扫描直接砍掉大半 GMM 拟合 |
| discretize_strategy | kmeans | **quantile** | kmeans 每列一次 KMeans 迭代是 Ψ-PC 最大热点（profiling：34 s / 58 s 案例）；quantile 按分位数切桶，解析式无迭代 |
| normal_post_trim | 0 | **resample_s=15 行（原生分辨率，重采样前）** | 异常检测有延迟时，故障初期的样本会漏进 normal 窗口污染 μ/σ；删除 normal 尾部 15 个原生秒 ≈ 后 15 s 污染窗。注意**必须在 `iloc[::15]` 重采样之前删**——在 15 s 重采样后删 15 行 = 删 225 s，会把短窗口（如 SS 正常侧仅 40 个重采样行）砍掉 37.5% 直接破坏统计（实测隔离证明这点单独就把 SS 打崩） |
| 健壮性 | （参考同样崩） | **kmeans 样本<bins 退 quantile；severity 矩阵为空返回空排名** | 短窗口案例（RE1 delay 类仅 4 样本）参考实现会 `n_samples < n_clusters` 崩溃；改为优雅降级，案例仍可评估 |

### 5.1 robust scaler 为何被否决（证据记录）

隔离实验（SS 数据集 6 案例，top-1 命中，配置 monkeypatch 只改单分量）：

| 配置 | top-1 命中 |
|---|---|
| faithful | 5/6 |
| improved（robust 全开） | 0/6 |
| robust→standard | **5/6**（唯一恢复项） |
| covariance→full（计划预设预案） | 0/6 |
| quantile→kmeans / 无 trim / GMM 无上限 | 0/6 |

结论：唯一元凶是 robust scaler；计划的"covariance 退回 full"预案被证伪。
机理：`(b - median)/IQR` 对稀疏日志计数列，normal 侧 IQR=0 → 兜底 1.0，
而 standard 的 σ 兜底也是 1.0 但 μ/σ 对尖峰更不敏感；robust 把 max|z|
放大后经 `fine2coarse_highest` + 归一化，日志模态压过 metric 模态。

### 5.2 improved 的延迟构成（实测）

- RCAeval RE1：840 s → 252 s（**3.3×**）；
- RCAeval RE2（metric+log+trace）：5159 s → 3803 s（**1.36×**）；
- RCAeval RE3（小样本 90 例）：462 s → 613 s（0.75×，diag GMM 收益被小簇数
  摊薄，quantile 固定开销无覆盖——如实记录）；
- AIOps 24 案例：456 s → 282 s（**1.6×**）。

轻指标场景（RE1/AIOps）提速显著：quantile 离散化直接命中 Ψ-PC 的 kmeans
热点；RE2 的剩余成本转移到 traces 的 I/O 与 log 模板化。

---

## 6. 代码地图

```
src/alg_models/causal/
├── torai.py            TORAI 管线（基准+改进）
│   ├── ToraiConfig     dataclass 配置（resample_s/gamma/bins/...）
│   ├── severity_scores 向量化 max|z| 严重度
│   ├── fine2coarse_addup / fine2coarse_highest
│   ├── symptom_cluster GMM+BIC 聚类
│   ├── to_torai_frames TelemetryFrame/LogEvent/TraceSpan → TORAI 表
│   ├── ToraiRCA.analyze_tables  基准管线（benchmark 入口）
│   ├── ToraiRCA._rcd_multimodal 簇内 RCD 调用
│   ├── ToraiRCA.analyze         检测器接入 + CausalReport 组装
│   └── ToraiRCA._variant_cfg    变体门控
└── psi_pc.py           Ψ-PC 因果发现（原生 numpy）
    ├── MiniCausalGraph 邻接矩阵图（替代 causal-learn CausalGraph）
    ├── chisq_ci        卡方条件独立检验（位级等价）
    ├── discretize      KBinsDiscretizer 包装（kmeans/quantile + 兜底）
    ├── local_skeleton_discovery / skeleton_discovery
    ├── run_psi_pc      α 扫描
    ├── create_chunks / run_level / run_multi_phase   RCD 两阶段
    └── add_fnode_and_concat / _match_columns

experiments/
├── run_torai_rcaeval.py   官方 RCAeval RE1/RE2/RE3 直读 parquet 基准
├── run_torai_aiops.py     AIOps 2020 实例级适配器
├── run_torai.py           TORAI-format（官方 Figshare 布局）基准
└── torai_aggregate.py / run_torai_serial.py   聚合与串行队列
```

## 7. 从零复现/上手步骤

```bash
cd eTrace-Diag && uv sync --extra dev
# 官方 RCAeval 真实数据（data/rcaeval 已在盘）
uv run python -m experiments.run_torai_rcaeval --suite RE1 --variant faithful
uv run python -m experiments.run_torai_rcaeval --suite RE1 --variant improved
# AIOps 2020（用户提供 archive）
uv run python -m experiments.run_torai_aiops --archive data/AIOps挑战赛2020预赛数据.zip \
    --object all --variant faithful --max-cols 50
# 单元测试（severity/聚类/Ψ-PC/变体/trim 语义）
uv run pytest -q tests/test_torai.py
```

## 8. 关键参数速查

| 参数 | 默认 | 作用 |
|---|---|---|
| resample_s | 15 | 指标重采样间隔（秒） |
| gamma | 5 | RCD phase-1 分块大小 |
| bins | 5 | 离散化桶数（也是卡方表维度） |
| localized | True | Ψ-PC 只发现 F-node 局部骨架 |
| scaler | standard | 严重度标准化方式 |
| covariance_type | full / diag | GMM 协方差结构（变体开关） |
| n_components_max | None / 10 | BIC 扫描簇数上限（变体开关） |
| discretize_strategy | kmeans / quantile | 离散化策略（变体开关） |
| gmm_max_iter | 50 | GMM EM 迭代上限 |
| normal_post_trim | 0 / 15 | normal 尾裁剪（原生秒，变体开关） |
| random_state | 0 | GMM 确定性种子 |
| START_ALPHA / ALPHA_STEP / LOCAL_ALPHA | 0.001 / 0.1 / 0.01 | Ψ-PC α 扫描与分块阶段起点 |

---

## 9. 已知限制与失败语义

1. **短窗口**：样本 < 离散化桶数时，kmeans 退 quantile（改进版自动；基准
   版同参考会崩，现同样退避以保证可评估）；
2. **无信号案例**：正常窗口所有指标恒定 → severity 矩阵为空 → 返回空排名
   并记 `"empty severity matrix (no signal)"`，评估时如实排除（RE1 有 2 例）；
3. **RCD 高维膨胀**：列数过多（如 AIOps os/db 全展开 598-1122 列）时 Ψ-PC
   组合爆炸，需 `--max-cols` 按方差截断（AIOps 适配器默认 50）；
4. **簇内 RCD 无结论**：返回序未覆盖全部簇成员时回退严重度序（忠实参考
   行为）；
5. **日志模板数**：Drain 模板化上限 500 组/服务，防列爆炸。

---

## 10. 与论文/RCAEval 的忠实性声明

- `severity_scores` 与参考逐列 StandardScaler 数值等价（向量化）；
- `fine2coarse_addup/highest`、`frontendservice→frontend` 重命名、
  `traces_err` normal 侧 `[:-2]`、`_A` 后缀、簇内裁决规则：逐行忠实；
- `chisq_ci` 与 causal-learn 120/120 位级一致；骨架发现循环（深度、
  permutation、MI 表、p 值记录）按 patched 版逐行移植；
- 唯一语义差异：seed 贯穿所有随机源（参考实现用全局 RNG，不可复现），
  与改进版的健壮性降级（§5）。
