# eTrace-Diag

基于 eBPF 的系统异常观测与根因定位工具（社区赛题）。轻量级、低开销，面向 CPU 异常占用、I/O 延迟抖动、内存抖动/OOM 风险、锁竞争、高频/高耗时系统调用热点五类典型异常场景，实时观测、指标采集、事件关联，并通过 WebSocket 把结构化证据交由异常检测 / 因果推断模型完成根因诊断（协议见 `docs/adr/0003-ws-integration-contract.md`）。

eBPF-based system anomaly observation and root-cause diagnosis tool. Low-overhead, CO-RE, targets CPU saturation, I/O latency jitter, memory pressure/OOM risk, lock contention, and syscall hotspots.

> **当前状态**：采集器与算法模型已完成 WS 联调。采集器产出结构化指标/事件/调用栈证据，DEEP 证据包经 `ws://<host>:9000/causal` 交给 `models/` 下的 TORAI 因果模型，结构化诊断落盘为会话 `diagnosis.json`；异常检测（Time-RCD-Fuse）经 `/anomaly` 驱动 BASE→DEEP 状态机。模型侧说明见 [`models/README.md`](models/README.md)。
> 详细设计见 [`docs/architecture.md`](docs/architecture.md)，实测开销见 [`docs/overhead-baseline-20260828.md`](docs/overhead-baseline-20260828.md)。

---

## 特性

- **两阶段采集**：BASE 常驻基线（主机指标 + 飞行记录器 + 异常检测特征）→ DEEP 异常后细粒度证据（on/off-CPU 画像、syscall 热点、锁竞争、run-queue 延迟、热点文件 I/O）。
- **内核侧 top-k 过滤**：唯一 top-k（进程表 + 每进程线程表），所有细粒度 hook 在 BPF 内按 `targets` map 门控，非目标数据不离开内核。
- **硬件自适应预算**：按 online CPU、cgroup `cpu.max` 配额、cpuset、内存、飞行记录器环形容量推导线程预算（`auto_scale`）。
- **滑窗抗抖动**：`window_seconds` 滑窗计分 + 进程级滞回，指标突变不造成成员抖动、证据序列连续。
- **低开销**：计数器全为内核累积 + 主机侧 delta；栈经 `stack_id` 去重；直方图压缩传输。自开销逐程序精确记录（`bpf_stats.jsonl`）。
- **热配置**：SIGHUP 重载全部采样/窗口/top-k 参数；SIGUSR1/2 手动切换阶段（无模型基准测试用）。
- **多内核适配**：openKylin 6.6（openKylin 目标）/ 5.15 降级路径（per-CPU 采样器、mutex kprobe、无 percpu-lookup 助手），x86_64 / arm64。

## 架构

```
main.cpp ── CLI/信号/初始 config
RunCollector (app.cpp) ── 单线程 tick 调度（host / feature / topk / deep / overhead）
├── EbpfManager    骨架 open/load/attach、map 访问、目标表编辑、自开销统计
├── TargetSelector 两档 top-k（进程表 + 每进程线程）+ 滑窗计分 + 硬件自适应
├── DeepCollector  DEEP 阶段：深链 attach、pre/post 窗口、热点结果 dump
├── PhaseManager   BASE/DEEP 状态机（异常起止/去抖/合并）
├── HostMetrics    /proc 主机指标
├── OutputWriter   会话目录 + JSON Lines / folded 输出
└── ModelClient    ws_model_client | onnx（占位）
```

- 内核侧：单 CO-RE 对象 `bpf/etrace.bpf.c`（`tp_btf`/`kprobe`/`perf_event`/`iter/task`/`fentry` 挂载），完整清单见 `docs/architecture.md §3`。
- 数据流与输出文件见 `docs/architecture.md §6`。

## 环境要求

| 项 | 要求 |
|---|---|
| 操作系统 | openKylin（目标）/ 主流 Linux（开发验证于 5.15 与 6.6） |
| 内核 | ≥ 5.15（目标 6.6+），`CONFIG_DEBUG_INFO_BTF=y`（缺失则启动 fail-fast 并提示） |
| 权限 | root，或 `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN` |
| 架构 | x86_64 / arm64 |
| 构建工具 | cmake ≥ 3.16、clang（BPF target，llvm 14+）、bpftool、libbpf（系统包或自动构建）、libelf、zlib |
| 运行时库 | sqlite3 开发包（会话输出以单文件 SQLite 落盘） |
| 运行时（可选） | stress-ng、fio（复现场景）、python3（mock 模型） |

## 构建

```bash
./scripts/build.sh
# 产物：build/etrace-diag、build/bpf/etrace.bpf.o、build/bpf/etrace.skel.h
```

- 优先使用系统 libbpf（pkg-config），否则自动从内核 `tools/lib/bpf` 静态构建。
- 配置期自动探测内核特性（`bpf_timer`、`lock:contention_begin/end`、`bpf_map_lookup_percpu_elem`）并选择对应实现路径。
- 构建期测试：`config_probe`（配置解析/夹取校验）。

## 使用

```bash
# 参数一览
./build/etrace-diag --help

# BASE 冒烟（60s）
sudo ./build/etrace-diag --output-dir ./out --run-seconds 60 --config config/default.json

# 手动触发 DEEP（无模型基准）：运行后
kill -USR1 <pid>   # 进入 DEEP
kill -USR2 <pid>   # 返回 BASE
kill -INT  <pid>   # 干净退出（DEEP 先 finalize）
```

输出会话目录 `out/<YYYYmmdd-HHMMSS>_<pid>/`：

```
etrace.sqlite3   单文件会话库（WAL 已 checkpoint，自含可复制）。
                 22 张表：meta / host / host_cpu / host_disk / host_proc /
                 anomaly / anomaly_tid / targets_log / oom_events /
                 memory_events / io_devices / bpf_stats / proc_overhead / logs /
                 deep_episodes / deep_series / deep_gap / deep_folded /
                 deep_syscall / deep_lock / deep_runq / deep_iofile。
                 每采集 tick 一个事务；退出前 WAL 合并，文件可独立分发。
```

## 可视化

```bash
# 启动静态服务：站点根 = tools/viz/ 页面；/out/ = 会话输出目录（默认 <项目根>/out）
python3 tools/viz/serve.py            # 默认 http://127.0.0.1:8901/
python3 tools/viz/serve.py --port 9000 --out /data/runs   # 自定义端口与输出目录
```

打开 <http://127.0.0.1:8901/>：自动列出 `out/` 下全部会话（探测各目录的 `etrace.sqlite3`），
默认加载最新一个；更换输出根目录可用浏览器参数 `?out=/路径` 或启动参数 `--out`。

- 无构建步骤：vendored sql.js（WASM）在浏览器内直接读 SQLite；`serve.py` 仅做静态文件服务，也可用任意静态服务器替代（需同时暴露 `tools/viz/` 与会话目录，否则用 `?out=` 指定）。
- 功能面：总览卡片、可编排趋势面板（添加/编辑/拖拽排序/双语纲自动双轴/联动缩放，布局持久化于 localStorage，可导入导出）、DEEP 取证（逐线程趋势小方块 + 点击放大、on/off-CPU 火焰图带面包屑、热点表）、日志检索 + 「定位到图表时段」。
- 测试（node 环境，无需浏览器）：`node tools/viz/test/smoke.mjs <会话目录>`；`node tools/viz/test/dom.mjs <会话目录>`（jsdom，需先 `npm i`，仅此一处用到）。

## 配置

全部参数见 `docs/architecture.md §2`（`config/default.json` ↔ `include/etrace_diag/config.h`）。要点：

- **加载优先级**：CLI > `ETRACE_DIAG_*` 环境变量 > `--config` JSON > 内置默认。
- **热重载**：SIGHUP 重读配置文件，`sample.*` / `window.*` / `targets.*` 下一 tick 生效。
- **top-k 关键项**：`auto_scale`（硬件自适应）、`max_targets`（线程预算上限）、`per_proc_threads`（每进程线程数）、`concurrency_factor`（每逻辑核关注线程数）、`eval_interval_ms`（重评周期）、`window_seconds`（滑窗跨度）。
- **自开销**：`misc.enable_bpf_stats=true` 时启动置 `kernel.bpf_stats_enabled=1`，逐程序记录执行次数/耗时，退出恢复原值。

## 复现与验证

```bash
# 五个场景（赛题要求 §46-49）：每个脚本运行收集器、触发 DEEP、断言产物
./scripts/scenario_cpu.sh
./scripts/scenario_io.sh
./scripts/scenario_mem.sh
./scripts/scenario_lock.sh

# 采集器独立回归（mock 模型触发一次异常 → DEEP → 证据打包 → diagnosis.json）
sudo MODEL_PY=<models venv python> ./scripts/regress_mock.sh 45

# 真实模型 WS 端到端联调（每场景约 3.5 分钟：预热 60s + 注入 90s + post 40s）
sudo bash scripts/e2e_scenario.sh cpu     # cpu|io|mem|lock，见 models/configs/e2e.yaml
```

端到端断言：DEEP episode ≥ 1、`diagnosis.json` 的 CausalReport 非空且候选实体
为 `proc<pid>` / `dev<maj>m<n>` / `host` 之一、异常类型与注入场景一致。

## 一键环境部署（openKylin）

```bash
sudo ./scripts/setup_openkylin.sh          # 工具链 + stress-ng/fio + 模型环境 + checkpoint
```

过程记录与排错见 [`docs/env-setup-openkylin.md`](docs/env-setup-openkylin.md)；
QEMU 四架构（amd64/arm64/loongarch64/riscv64）验证计划见
[`docs/qemu-crossarch-plan.md`](docs/qemu-crossarch-plan.md)。

场景脚本验证断言：BASE ≥1 行/s、DEEP 窗口时间戳 ∈ `[anomaly_start−pre, anomaly_start+post]`、热点文件非空、top-k 成员出现在 `targets_log`、自开销文件逐秒增长。

## 实测开销（2026-08-28，5.15 共享机，仅 BPF 程序体）

| 阶段 | 内核 BPF 本体 | 用户态进程 |
|---|---|---|
| BASE | ≈ 17% 单核 | ≈ 11% 单核 |
| DEEP | ≈ 50% 单核 | ≈ 20% 单核 |

口径与逐程序明细见 [`docs/overhead-baseline-20260828.md`](docs/overhead-baseline-20260828.md)；系统净影响（评审口径）需 `perf stat -a` 加载/不加载对照。6.6 目标机上 `snapshotter` 走 bpf_timer 求和模式，成本显著低于 5.15 降级路径。

## 已知限制

- `file_open_path` 的路径缓存为「最近一次 open」，同一 inode 多路径退化为最近路径；open 早于入榜时退化为 basename。
- `mm->rss` 在 6.6 为 percpu 计数器（BPF 不可读），RSS 仅对目标进程主机侧补读。
- ONNX 适配器为占位（`model.adapter=onnx` 会抛未链接异常），当前推理走 WS。
- 飞行记录器环形容量编译期固定（`RING_CAP=32768`），`ring_backlog_seconds` 只能下调不能超容量上调。

## 目录结构

```
bpf/                内核 BPF 程序（CO-RE 单对象）
cmake/              libbpf / bpftool 构建适配
config/             默认配置
include/etrace_diag/ 公共头（config/metrics/output_writer/model_client/app）
src/                C++ 实现（collect/ model/ output/ 及主循环）
scripts/            构建、运行、mock 模型、场景复现、e2e 联调、openKylin 一键部署
models/             算法模型（Time-RCD-Fuse 异常检测 + TORAI 因果 RCA + WS 服务）
tools/viz/          浏览器端会话可视化（静态页面 + serve.py + node 测试）
tests/              构建期测试（config_probe）
third_party/        vendored 单头 nlohmann/json
docs/               架构/开销基线/ADR/术语表/部署记录/QEMU 多架构计划
```

## 许可

见赛题说明（`赛题要求.md`）。本项目为竞赛作品，开源技术栈（C++20 / libbpf / eBPF / nlohmann-json）。
