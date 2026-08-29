# eTrace-Diag 整体框架说明（实现对照）

> 依据 `bpf/etrace.bpf.c`、`src/`、`config/default.json` 实际代码整理，非设计稿。
> 内核侧契约：SEC 字符串 / map 名 / 数据结构均冻结（与实现计划一致）。
> 生成日期：2026-08-28。目标内核 6.6+（openKylin），当前开发机为 5.15（有降级路径）。

## 0. 定位与运行模型

- C++20 用户态 + libbpf CO-RE，内核侧单对象 `bpf/etrace.bpf.c`（编译为 `etrace.bpf.o` → `etrace.skel.h`）。
- 两阶段状态机：**BASE**（常驻基线采集 + 异常检测）→ **DEEP**（异常后 3 分钟细粒度采集 + 因果推断）。
- 异常检测 / 因果推断 = 外部模型（WS 协议，`model.adapter` 预留 onnx 端口），本里程碑只做数据采集。
- 运行前提：root 或 CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN；`CONFIG_DEBUG_INFO_BTF=y`（无则 fail-fast）。

## 1. 顶层组件与主循环

```
main.cpp ── CLI/信号/初始 config
RunCollector (app.cpp) ── 主循环，单线程 tick 调度
├── EbpfManager    骨架 open/load/attach、map 访问、CollectProgramStats、目标表编辑
├── TargetSelector 唯一 top-k 选择（targets map 编辑者）
├── DeepCollector  DEEP 阶段：attach 深链 + profiler、pre/post 窗口、结果 dump
├── PhaseManager   BASE/DEEP 状态机（异常起止/去抖/合并）
├── HostMetrics    /proc 主机指标（无特权）
├── OutputWriter   会话目录 + 各文件
└── ModelClient    ws_model_client（IXWebSocket）| onnx（占位，抛未链接）
```

主循环 tick 表（频率全部来自 `sample.*`，SIGHUP 可热改）：

| tick | 周期(默认) | 动作 |
|---|---|---|
| host | `base_host_interval_ms` 1000 | `HostMetrics::Snapshot()` + `iter/task` 进程表（截 top-200）+ mem/oom/dev_io 增量 dump → `base_host.jsonl` |
| feature | `base_feature_interval_ms` 1000 | 构造异常特征向量（host + ebpf 计数器 + top_tasks）→ WS 模型 → `base_anomaly.jsonl` |
| topk | `targets.eval_interval_ms` 5000 | `TargetSelector::Evaluate()`：两档 top-k（进程表+每进程线程）+ 滑窗计分 + 硬件自适应，改 `targets` map |
| deep | `deep_dump_interval_ms` 1000（仅 DEEP） | `DeepCollector::Tick()`：post 窗口增量 drain + DEEP 结果 map dump |
| overhead | `overhead_interval_ms` 1000 | 自开销：`bpf_prog_info.run_cnt/run_time_ns` → `bpf_stats.jsonl`；`getrusage`+RSS → `proc_overhead.jsonl` |

## 2. 完整配置表（config/default.json ↔ config.h，均为确切字段名）

| 分组 | 字段 | 默认 | 含义 |
|---|---|---|---|
| sample | base_host_interval_ms | 1000 | 主机指标采样周期 ms |
| sample | base_feature_interval_ms | 1000 | 异常特征/模型调用周期 ms |
| sample | fine_interval_ms | 100 | 飞行记录器 BASE 采样周期 ms |
| sample | deep_fine_interval_ms | 20 | 飞行记录器 DEEP 采样周期 ms |
| sample | deep_dump_interval_ms | 1000 | DEEP 结果 dump 周期 ms |
| sample | profile_freq_hz | 99 | on-CPU profiler 采样频率 Hz |
| sample | offcpu_sample_rate | 16 | off-CPU 栈捕获限流（次/线程/秒） |
| sample | iofile_sample_rate | 4 | vfs_read/write 采样 1/N |
| sample | overhead_interval_ms | 1000 | 自开销采样周期 ms |
| window | pre_anomaly_seconds | 60 | 异常前证据窗口 s |
| window | post_anomaly_seconds | 180 | DEEP 持续 s |
| window | ring_backlog_seconds | 90 | 环形缓冲保留 s |
| window | end_debounce_samples | 3 | 结束去抖（连续 N 次非异常） |
| window | end_grace_seconds | 5 | 结束宽限 s |
| targets | max_targets | 64 | 线程预算上限（`targets` map 容量；auto_scale 关时即命令值） |
| targets | auto_scale | true | 按硬件推导线程预算 |
| targets | min_targets | 4 | 自适应线程预算下限 |
| targets | per_proc_threads | 4 | 每选中进程的线程数 |
| targets | concurrency_factor | 2.0 | 每逻辑核关注的线程数 |
| targets | eval_interval_ms | 5000 | 滑窗重评周期 ms |
| targets | window_seconds | 30 | 滑窗计分跨度 s |
| model | anomaly.url / timeout_ms | ws://127.0.0.1:9001/anomaly / 5000 | 异常模型 |
| model | causal.url / timeout_ms | ws://127.0.0.1:9002/causal / 30000 | 因果模型 |
| model | adapter | ws | ws \| onnx |
| output | dir / metrics_format / profile_format | out / jsonl / folded | 输出 |
| misc | log_level / categories / pid_filter | info / 全5类 / 0 | 杂项 |
| misc | enable_bpf_stats | true | 启动写 `kernel.bpf_stats_enabled=1`，退出恢复 |

## 3. 内核 BPF 程序清单

### 3.1 Always-on（启动 attach 一次，永不 per-process 重挂）

| SEC（挂载点） | 程序名 | 采集内容 → 写 map | 过滤 |
|---|---|---|---|
| `tp_btf/sched_switch` | on_switch | 在核时间归属 `on_cpu_ns[tid]+=Δ`；切换计数 `switches[tid]{vol,invol}`；DEEP 分支：off-CPU stash/归并 `offcpu_stash/offcpu_time`、runq 延迟 `runq_st` | **on_cpu_ns/switches 全量**；off-CPU/runq 分支 `deep_mode && tid∈targets`（+offcpu 限流 1/16/s） |
| `tp_btf/sched_wakeup` + `sched_wakeup_new` | on_wakeup / on_wakeup_new | `wakeup_ts[tid]=now`（runq 延迟起点） | `deep_mode && tid∈targets` |
| `tp_btf/block_rq_insert` | on_rq_insert | `blk_req[rq]={insert_ts,dev,pid,rw}` 暂存 | 全量 |
| `tp_btf/block_rq_issue` | on_rq_issue | `blk_req[rq].issue_ts=now` | 全量 |
| `tp_btf/block_rq_complete` | on_rq_complete | `block_io[pid]{ops,bytes,lat_sum,hist13}` + `dev_io[dev]`；await=issue−insert；删暂存 | 全量（IRQ ctx，pid 取自暂存） |
| `kretprobe/handle_mm_fault` | fault_ret | `faults[tid]{minor,major}`（VM_FAULT_MAJOR=0x4） | 全量 |
| `tp_btf/mm_vmscan_kswapd_wake/sleep` | on_kswapd_wake/sleep | `mem_events.kswapd_active` | 全量（无 tid 概念） |
| `tp_btf/mm_vmscan_direct_reclaim_begin/end` | on_direct_reclaim_begin/end | `mem_events.direct_reclaim / nr_reclaimed` | 全量 |
| `tp_btf/mark_victim` | on_mark_victim | `oom_events[64]` 环形 + seq | 全量 |
| `tp_btf/contention_begin/end`（≥6.0，无条件存在） | on_contention_begin/end | `lock_wait[tid]` 暂存 → `lock_st[tid]{waits,lat,hist13}` + `lock_hot[addr]` | 全量 |
| `<6.0 降级 kprobe/kretprobe __mutex_lock_slowpath` | mutex_lock_slow / _ret | 同上 | 全量 |
| `iter/task` | task_iter | 全进程/线程表（pid,tgid,comm,state,start,utime,stime,nvcsw,nivcsw,total_vm） | 全量（host 1s 读，用户态截 top-200） |
| `syscall`（≥6.4）/ `perf_event`（<6.4） | arm_snapshotter / snapshotter | 飞行记录器（见 §7） | **逐 targets 迭代** |

### 3.2 DEEP-only（DEEP 入口 attach 链接，退出 destroy）

| SEC（挂载点） | 程序名 | 采集内容 → 写 map | 过滤 |
|---|---|---|---|
| `tp_btf/sys_enter`（raw_syscalls/sys_enter） | on_sys_enter | `sys_start[tid]={id,ts,futex_wait}` 暂存 | **`tid∈targets` 先查后写**；futex 路由按 `__NR_futex`+WAIT/WAIT_BITSET |
| `tp_btf/sys_exit` | on_sys_exit | `sys_lat[{tid,id}]{count,lat,hist64}`、`syscall_caller[{id,user_sid}]`、`sys_st[tid]`、futex→`futex_st[tid]` | **`tid∈targets` 先查后写**（显式 gate） |
| `perf_event`（profiler 99Hz×每核） | oncpu | `oncpu_count[{pid,user_sid,kernel_sid}]` + `stackmap`（user 64 帧 / kernel 127 帧） | `tid∈targets` |
| `kprobe/vfs_read` | do_vfs_read | `io_file[{dev,ino,path}]{bytes,ops}` | `deep_mode && tid∈targets && 采样 1/N` |
| `kprobe/vfs_write` | do_vfs_write | 同上 | 同上 |
| `fentry/security_file_open` | file_open_path | `open_path[{dev,ino}]=bpf_d_path(buf,256)` | **`deep_mode && tid∈targets`**（已补 target gate） |

### 3.3 内核侧总成本（实测，见 §9）

BASE ≈ 22% 核 / DEEP ≈ 54% 核（仅 BPF 程序体，5.15 降级机）。

## 4. Map 清单（名字冻结）

| map | 类型 | 键 → 值 | 用途 |
|---|---|---|---|
| targets | HASH 4096 | u32 tid → u32 flags(1=pinned/2=dynamic) | **唯一 top-k 集合**，采集门控 |
| task_meta | HASH 4096 | u32 tid → {tgid, comm[16]} | 记录器元数据 |
| on_cpu_ns | PERCPU_HASH 4096 | tid → u64 | 在核 ns（累积） |
| switches | PERCPU_HASH 4096 | tid → {vol,invol} | 切换计数 |
| block_io | PERCPU_HASH 4096 | tid → {ops,bytes,lat_sum,hist13} | 进程块 IO |
| faults | PERCPU_HASH 4096 | tid → {minor,major} | 缺页 |
| lock_st / sys_st / futex_st / runq_st | PERCPU_HASH 4096 | tid → {count,lat_sum,hist13} | 锁/系统调用/futex/runq 等待 |
| dev_io | PERCPU_HASH 256 | dev → blk_io_t | 设备 IO |
| deep_enabled | ARRAY 1 | u32 | DEEP 门控 |
| ring_head / snapshot_cfg / ncpus / arm_cmd / sample_rate_cfg / oom_seq | ARRAY 1 | 控制 | 记录器/采样率控制 |
| timer_map | ARRAY 1 | {bpf_timer} | ≥6.4 定时器 |
| recorder | ARRAY 32768 | snapshot_rec（~200B） | 飞行记录环形 |
| scratch | PERCPU_ARRAY 1 | snapshot_rec | 记录暂存 |
| mem_events | ARRAY 1 | {kswapd_active,direct_reclaim,nr_reclaimed} | 内存压力 |
| oom_events | ARRAY 64 | {ts,pid} | OOM 环形 |
| ratelimit | PERCPU_ARRAY 1 | {last_ts[4]} | offcpu/iofile 限流 |
| last_run_ts / cur_tid | PERCPU_ARRAY 1 | u64 / u32 | sched 在核归属 |
| blk_req | HASH 65536 | request* → {insert_ts,issue_ts,dev,pid,rw} | 块 IO 匹配暂存 |
| wakeup_ts | HASH 4096 | tid → u64 | runq 延迟起点 |
| offcpu_stash | HASH 4096 | tid → {out_ts,ksid} | off-CPU 暂存 |
| sys_start | HASH 4096 | tid → {id,ts,user_sid,futex_wait} | syscall 配对 |
| lock_wait | HASH 4096 | tid → {lock_addr,ts,flags} | 锁等待配对 |
| sys_lat | PERCPU_HASH 16384 | {tid,id} → {count,lat_sum,hist64} | syscall 热点 |
| syscall_caller | HASH 16384 | {id,user_sid} → u64 | 调用者分布 |
| oncpu_count | HASH 16384 | {pid,user_sid,kernel_sid} → u64 | on-CPU profile |
| offcpu_time | HASH 8192 | {tid,ksid} → u64 | off-CPU 累计 |
| io_file | PERCPU_HASH 16384 | {dev,ino,path[256]} → {bytes,ops} | 热点文件 |
| open_path | HASH 8192 | {dev,ino} → char[256] | 打开路径缓存 |
| lock_hot | HASH 4096 | u64 addr → {count,lat_sum} | 热点锁 |
| stackmap | STACK_TRACE 16384 | u32 sid → u64 ip[127] | 栈去重 |

## 5. top-k 选择与过滤（重点）

### 5.1 唯一 top-k = `targets` map（两档：进程表 + 每进程线程）

- **两档结构**：`targets` map 存**线程 tid** = 选中的 top-K 进程 × 每进程 top-`per_proc_threads` 线程；K = `thread_budget / per_proc_threads`。
- **硬件自适应**（`Probe()`）：读 logical CPU、cgroup `cpu.max` 配额、`cpuset`、`MemTotal`、recorder 环形容量，得 **有效并发** `eff_cpus = min(online, quota, cpuset)`；线程预算 `thread_budget = clamp(min(eff_cpus×concurrency_factor, ring_slots/backlog_ticks), min_targets, max_targets)`（auto_scale 开）。4 核 VM：eff_cpus=4 → 8 线程 → 2 进程 × 4 线程。
- **滑动窗口计分**：每次 eval 推一帧全量 per-tid 累计计数器快照，`delta = 当前帧 − 窗口内最老帧`（跨度 `window_seconds=30`），杜绝瞬时尖峰抖动。评分公式：
  `score = w.cpu·cpu_util + w.switch·sat(sw_rate/1e4) + w.io·(sat(io_rate/1e4)+sat(io_bw/1GiB))/2 + w.fault·sat(fault_rate/1e4) + w.lock·sat(lock_rate/1e3)`（`cpu_util=Δon_cpu_ns/窗口`，各分量 sat 到 [0,1]）。
- **进程级滞回**：进程 rank ≤ `enter_rank` 连续 `hold_periods` 期入榜；rank > `leave_rank` 连续 N 期且驻留 ≥ `min_residency` 出榜；pinned 进程永不退出。
- **线程级**：每个选中进程取窗口内 score 最高的 `per_proc_threads` 个线程（pinned tid 恒在内）。
- **兜底冷启动**：首个计分周期成员为空 → 强制把 rank-1 进程纳入并取 top `per_proc_threads` 线程（保证记录器不空）。
- 成员变更 = 只改 `targets`/`task_meta` map，**从不 attach/detach**；写 `targets.log`。

### 5.2 过滤矩阵：哪些数据全量、哪些按 targets 门控

| 数据 | 阶段 | 过滤 | 理由/说明 |
|---|---|---|---|
| on_cpu_ns / switches / block_io / faults / lock_st（逐 tid） | 常驻 | **全量（所有 tid）** | 必须全量才能给 top-k 排名；这是评分源的原始数据，不是“top-k 过滤” |
| dev_io / mem_events / oom_events | 常驻 | 全量 | 无 tid 概念（设备/内存事件） |
| task_iter 进程表 | 常驻 | 全量 → 用户态截 top-200 | 异常特征用 |
| 飞行记录器 recorder | 常驻 | **逐 targets 迭代** | 每个 target 一条 `snapshot_rec`/tick |
| wakeup_ts / runq_st（调度延迟） | DEEP | `deep && tid∈targets` | |
| offcpu_stash / offcpu_time | DEEP | `deep && tid∈targets && 限流` | 1/16 次/线程/秒 |
| sys_start / sys_lat / syscall_caller / sys_st / futex_st | DEEP | `tid∈targets`（sys_enter 先查） | |
| oncpu_count + stackmap | DEEP | `tid∈targets` | |
| io_file（vfs_read/write） | DEEP | `deep && tid∈targets && 1/N 采样` | |
| open_path（file_open_path） | DEEP | `deep && tid∈targets` | 为 io_file 提供路径 |

**结论**：细粒度采集（记录器 + DEEP 全部结果 map + open_path）全部按唯一 top-k（`targets`）在内核门控，无脱靶点；唯一的全量 per-tid 计数器（on_cpu_ns/switches/block_io/faults/lock_st）是 top-k 排名的评分源，属必要全量。

### 5.3 其余 top-N（已收敛到唯一 top-k）

异常特征向量的拆分已统一引用 `targets`：`EbpfCounters.per_tid` = 选中线程；`AnomalyFeatures.top_tasks` = 选中进程（每进程聚合一行）。不再有独立的 top-200/32/64 过滤。全量项仅剩：评分源 per-tid 计数器（必要）与 `last_host.procs` 主机摘要（top-200，供模型参考，非诊断 top-k）。

## 6. 数据流与输出文件（会话目录 `<out>/<YYYYmmdd-HHMMSS>_<pid>/`）

| 文件 | 内容 | 频率 |
|---|---|---|
| base_host.jsonl | HostSnapshot（cpu/load/mem/vm/psi/disk/procs） | 1s |
| base_anomaly.jsonl | 异常特征向量（发给模型那份） | 1s |
| targets.log | join/leave 事件 | 变更时 |
| memory_events.txt | mem_events 变化 + OOM | 变化时 |
| io_devices.txt | dev_io 累积（hist13） | 1s |
| bpf_stats.jsonl | 每 BPF 程序 run_cnt/run_time_ns/avg_ns | 1s |
| proc_overhead.jsonl | getrusage CPU/切换/缺页 + RSS/HWM | 1s |
| log.txt | 运行日志 | 事件 |
| deep/<N>/meta.json | DEEP 元数据（start/end/indicators） | DEEP 入口 |
| deep/<N>/pre_series.jsonl / post_series.jsonl | 飞行记录器窗口（CanonicalSnapshot） | 100ms/20ms |
| deep/<N>/host_series.jsonl | DEEP 期间主机序列 | 1s |
| deep/<N>/on_cpu.folded / off_cpu.folded | 折叠栈（含计数/时间） | DEEP 末 |
| deep/<N>/syscall_hotspot.txt / lock_contention.txt / runq_latency.txt / io_files.txt | 各自热点 | DEEP 末 |
| deep/<N>/summary.txt | 异常起止、指示、汇总 | DEEP 末 |

## 7. 飞行记录器协议

- 内核驻留单生产者环形 `recorder`（ARRAY 32768 × ~200B ≈ 6.5MB），槽位 seqlock（seq 偶=提交）。
- 记录 `snapshot_rec`：seq/ts_ns/tgid/tid/comm + BASE 字段（on_cpu_ns、sw_vol/invol、io{ops,bytes,hist13}、pf{minor,major}、lock{waits,lat,hist13}）+ DEEP 字段（syscall/futex/runq 的 count/lat/hist13，BASE 期为 0）+ flags(bit0=deep tick)。**计数器全为累积值，主机侧算 delta**（丢失槽位不损坏序列）。
- 两种生产模式：
  - **≥6.4（openKylin 6.6）**：`bpf_timer` 单回调 `snap_tick`，每 tick 用 `bpf_for_each_map_elem(&targets)` + `bpf_map_lookup_percpu_elem` 逐 target 跨 CPU 求和 → 1 条求和记录/target/tick；主机按需读窗口。
  - **<6.4（5.15 开发机）**：无 percpu-lookup 助手，改 per-CPU `PERF_COUNT_SW_CPU_CLOCK` perf-event `snapshotter`，每 CPU 记本 CPU 切片，主机合并。
- BASE 周期 `fine_interval_ms=100`，DEEP `deep_fine_interval_ms=20`；读侧：DEEP 入口一次性抽取 `[now−pre, now]` 窗口，DEEP 中每 `deep_dump_interval_ms` 增量 drain；环满覆盖由 seqlock 检查兜底。

## 8. 运行时控制面

- SIGHUP → 重读 config（`sample.*`/`window.*`/`targets.*` 热生效；`misc.*` 启动期固定）。
- SIGUSR1 / SIGUSR2 → 手动进入/退出 DEEP（无模型 benchmark 用）。
- SIGINT/SIGTERM → 干净退出（DEEP 先 finalize 再恢复 BASE，恢复 `kernel.bpf_stats_enabled` 原值）。

## 9. 实测开销基线（2026-08-28，5.15 共享开发机，非评测 VM）

| 阶段 | 内核 BPF 本体（ms/s，=单核%） | 用户态进程 CPU | 主导项 |
|---|---|---|---|
| BASE | 221.9 = **22.2%** | **14.9%** | on_switch 110 / fault_ret 45 / snapshotter 32 / task_iter 26 |
| DEEP | 543.9 = **54.4%** | **25.3%** | snapshotter 144 / on_switch 125 / sys_exit 102 / sys_enter 61 / fault_ret 43 / file_open_path 19 / oncpu 7 |

（逐程序明细与口径见 `docs/overhead-baseline-20260828.md`。）

## 10. 已解决（2026-08-29 对齐用户意图）

1. ✅ 硬件自适应 top-k：`Probe()` 读 logical CPU + cgroup quota/cpuset + MemTotal + ring 容量 → 有效并发 → 线程预算。
2. ✅ 唯一 top-k（两档）：进程表 top-K + 每进程 top-P 线程；`per_tid`/`top_tasks` 直接引用 `targets` 成员，删除独立 top-200/32/64。
3. ✅ 滑动窗口选择：`window_seconds` 内累计计数差值计分 + 进程级滞回，仅 `eval_interval_ms` 重评。
4. ✅ DEEP 全量内核过滤：`file_open_path` 与 `on_sys_exit` 已补 `tid_is_target` 内核 gate。
