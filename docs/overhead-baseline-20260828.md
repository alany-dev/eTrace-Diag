# 实测开销基线 2026-08-28

> 环境：**共享高负载开发机**，kernel 5.15.0-105（非 4 核 6.6 评测 VM）。因此 `snapshotter` 走 per-CPU 采样降级路径，`on_switch/fault_ret/sys_enter/sys_exit` 等系统级 tap 成本随整机负载放大。评测环境数值应显著低于此处。
> 方法：`kernel.bpf_stats_enabled=1` + `bpf_prog_info.run_cnt/run_time_ns`（每程序累计执行次数/时间，含 helper，不含 trampoline/中断/cache 污染）；用户态用 `getrusage` + `/proc/self/status`。原始数据在会话目录 `bpf_stats.jsonl` / `proc_overhead.jsonl`。

## 会话

- BASE 12s：`out/20260828-170947_478291`
- BASE 4.1s + DEEP 13.1s（SIGUSR1 手动切入）：`out/20260828-173948_560816`

## BASE 内核逐程序（BPF 程序体，ms/s）

| 程序 | run_cnt(12s) | avg_ns | ms/s |
|---|---|---|---|
| on_switch | 1,083,864 | 1134 | 107.90 |
| fault_ret | 5,149,549 | 139 | 63.15 |
| snapshotter | 7,150 | 48159 | 30.69 |
| task_iter | 103,648 | 2928 | 25.68 |
| on_wakeup | 576,212 | 102 | 5.16 |
| on_rq_complete | 681 | 3394 | 0.21 |
| on_rq_insert / on_rq_issue | 677/680 | 1738/674 | 0.10/0.04 |
| mutex_lock_slow_ret / _slow | 445 | 2444/993 | 0.09/0.04 |
| on_wakeup_new | 482 | 1221 | 0.05 |
| **TOTAL** | | | **233.12 ms/s = 23.3% 单核** |

用户态：wall 11.22s，cpu 2.06s = **18.4% 单核**（user 0.38s / sys 1.69s）；RSS 25.8MB / HWM 33.5MB；voluntary csw 3/s。

## DEEP 内核逐程序（ms/s，13.09s 窗口）

| 程序 | run_cnt | avg_ns | ms/s | 备注 |
|---|---|---|---|---|
| snapshotter | 45,254 | 45486 | 144.42 | 20ms 周期 × 5.15 per-CPU 降级 |
| on_switch | 1,839,175 | 1209 | 124.74 | +DEEP off-CPU 分支 |
| on_sys_exit | 18,472,964 | 73 | 101.65 | 全机每次 syscall 都查 sys_start |
| on_sys_enter | 18,473,778 | 44 | 61.20 | 全机每次 syscall 先查 targets |
| fault_ret | 6,486,307 | 123 | 42.50 | |
| task_iter | 168,177 | 2835 | 25.22 | |
| file_open_path | 176,711 | 1439 | 19.37 | bpf_d_path |
| on_wakeup | 952,794 | 156 | 9.17 | |
| oncpu | 83,678 | 1066 | 6.76 | 99Hz×核 + 双栈 |
| do_vfs_read / do_vfs_write | 592,540 / 46,130 | 91/372 | 4.09/1.30 | 1/4 采样 |
| on_rq_insert/issue/complete | 13,225 | — | 1.05/0.48/1.65 | |
| **TOTAL** | | | **543.85 ms/s = 54.4% 单核** | |

用户态：BASE 段 wall 4.10s cpu 0.61s = 14.9%；DEEP 段 wall 13.09s cpu 3.31s = **25.3%**（sys 2.87s：深图 dump + 符号化）；RSS 25.9MB / HWM 37.7MB。

## 口径与警告

1. `run_time_ns` 只含程序体执行（含 map/helper），**不含** trampoline 入口出口、timer softirq、perf 中断、cache/TLB 污染。
2. 系统级 tap（sched_switch、handle_mm_fault、raw_syscalls）每事件必触发，成本随**整机**事件率走：本机 ~9.6 万切换/s、~46 万缺页/s、~141 万 syscall/s。
3. `snapshotter` 的 32/144 ms/s 是 5.15 无 `bpf_map_lookup_percpu_elem`/`bpf_timer` 的 per-CPU 降级产物；6.6 上为单 bpf_timer 求和模式，成本降一个量级（计划估值≈可忽略）。
4. 对业务的**系统净拖累**（评分口径）需另做 `perf stat -a` 加载/不加载对照，与本表为两套口径，不可直接相减。
