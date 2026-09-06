# ADR-0004: 因果证据适配（单机诊断到 TORAI 多模态输入）

- 状态：已采纳（2026-09-05）

## 背景

TORAI 原生面向微服务系统：`service` 为粗粒度实体，三模态
（metric / log / trace_lat / trace_err）各自按 `service` 聚合，fine→coarse 以
`service = prefix before first '_'` 约定。本工具诊断对象是**单机**：宿主 +
进程/线程 + 块设备。必须把采集器的深采证据映射为 TORAI 可消化的实体与模态，
且缺失模态按 severity 0 处理（盲点语义，绝不把「没数据」当「没异常」）。

## 决策

1. **实体（service）命名**（不含下划线，兼容 TORAI fine→coarse 前缀约定）：
   - `host` —— 宿主级序列（CPU/内存/负载/上下文切换等 host 表指标）；
   - `proc<pid>` —— 进程级（deep_series per-target 进程行，如 `proc1234`）；
   - `dev<major>m<minor>` —— 块设备级（deep_iofile / io_devices，如 `dev8m0`）。
   fine 指标名 = `<entity>_<metric>`（如 `proc1234_cpu_pct`），TORAI 按首个
   `_` 取前缀聚合：实体名本身不得含下划线（`proc_1234_cpu` 会全部坍缩为
   服务 `proc`）。`localized=True` 下根因候选即这些实体。
2. **模态映射**（采集端打包进 CausalContext.body，模型端零 SQLite 依赖）：
   - **metric**：deep_series pre/post 窗口逐 tick 数值序列（CPU%、RSS、ctx_sw、
     page_fault、syscall 计数、runq 延迟、IOPS/await），每实体一列。
   - **log**：oom_events 行 + deep_syscall 热点条目，转 LogEvent(entity, template,
     attrs)；无 OOM/热点时该模态为空 → severity 0。
   - **trace_lat**：deep_runq 等待时间与 deep_syscall 耗时，合成 TraceSpan
     （start=dur 起点，end=+dur，service=对应实体）。
   - **trace_err**：futex/锁等待超时（deep_lock）与 syscall 错误事件，合成
     错误 span。
   - folded 栈与 on/off-CPU 画像不进 TORAI（作 narrative/证据链展示）。
3. **窗口与重采样**：TORAI `resample_s` 对单机调小（默认 15s 不变但可配置；
   联调按 episode 时长评估后定值）；anomaly 窗口 = PhaseManager 的
   `[anomaly_start − pre_anomaly_seconds, anomaly_end + post]`，
   `train/val` 从 BASE 段近期窗口切分（`split_by_time`）。
4. **失败语义**：无异常窗口（TORAI `_detect` 提不出 incident）→ 返回
   `ok=false` + `abstained_reason`，采集端照常落盘，不抛异常。

## 后果

- 采集端新增 evidence 打包器（SQLite 行 → body JSON），消息体积约百 KB~MB 级。
- 模型端新增 body 解析器（body JSON → TelemetryFrame/LogEvent/TraceSpan）。
- 单机实体规模（~数十实体）远小于微服务规模，GMM/Ψ-PC 计算量在联调时长内可控。
