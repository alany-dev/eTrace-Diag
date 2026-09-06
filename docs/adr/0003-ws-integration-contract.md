# ADR-0003: WebSocket 联调契约（采集器 ↔ 模型服务）

- 状态：已采纳（2026-09-05）

## 背景

采集器已有依赖零库的 WS 客户端（`src/model/ws_client.*`）与协议 v1：两个端点
分别承载异常打分与因果推理（mock 服务端在 `scripts/mock_model.py`）。模型侧
只有 FastAPI HTTP 面（`/v1/score`、`/v1/causal/analyze`、`/v1/feedback`、
`/v1/incidents/{id}`），无 WS 端点。需要为联调建立单一、双方共同实现的 WS 契约。

## 决策

1. **单服务双端点**：模型侧新增 WS 路由 `ws://<host>:9000/anomaly` 与
   `ws://<host>:9000/causal`（一个 uvicorn 进程、一个端口）。采集器
   `config/default.json` 的 `model.anomaly.url` / `model.causal.url` 默认改为该端口。
   旧 mock 双端口（9001/9002）保留供采集器独立回归测试。
2. **/anomaly 协议（v1 不变）**：
   - 请求：`{v, seq, ts_ns, host, ebpf, top_tasks, network, gpu, cgroup}`（AnomalyFeatures JSON）。
   - 响应：`{v:1, seq, ts_ns, is_anomaly, type, confidence, indicators:[{type, confidence}]}`。
   - 实机检测器 = **Time-RCD-Fuse**（冻结 HF checkpoint `thu-sail-lab/Time-RCD`
     + Robust-z w=0.3 + median-k5），新增运行时模块
     `src/alg_models/detection/time_rcd_fuse.py` 注册进 DETECTOR_REGISTRY。
   - 预热：连接建立后先缓冲 `warmup_seconds`（默认 90s）BASE 流，用缓冲段统计
     通道 med/MAD/q99 与融合归一化参数；预热期间一律 `is_anomaly=false` 并附
     `indicators:[{type:"warmup", confidence:0}]`。
   - 打分节奏：按 `stride_ns`（默认 30s）滑窗打分一次，非逐 tick（控制 CPU 开销）。
   - 异常类型映射：Robust-z 逐通道最大离差 → 通道组（cpu/io/mem/lock/net 五组）
     取最高组为 `type`；`indicators` 携带逐组置信度。
3. **/causal 协议**：
   - 请求：`{v, seq, window_start_ns, window_end_ns, body}`；`body` 由采集端打包
     证据本体（deep_series / deep_runq / deep_syscall / deep_lock / deep_iofile /
     oom_events 的序列化行 + anomaly 元数据），不再只是摘要计数。见 ADR-0004。
   - 响应：`{v:1, seq, ok, report:<CausalReport model_dump>}`——TORAI
     （`variant: fast` 默认）的完整结构化诊断。
4. **诊断落盘**：采集端解析 `report` 原样写入会话目录 `diagnosis.json`，并随
   summary 记入 SQLite；HTTP 面（/v1/*）保留不改（CLI、测试与反馈闭环仍用）。
5. **依赖**：`models/pyproject.toml` 新增 `websockets` 核心依赖；torch extra
   （含 time-rcd git 源）成为联调必需路径，openKylin 部署文档给出
   `uv sync --extra torch` 安装步骤。

## 后果

- 采集端变更点：evidence 打包、diagnosis.json 落盘、默认 URL 单端口。
- 模型端变更点：WS 路由 + Fuse 运行时模块 + body 解析适配（ADR-0004）。
- 风险：torch CPU 依赖使模型服务部署体积增大；打分已按 stride 降频，且
  采集器 BASE 自开销不受模型影响（模型是独立进程）。
