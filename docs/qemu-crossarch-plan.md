# QEMU 多架构验证计划（openKylin 2.0 SP2 × 4 架构）

## 调研结论（2026-09-05）

**QEMU 能跑 eBPF 吗？能。** eBPF 子系统（校验器/JIT/BTF/map/挂载点）是
**客户机内核自身**的功能，QEMU 只提供 CPU/内存/设备层，与 BPF 无耦合：

- **KVM 模式（同架构硬件虚拟化）**：客户机内 BPF 以原生速度运行，等价于
  真机；宿主只需 CPU 虚拟化扩展。
- **TCG 模式（异架构指令模拟）**：BPF 同样功能完整 —— 客户内核的 BPF
  JIT 先把字节码编译成客户机架构指令，TCG 再逐条模拟；慢（约 10–50×），
  但功能/语义与真机一致，适合功能验证（本项目评分点正是「多平台能跑」，
  性能不敏感）。
- **不同内核**：QEMU 引导任意内核镜像 —— 同一磁盘镜像换 vmlinuz/initrd
  即可测 6.6 LTS / 7.0 等多个内核版本，天然支持内核矩阵。

前提条件全在客户机侧：`CONFIG_DEBUG_INFO_BTF=y`（openKylin 官方内核自带）、
`CONFIG_BPF=y`、root 或 CAP_BPF/CAP_PERFMON。宿主侧无特殊要求。

## 验证矩阵

| 架构 | QEMU 后端 | 加速 | 镜像（openKylin 2.0 SP2） | 备注 |
|---|---|---|---|---|
| amd64 | qemu-system-x86_64 | KVM（本机） | 官方 ISO/镜像 | 真机已覆盖，作为对照基线 |
| arm64 | qemu-system-aarch64 | TCG | aarch64 镜像 | virt 机器，UEFI 启动 |
| loongarch64 | qemu-system-loongarch64 | TCG | loongarch64 镜像 | virt 机器，qemu ≥ 8 |
| riscv64 | qemu-system-riscv64 | TCG | riscv64 镜像 | 需 OpenSBI/U-Boot 引导，qemu ≥ 7 |

## 每架构验证内容（评分口径：多平台适配 10 分）

1. `scripts/setup_openkylin.sh` 一键装环境（跨架构包名一致；stress-ng/fio
   源码构建天然跨架构；clang-22/gcc/libbpf-dev 在 openKylin 各架构仓库均可用）。
2. `./scripts/build.sh` 编译采集器 + BPF 对象（CO-RE 单对象，无需改代码；
   cmake 已识别 x86_64/aarch64 的 `__TARGET_ARCH_*`，loongarch64/riscv64
   需补两行 token，见下）。
3. BASE 冒烟：`--run-seconds 30`，会话库产出、host 表非空。
4. 单场景注入（CPU stress-ng 60s）：mock 模型触发 DEEP → deep_episodes ≥ 1
   → diagnosis.json 存在。

## 已知适配点（代码级）

- `cmake/bpftool.cmake`：`CMAKE_SYSTEM_PROCESSOR` 只映射 x86_64/aarch64 →
  `__TARGET_ARCH_x86/arm64`，需增加 loongarch64 → `__TARGET_ARCH_loongarch`
  （BCC 风格 token 为 `__TARGET_ARCH_loongarch`）、riscv64 →
  `__TARGET_ARCH_riscv`（对应 BPF 源中按架构分支的取样器代码，若存在）。
- 宿主侧 `/proc` 解析与 SQLite 均为架构无关 C++，无待适配项。
- TCG 下 `stress-ng --cpu 2 --timeout 90` 实际耗时可能 ×N，注入脚本需放宽
  超时（按架构配置 `STRESS_SCALE` 环境变量）。

## 执行计划（后期阶段，不阻塞当前联调）

1. 下载 openKylin 2.0 SP2 四架构镜像（openkylin 官网/镜像站）。
2. 脚本 `scripts/qemu/<arch>.sh`：qcow2 覆盖层 + 端口转发 + cloud-init 或
  首次启动注入 `setup_openkylin.sh`。
3. 每架构跑「验证内容」四步，产物归档 `out_qemu/<arch>/`（会话 SQLite +
   诊断 JSON + 构建日志），作为多平台评分证据。
4. 内核矩阵（可选）：同镜像换 6.6 内核再跑一轮 BASE 冒烟。
