# LoongArch64 / RISC-V64 适配评估（2026-09-07）

结论先行：**BPF 代码层适配已完成**（bpf/etrace_loongarch64.bpf.c、bpf/etrace_riscv64.bpf.c，
cmake 按架构自动选择）；**阻塞在 openKylin nile 仓库的内核构建配置**，非代码问题。

## 已完成
1. 每架构 bpf.c（用户方案）：syscall 入口/出口用 tp_btf/sys_enter + sys_exit
   tracepoint（BPF 程序与 arm64 已验证的完全一致），架构差异仅剩 futex
   wait-flag 的寄存器读取一个宏：
   - loongarch64: regs[5] (a1)，ETD_NR_FUTEX=98
   - riscv64: a0，ETD_NR_FUTEX=222
   - 其余 sched/block/mm/lock/net/file 程序全部共享 etrace_common.h（同一套采集逻辑与指标）
2. cmake/bpftool.cmake 按 CMAKE_SYSTEM_PROCESSOR 选源文件；交叉语法检查通过
   （除 host-x86 vmlinux 缺目标架构 user_pt_regs 的预期伪差异，实机构建用各自 vmlinux 不受影响）
3. qemu-user-static 8.2.2 已装（qemu-loongarch64-static/qemu-riscv64-static），
   debootstrap stage2 路径可行；nile 仓库 binary-loong64 / binary-riscv64 均 200

## 阻塞：内核 CONFIG_DEBUG_INFO_BTF 未启用（实测包内 config）
- loong64  linux-image-6.6.0-15-generic 6.6.0-15.0ok13: **CONFIG_DEBUG_INFO_BTF is not set**
- riscv64  linux-image-5.15.65-rt56+-3:   **CONFIG_DEBUG_INFO_BTF is not set**（且内核 <6.6）
- 采集器为 CO-RE 实现，无 BTF 无法加载（代码 fail-fast + 明确报错，行为正确）
- 对照：同版本 x86_64/arm64 6.6.0-15.0ok13 内核均带 BTF，guest 验证通过

## 可行路径（供决策）
A. 换用带 BTF 的 loong64/riscv64 内核（AOSC/openEuler/Debian 的 6.6+ 内核均可），
   openKylin 用户态不变 —— 改动仅 prepare_guest.sh 的 KERNELURL 常量
B. 本地用 pahole 为 loong64/riscv64 vmlinux 生成 BTF 并附加（vmlinux+modules 需重新
   打包，可行但偏离"用户实测发行版"口径）
C. 维持现状：matrix.sh 覆盖 x86_64/arm64 两架构实机；loong64/riscv64 代码就绪，
   等上游内核开 BTF 后零改动接入

当前采纳 C（代码就绪 + 文档记录），A 作为赛题演示的推荐增强。

## openKylin 3.0 (huanghe) 实测（2026-09-07 追加）

按"试试 openKylin 3.0"实测 huanghe 套件（架构列表 amd64 arm64 i386 loong64 riscv64 rv64g）：

| 架构 | 内核包 | 版本 | BTF |
|---|---|---|---|
| loong64 | linux-image-6.6.0-20-generic | 6.6.0-20.0ok1 | **无**（config 无该行 + vmlinuz 解压扫描无有效 BTF 头） |
| loong64 | linux-image-unsigned-7.0.0-2-generic (proposed) | 7.0.0-2.0ok7 | **无** |
| riscv64 | linux-image-5.15.65-rt56+ | 5.15.65-rt56+-3 | **无**（且 <6.6） |

验证方法：config-6.6.0-20/7.0.0-2 内 `CONFIG_DEBUG_INFO_BTF` 缺失；解压 vmlinuz
（gzip 全量解压）扫描 BTF 魔数 0xEB9F + 合法头（ver=1, hdr_len∈{24,32}）均未命中；
modules 包内亦无 *.btf。对照组：同机 x86_64 主机内核 7.0.0-2-generic 有 BTF
（CONFIG_DEBUG_INFO_BTF=y，/sys/kernel/btf/vmlinux 7.08MB）。

**结论：openKylin 官方源 loong64/riscv64 全系（2.0 nile 与 3.0 huanghe）均未启用
BTF，属发行版内核构建策略，升级大版本无法解决。** 要跑通 loong64/riscv64 必须：
1. 换带 BTF 的第三方内核（Debian trixie+ 内核 6.12/7.1 loong64/riscv64 均
   默认 BTF；openEuler 24.03 loongarch 同），openKylin 用户态不动；或
2. 重编 openKylin 内核（开 CONFIG_DEBUG_INFO_BTF）——需要上游源码与构建环境。

bpf 代码层（etrace_loongarch64.bpf.c / etrace_riscv64.bpf.c）已就绪，内核一到位
`matrix.sh loong64|riscv64` 即可复用全流程。
