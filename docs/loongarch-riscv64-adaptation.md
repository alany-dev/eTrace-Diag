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
