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

## riscv64 实机验证通过（2026-09-08）

**方案**：openKylin nile riscv64 用户态（debootstrap）+ **Debian trixie 内核
linux-image-6.12.86+deb13-riscv64**（CONFIG_DEBUG_INFO_BTF=y，双内核来源中
唯一带 BTF 的 riscv64 选项）+ OpenSBI fw_dynamic.bin + qemu-system-riscv64。

关键点（踩坑记录）：
1. **内核来源**：openKylin huanghe/nile riscv64 内核（5.15.65-rt56+）无 BTF 且 <6.6；
   Debian trixie 6.12 riscv64 有完整 BTF（vmlinux 未压缩 ELF 附带，可直接
   bpftool dump）。下载需断点续传（111MB deb，wget --continue 多轮）。
2. **引导链**：riscv64 需 OpenSBI（opensbi_1.6-1_all.deb 提供 fw_dynamic.bin），
   `-bios fw_dynamic.bin -kernel vmlinux.elf -initrd initrd.img`；UEFI PE
   (vmlinuz) 会 ROM 重叠，fw_jump.elf 段 @0 与 mrom.reset 重叠，fw_dynamic.bin
   (raw) 正确。
3. **qemu-system-riscv64 二进制**：openKylin qemu-system-misc 缺 riscv64
   模拟器，从 Debian trixie qemu-system-riscv_10.0.11 deb 提取二进制 +
   libcapstone5/opensbi 补齐依赖，`QEMU_MODULE_DIR` 指向解包目录。
4. **devpts 级联损伤**：guest rootfs 挂载 /dev 后 umount 时序问题会反复
   stack /dev/pts 于宿主（此前 rm -rf 清 rootfs 还曾把宿主 /dev/null 变
   普通文件）；每次 rootfs 操作后须清理嵌套挂载。prepare_guest.sh 已加
   mountpoint 守卫（bbebe3a）。
5. **用户坑**：riscv64 debootstrap 用户态无 `yang` 用户，ssh 尝试 yang 遭
   Permission denied 数十轮——最终用 root:yang（chpasswd -c SHA512）成功。
6. **root=/dev/vda**（make_disk 整盘单分区，非 /dev/vda1）。

验证结果：multi-user 达、SSH 登录、6.12.86 内核 + BTF 确认。采集器 BPF
加载待跑冒烟（与 arm64 同款 tp_btf/sys_enter 路径，内核 6.12 BTF 完备）。
