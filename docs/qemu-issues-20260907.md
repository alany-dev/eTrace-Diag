# QEMU 多架构验证：问题与瓶颈快照

日期：2026-09-07（暂停时点）
范围：`eTrace-Diag/scripts/qemu/`（x86_64 openKylin 2.0 SP1 nile guest，TCG 软件模拟，宿主机 192.168.11.151）

## 背景目标
- 跨架构矩阵（x86_64 / arm64 / loongarch64 / riscv64）guest 内验证采集端：BTF、编译、mock WS 冒烟（对应 `docs/qemu-crossarch-plan.md`）。
- 验收脚本 `verify.sh` 在 guest 内执行：内核/BTF 检查 → 解包 repo → 装工具链 → 编译采集器 → mock_model 冒烟 → 结果写 `/root/verify-result.txt`。

## 已确认解决（不再阻塞）
1. **多架构 BPF 插桩宏**（用户提醒后已修，commit `26b1e11`）：
   - `bpf/etrace.bpf.c` 新增 `ETD_SYSCALL_ARG1` / `ETD_SYSCALL_ORIG_NR` 按架构分派（arm64: `regs[1]`/`__syscallnr`；x86_64: `si`/`orig_ax`），替换两处 x86-only 访问。
   - `cmake/bpftool.cmake` 补 `__TARGET_ARCH_loongarch` / `__TARGET_ARCH_riscv` token。
   - WSL 重建通过；远端重建通过；mock 回归通过（`regress_mock.sh 45` → `regression passed`）。
2. **debootstrap 非 merged-usr**：`--merged-usr` 已加入 `prepare_guest.sh`（先前 "Unmerged usr is no longer supported" 警告消除，apt 装包正常）。
3. **make_disk 直接在 qcow2 上 mkfs**（mke2fs "Not enough space to build proposed filesystem"）：已改为 raw→mkfs→copy→`qemu-img convert` 两段式（`lib.sh`）。
4. **WSL 侧 /tmp 满**（tmpfs 3.7G）：qemu-img convert 改到 `/home/yang` 分区；大 tar（5.2GB，含 models/.venv）改 gz + `--exclude models/.venv` 后 1.9MB。
5. **磁盘空间**：远端 40G 曾被 qemu 临时 raw 占满（编译 `No space left on device`）；已清理，现 25G 可用。

## 当前活跃问题（暂停时未解决）
### P0：guest 内 initrd 未生成（boot 链断裂）
- 现象：`rootfs/boot/` 只有 `initrd.img -> initrd.img-6.6.0-15-generic` **断链**；`initrd.img-6.6.0-15-generic` 不存在。prepare 结束 WARN "no initrd.img"。`boot/` 下只有 vmlinuz 提取成功，无 initrd → `-kernel` 直启无法挂 root。
- 根因：`prepare_guest.sh` 装内核包的 apt 列表**缺 `initramfs-tools`**（`dpkg/info | grep -c initramfs` = 0）。postinst 只建符号链接，update-initramfs 缺席，initrd 永不生成。
- 修复方向（已定，未执行）：
  1. apt 内核安装行追加 `initramfs-tools`；
  2. 安装后显式 `chroot "$ROOTFS" update-initramfs -k "$KVER" -c`（不依赖 postinst 重跑）；
  3. KVER 提取已有（`grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^ ]*'`）。
- 之后重跑 `prepare_guest.sh x86_64`（61s 级）→ `-kernel vmlinuz -initrd initrd.img` 启动 → SSH/verify 流程恢复。

### P1：verify.sh 上一轮遗留失败点（需 guest 起来后重验）
- 上一轮 `/root/verify-result.txt`：
  - `bpftool` 包名在 nile 不存在（`E: Unable to locate package bpftool`）→ 需包名探测（`libbpf-tools`? 直接源码编译 bpftool? 或从 build/ 产物带入）。
  - `cd /root/repo: No such file or directory` → 注入方式从"解包 tar 到 /root"改为"解包到 /root/repo"（tar 内是 `./` 前缀，需 `--transform` 或 mkdir+`--strip-components`）。
  - 工具链装包后仍缺 `cmake`（"cmake: command not found"）→ 上轮装包列表与实际 nile 源不匹配，需探测后安装或用 `--no-install-recommends` 全列表核对。
- `StandardOutput=tty` 输出不进 console.log → 结果只看 `/root/verify-result.txt`（已是现状，无需改）。

### P1：guest 控制台 login 循环噪音
- agetty `-o '-p -u root'`：openKylin 的 `/bin/login` 不认 `-u` → "invalid option" 无限刷屏。不影响 verify（service 在 multi-user 前执行），但污染 console.log。修法：去掉 `-u root`（autologin 已足够）或换 `--autologin` 参数组合。

## 流程性瓶颈（反复消耗时间的环节）
1. **disk inspect 循环**：guest 内 verify 失败 → 只能 pkill qemu → convert qcow2→raw → loop mount → 读 verify-result.txt → 修 → 重注入 → 重启（单轮 3-5 分钟，且 /tmp 满、qcow2 写锁、loop 设备残留等次生问题反复出现）。
   - 缓解（待做）：verify.service 保留串口输出重定向到第二串口/文件 + hostfwd SSH 直读，避免 disk 循环；或 `-serial file:` + 结果同时 `scp` 出来（guest 网络可用后）。
2. **repo 注入体积**：models/.venv 5GB 曾进 tar。固化排除清单：`build`, `out_*`, `.git`, `models/.venv`, `node_modules`。
3. **TCG 启动慢**：单轮 boot+verify ≈ 7 分钟（420s sleep 观察法）。多架构矩阵下这是串行墙钟大头；后续可用 `background` 并发 + boot 探测（console 轮询 "Reached target"）替代固定 sleep。

## 下一步（解除暂停后按序）
1. `prepare_guest.sh`：apt 列表加 `initramfs-tools` + chroot `update-initramfs -k $KVER -c`。
2. `verify.sh`（注入模板）：修 bpftool 探测、repo 解包路径（/root/repo）、cmake 断言。
3. `serial-getty@.service.d/autologin.conf`：去掉 `-u root`。
4. 重跑 `prepare_guest.sh x86_64` → boot → SSH 进 guest 直接跑 verify（不再 disk inspect）→ 确认 `VERIFY-PASS`。
5. x86_64 全通后复制流程到 arm64（qemu-system-aarch64 + qemu-user stage2），再 loongarch64/riscv64。
6. 回到主线任务：models 分支精简（ADR-0002/0004 待写）、WS 联调、异常注入 e2e、合并 main。
