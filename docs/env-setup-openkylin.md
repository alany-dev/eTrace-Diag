# openKylin 环境部署记录（开发/运行环境一键安装）

本文记录在 openKylin 上部署 eTrace-Diag 开发与运行环境的完整过程，与
`scripts/setup_openkylin.sh` 一一对应。脚本本身就是可执行的部署文档；
本文补充每步的依据、排错记录与离线兜底方案。

**验证基线**：openKylin 3.0 (huanghe)，kernel `7.0.0-2-generic`，x86_64，
8 核 / 7GB / 40GB。赛题评测基线为 openKylin（kernel 6.6+）。

## 一键安装

```bash
cd eTrace-Diag
sudo ./scripts/setup_openkylin.sh              # 完整：工具链 + stress/fio + 模型环境
sudo ./scripts/setup_openkylin.sh --skip-python  # 只要采集器工具链
```

脚本幂等，可重复执行。完成后自检输出 kernel BTF、clang/cmake/bpftool/fio/
stress-ng 版本。

## 步骤与依据

### 1. 系统包（apt）

| 包 | 用途 |
|---|---|
| clang-22 | BPF 目标编译（etrace.bpf.o；仅需驱动，不装 llvm 元包） |
| cmake gcc g++ make pkg-config | C++20 采集器构建 |
| libbpf-dev libelf-dev zlib1g-dev | CO-RE 加载 / ELF / zlib |
| bpftool | 构建期 vmlinux.h 生成 + 运行期可选 |
| python3-pip python3-venv | 模型环境引导 |
| rsync git sqlite3 | 部署/源码/会话库 |

**排错 1**：`apt install stress-ng` 依赖 `libipsec-mb0 (>= 0.53)`，huanghe
仓库未发布该包，apt 事务整体回滚（其余包也不会装上）→ stress-ng 改为源码构建
（见步骤 2）。

**排错 2**：`llvm` 元包 → `llvm-22` → `libpfm4`（huanghe 仓库未发布）→ 安装
失败。本项目的 BPF 构建只用 `clang -target bpf`（不调用 llvm-strip/opt/llc），
故只装 `clang-22`（其依赖树无 libpfm4）。

**排错 3**：sources 里 `huanghe-proposed` 口袋的 gcc-15 等基础包版本与 main
的 `-ok3` 固定版本冲突（"Reached two conflicting assignments"），脚本已禁用
该口袋（注释 `/etc/apt/sources.list` 中 huanghe-proposed 行）。

**排错 4**：`kdump-tools` 的 kernel postinst 钩子构建 kdump initramfs 在
VM 中失败（`mkinitramfs: failed to determine device for /sysroot`），导致
`dpkg --configure -a` 报错、apt 事务尾部失败。工具链不需要 kdump →
脚本直接移除该包与残留钩子脚本再 `dpkg --configure -a`。

**排错 5**：huanghe 仓库 clang-22 索引陈旧（`Depends: libllvm22 (= 1:22.1.1-1ok1.1)`，
该版本 deb 已从 pool 下线，现存 `1:22.1.2-ok4`）→ apt 无法解析。本项目
BPF 构建只用 clang 驱动（不用 llvm-strip）→ 脚本改从 Ubuntu noble 的
USTC 镜像装 `clang-18`（libllvm18 版本隔离，与系统 libllvm22 不冲突），
并链接 `/usr/local/bin/clang`。（备选：llvm.org 官方 tarball —— 实测
github release 大文件下载超时，放弃。）

### 2. stress-ng（源码构建）

openKylin 仓库不可装；`github.com/ColinIanKing/stress-ng` V0.17.06 源码
`make -j$(nproc) && make install`。前置 `libaio-dev zlib1g-dev`。

### 3. fio（源码构建）

openKylin 仓库无 fio 包。`github.com/axboe/fio` tag `fio-3.36`：
`./configure --prefix=/usr/local && make -j$(nproc) && make install`。
前置 `libaio-dev`。赛题要求 §47 的 I/O 注入脚本依赖 fio。

### 4. uv（pip 引导）

`pip3 install --break-system-packages uv`；astral.sh 在线安装脚本为备选
（部分网络下 astral.sh 被拦截时 pip 引导更稳）。

### 5. 模型依赖（uv sync）

`models/` 下 `uv sync --extra dev --extra torch`：
- 核心 CPU 路径：numpy/scipy/pandas/sklearn/fastapi/uvicorn/websockets；
- `torch` extra：`time-rcd`（git 源 `github.com/thu-sail-lab/Time-RCD`）+
  torch CPU —— Time-RCD-Fuse 实机检测器的运行时。

### 6. Time-RCD checkpoint 预取

`TimeRCDDetector.from_pretrained(variant='multi')` 首次调用从
`huggingface.co/thu-sail-lab/Time-RCD` 下载。huggingface.co 不可达时
（验证机实测 000），用 `HF_ENDPOINT=https://hf-mirror.com` 走国内镜像。

## 网络依赖矩阵（验证机实测）

| 目标 | 状态 | 兜底 |
|---|---|---|
| archive.build.openkylin.top（apt） | ✅ | — |
| pypi.org / files.pythonhosted.org | ✅ | 可换 TUNA/清华 PyPI 镜像 |
| github.com（git clone / tarball） | ✅ | — |
| codeload.github.com | ❌ 000 | 不影响（git clone 走 github.com） |
| huggingface.co | ❌ 000 | `HF_ENDPOINT=https://hf-mirror.com` |
| astral.sh | ✅ | pip 引导 uv |

## sudo 无 NOPASSWD 时的执行方式

验证机 sudo 需要密码。以密码管道执行：

```bash
echo '<password>' | sudo -S -p "" bash scripts/setup_openkylin.sh
```

建议正式环境给部署账号配置 NOPASSWD 或直接以 root 执行。

## 内核要求

- 采集器需 `CONFIG_DEBUG_INFO_BTF=y`（`/sys/kernel/btf/vmlinux` 存在；
  验证机 7.0.0-2-generic 已带 BTF，7MB）。
- 权限：root 或 `CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN`。
- openKylin 3.0 内核 7.0：rss_stat 为 percpu_counter（见
  `docs/known-limitations` 与 `bpf/etrace.bpf.c` 注释），RSS 由宿主侧补读。

## QEMU 多架构验证（后续加分项）

见 `docs/qemu-crossarch-plan.md`：openKylin 2.0 SP2 的 amd64/arm64/
loongarch64/riscv64 四架构 QEMU 矩阵，用于多平台适配评分的功能验证。
