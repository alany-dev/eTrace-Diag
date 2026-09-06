# ADR-0001: dev_models 分支以 subtree 方式并入 main 的 models/ 目录

- 状态：已采纳（2026-09-05）
- 决策者：项目成员 + 联调评审

## 背景

仓库 `alany-dev/eTrace-Diag` 存在两条共享历史的分支：

- `main`：eBPF 采集器（C++20），根目录含 `src/ bpf/ config/ docs/ tests/ README.md`。
- `dev_models`：算法模型（Python 3.11/3.12），根目录含 `src/ pyproject.toml configs/ docs/ tests/ README.md`。

两分支根目录的 `src/`、`tests/`、`docs/`、`configs/`、`README.md` 路径重叠，直接 `git merge` 必然产生路径冲突且语义混乱。最终交付物要求单一仓库同时承载采集器与模型。

## 决策

1. **subtree 合并**：在 `main` 上执行
   `git subtree add --prefix=models origin/dev_models`，
   `dev_models` 的完整提交历史保留在 `models/` 子目录下，`main` 仅新增一个 merge commit，不重写历史。
2. **布局**：最终仓库根目录为采集器布局，模型全部位于 `models/` 子目录（与当前工作区 `eTrace-Diag/ + models/eTrace-Diag/` 的并列布局对应）。
3. **远端处置**：精简与联调完成后，`push` 更新后的 `dev_models` 与合并后的 `main` 至 origin；保留 `dev_models` 分支供后续模型侧开发。

## 后果

- 优点：模型历史完整可追溯（`git log -- models/` 可见全部模型演进）；无重写/强推。
- 缺点：仓库体积含两条历史；跨分支改同一文件需要 merge 或 cherry-pick 纪律。
- 备选方案（已否决）：
  - squash 单 commit 并入：main 干净但模型历史不可见；
  - 直接 merge + `git mv`：src/tests/docs 冲突面最大。
