#!/usr/bin/env python3
"""Run the TORAI benchmark for all datasets/variants/seeds in parallel.

Spawns one process per (dataset, variant, seed) combo; each writes its own
per-seed row-level JSON under results/torai. Use with 64-core hosts.

Usage:
    uv run python -m experiments.run_torai_all
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

DATASETS = ["torai-ob", "torai-ss", "torai-tt"]
VARIANTS = ["faithful", "improved"]
SEEDS = ["7", "11", "19"]


def main() -> int:
    cmds: list[list[str]] = []
    for ds in DATASETS:
        for variant in VARIANTS:
            for seed in SEEDS:
                cmds.append(
                    [
                        sys.executable, "-m", "experiments.run_torai",
                        "--dataset", ds,
                        "--variant", variant,
                        "--seeds", seed,
                        "--methods", "torai,rcd_only,baro,correlation",
                    ]
                )
    procs = []
    for cmd in cmds:
        log = Path("results/torai") / f"{cmd[4]}-{cmd[6]}-s{cmd[8]}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        with open(log, "w") as f:
            p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
        procs.append((cmd, p))
        print(f"started {' '.join(cmd[4:])} -> {log}", flush=True)
    failed = []
    for cmd, p in procs:
        rc = p.wait()
        if rc != 0:
            failed.append((cmd, rc))
    for cmd, rc in failed:
        print(f"FAILED ({rc}): {' '.join(cmd)}")
    print(f"done: {len(procs) - len(failed)}/{len(procs)} ok")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
