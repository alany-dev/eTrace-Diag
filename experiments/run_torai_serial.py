#!/usr/bin/env python3
"""Serial TORAI benchmark queue: ONE run at a time (no concurrency).

The machine is shared; experiments must not run concurrently. Each queue entry
is a blocking subprocess.run; results go to results/torai as per-seed JSONs.

Usage:
    uv run python -m experiments.run_torai_serial
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

# (dataset, variant, seeds, methods) — faithful seeds first (reproduction),
# then improved (post standard-scaler fix), then baselines last.
QUEUE: list[tuple[str, str, str, str]] = [
    # faithful — torai-ss-s11 already done
    ("torai-ob", "faithful", "7", "torai"),
    ("torai-ob", "faithful", "11", "torai"),
    ("torai-ob", "faithful", "19", "torai"),
    ("torai-ss", "faithful", "7", "torai"),
    ("torai-ss", "faithful", "19", "torai"),
    ("torai-tt", "faithful", "7", "torai"),
    ("torai-tt", "faithful", "11", "torai"),
    ("torai-tt", "faithful", "19", "torai"),
    # improved — standard scaler variant (user decision 2026-08-29)
    ("torai-ob", "improved", "7", "torai"),
    ("torai-ob", "improved", "11", "torai"),
    ("torai-ob", "improved", "19", "torai"),
    ("torai-ss", "improved", "7", "torai"),
    ("torai-ss", "improved", "11", "torai"),
    ("torai-ss", "improved", "19", "torai"),
    ("torai-tt", "improved", "7", "torai"),
    ("torai-tt", "improved", "11", "torai"),
    ("torai-tt", "improved", "19", "torai"),
    # baselines (plan Step 4.4), one seed each, full 90 cases
    ("torai-ob", "faithful", "7", "torai,rcd_only,baro,correlation"),
    ("torai-ss", "faithful", "7", "torai,rcd_only,baro,correlation"),
    ("torai-tt", "faithful", "7", "torai,rcd_only,baro,correlation"),
]


def main() -> int:
    master_log = Path("results/torai/queue-master.log")
    master_log.parent.mkdir(parents=True, exist_ok=True)
    t_start = time.time()
    failed: list[str] = []
    with open(master_log, "w") as ml:
        for i, (ds, variant, seed, methods) in enumerate(QUEUE, 1):
            cmd = [
                sys.executable, "-m", "experiments.run_torai",
                "--dataset", ds,
                "--variant", variant,
                "--seeds", seed,
                "--methods", methods,
            ]
            line = f"[{time.strftime('%H:%M:%S')}] [{i}/{len(QUEUE)}] START {ds} {variant} s{seed} ({methods})"
            print(line, flush=True)
            ml.write(line + "\n")
            ml.flush()
            t0 = time.time()
            rc = subprocess.run(cmd).returncode
            dt = time.time() - t0
            line = f"[{time.strftime('%H:%M:%S')}] [{i}/{len(QUEUE)}] DONE rc={rc} in {dt/60:.1f} min"
            print(line, flush=True)
            ml.write(line + "\n")
            ml.flush()
            if rc != 0:
                failed.append(f"{ds} {variant} s{seed}")
    line = f"[{time.strftime('%H:%M:%S')}] QUEUE COMPLETE, total {(time.time()-t_start)/3600:.1f} h, failed={len(failed)} {failed}"
    print(line, flush=True)
    with open(master_log, "a") as ml:
        ml.write(line + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
