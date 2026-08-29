#!/usr/bin/env python3
"""Download the TORAI multi-source RCA dataset (Figshare, DOI 10.6084/m9.figshare.31925976).

The Figshare CDN sits behind an AWS WAF JS challenge, so plain HTTP requests are
rejected (403). This script documents the acquisition steps; the challenge must
be passed in a real browser (or a browser automation session) and the resulting
zip placed at data/torai/torai-data.zip, which this script then unpacks.

Expected layout (docs/TORAI.md of RCAEval):

    data/torai/torai-{OB|SS|TT}/{service}_{fault}/{run}/
        simple_metrics.csv logts.csv tracets_err.csv tracets_lat.csv inject_time.txt

If the dataset cannot be fetched, ``python -m experiments.torai_data`` builds an
equivalent dataset from the local RCAEval RE2 parquet snapshot instead.

Usage:
    uv run python -m experiments.download_torai_data [--zip PATH] [--dest data/torai]
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

FIGSHARE_ARTICLE = "https://doi.org/10.6084/m9.figshare.31925976"
FIGSHARE_FILE = "https://ndownloader.figshare.com/files/63402423"
DEFAULT_ZIP = "data/torai/torai-data.zip"


def _readable_csvs(case_dir: Path) -> bool:
    return (case_dir / "simple_metrics.csv").is_file() and (case_dir / "logts.csv").is_file()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", default=DEFAULT_ZIP, help="path to the Figshare zip")
    parser.add_argument("--dest", default="data/torai", help="extraction root")
    args = parser.parse_args(argv)

    zip_path = Path(args.zip)
    dest = Path(args.dest)

    if zip_path.is_file():
        print(f"unpacking {zip_path} -> {dest}")
        dest.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(dest)
    else:
        print(
            "Figshare blocks plain HTTP clients with an AWS WAF JS challenge "
            f"(curl {FIGSHARE_FILE} -> 403). Acquire the archive with a real browser:\n"
            f"  1. open {FIGSHARE_ARTICLE}\n"
            "  2. pass the challenge, click Download, save the zip\n"
            f"  3. place it at {zip_path}\n"
            "then re-run this command. No derived/fabricated substitute is "
            "created (policy 2026-08-29); TORAI reproduction waits for the "
            "official archive."
        )
        return 2

    counts: dict[str, int] = {}
    for system in ("torai-OB", "torai-SS", "torai-TT"):
        root = dest / system
        if not root.is_dir():
            print(f"missing {root}")
            return 1
        counts[system] = sum(1 for d in root.glob("*/*") if _readable_csvs(d))
    print("cases per system:", counts)
    ok = all(counts.get(s, 0) == 90 for s in ("torai-OB", "torai-SS", "torai-TT"))
    print("dataset complete" if ok else "dataset INCOMPLETE (expected 90 per system)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
