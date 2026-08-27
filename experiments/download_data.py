"""Dataset download script — records manifest (name, version, SHA-256, license
note). Large datasets are NEVER committed to the repo.

    uv run python -m experiments.download_data --dataset smd --dest data/smd
    uv run python -m experiments.download_data --dataset rcaeval --dest data/rcaeval

License status is recorded per dataset; a checksum mismatch blocks the
experiment. AIOps 2020 requires a non-commercial research license — skipped by
default (recorded in the matrix).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

import httpx

MANIFEST_DIR = Path("data/manifests")

DATASETS = {
    "smd": {
        "url": (
            "https://github.com/NetManAIOps/OmniAnomaly/archive/refs/heads/master.zip"
        ),
        "in_archive": "OmniAnomaly-master/ServerMachineDataset",
        "license": "MIT (OmniAnomaly repo)",
        "note": "28 machines x 38 dims; per-point + interpretation labels",
    },
    "rcaeval": {
        "url": "https://github.com/phamquiluan/RCAEval/archive/refs/heads/main.zip",
        "in_archive": "RCAEval-main/data",
        "license": "MIT (verify in repo)",
        "note": "RE1/RE2/RE3 suites; 9 datasets, 735 failure cases",
    },
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(name: str, dest: Path) -> None:
    spec = DATASETS.get(name)
    if spec is None:
        raise SystemExit(f"unknown dataset {name}; available {sorted(DATASETS)}")
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
    tmp = Path("/tmp") / f"{name}.zip"
    print(f"downloading {spec['url']} ...")
    with httpx.stream("GET", spec["url"], follow_redirects=True, timeout=120) as r:
        r.raise_for_status()
        with open(tmp, "wb") as f:
            for chunk in r.iter_bytes(1 << 20):
                f.write(chunk)
    checksum = _sha256(tmp)
    with zipfile.ZipFile(tmp) as z:
        prefix = spec["in_archive"]
        members = [m for m in z.namelist() if m.startswith(prefix)]
        if not members:
            raise SystemExit(f"archive member {prefix} not found in {tmp.name}")
        dest.mkdir(parents=True, exist_ok=True)
        for m in members:
            rel = Path(m).relative_to(prefix)
            if rel.parts and rel.parts[0] == "..":
                continue
            target = dest / rel
            if m.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(m) as src, open(target, "wb") as out:
                out.write(src.read())
    manifest = {
        "name": name,
        "url": spec["url"],
        "sha256": checksum,
        "license": spec["license"],
        "note": spec["note"],
        "extracted_to": str(dest),
    }
    (MANIFEST_DIR / f"{name}.json").write_text(json.dumps(manifest, indent=2))
    print(f"ok: {name} -> {dest} (sha256 {checksum[:12]}...)")
    print("manifest:", MANIFEST_DIR / f"{name}.json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="experiments.download_data")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--dest", required=True)
    args = parser.parse_args(argv)
    try:
        download(args.dataset, Path(args.dest))
    except httpx.HTTPStatusError as exc:
        print(f"download failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())