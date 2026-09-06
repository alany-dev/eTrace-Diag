# Linux server tool usage
- Intel Xeon Gold 6326 (Dual-socket? 32 cores total): 64 cores (nproc=64).
- RTX 3090, driver nvidia-535: 24 GB VRAM, CUDA 11.2.
- Ubuntu 20.04, Python 3.9.16 (system).

# uv / python
- Project root: /hd_2t/lj/yzj_20260421/alg-models
- uv version: 0.7.8 (prefer uv over pip for reproducibility).
- Python 3.11 venv located at .venv — created by `uv sync --extra dev`.

# repo map
- configs/: benchmark.yaml, smoke.yaml
- experiments/: run_detection.py, run_rca.py, profile.py, make_fixtures.py, download_data.py
- src/alg_models/: schemas.py, data/, detection/, causal/, interactive/, api.py, cli.py, collectors/, distributed/
- tests/: test_schemas.py, test_no_leakage.py, test_missing_quality.py, test_explainer.py, fixtures/

# pytest
- ROS/ament plugins from /opt/ros break default pytest: pyproject addopts disables them.
- Run: uv run pytest -q tests/test_schemas.py tests/test_no_leakage.py tests/test_missing_quality.py

# internet
- PyPI and raw.githubusercontent.com reachable; github.com git/archive partially blocked.
- codeload.github.com works (used by download_data.py).

# notes
- CUDA: torch not installed (CPU-only default). To run GPU workloads need `uv sync --extra torch`.