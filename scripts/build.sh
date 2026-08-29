#!/usr/bin/env bash
# Build etrace-diag (C++20 user space + BPF object + skeleton).
# Prereqs: clang (BPF target), bpftool, libbpf, libelf, zlib, cmake, make.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"

mkdir -p "$BUILD_DIR"

cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release "$@"
cmake --build "$BUILD_DIR" -j"$(nproc)"

echo "Built:"
echo "  $BUILD_DIR/etrace-diag"
echo "  $BUILD_DIR/bpf/etrace.bpf.o"
echo "  $BUILD_DIR/bpf/etrace.skel.h"