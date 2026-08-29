#pragma once

#include <bpf/libbpf.h>

#include <cstdint>
#include <functional>
#include <vector>

#include "etrace_diag/metrics.h"

namespace etrace_diag {

// Frozen mirror of `struct snapshot_rec` in bpf/etrace.bpf.c. Layout verified
// at runtime against bpf_map__value_size(recorder).
struct KernelSnapshotRec {
  uint64_t seq;
  uint64_t ts_ns;
  uint32_t tgid;
  uint32_t tid;
  uint8_t comm[16];
  uint64_t on_cpu_ns;
  uint32_t nr_sw_vol;
  uint32_t nr_sw_invol;
  uint64_t io_ops;
  uint64_t io_bytes;
  uint32_t io_hist[kBase4HistBins];
  uint32_t pf_minor;
  uint32_t pf_major;
  uint64_t lock_waits;
  uint64_t lock_lat_ns;
  uint32_t lock_hist[kBase4HistBins];
  uint64_t syscall_count;
  uint64_t syscall_lat_ns;
  uint32_t syscall_hist[kBase4HistBins];
  uint64_t futex_waits;
  uint64_t futex_lat_ns;
  uint32_t futex_hist[kBase4HistBins];
  uint64_t runq_wait_ns;
  uint32_t runq_wait_count;
  uint32_t runq_hist[kBase4HistBins];
  uint32_t flags;
};

void DecodeSnapshot(const KernelSnapshotRec& rec, CanonicalSnapshot& out);

// User-space accessor for one BPF map. Handles both plain and PERCPU maps,
// batch iteration, and per-key percpu summation.
class MapSlice {
 public:
  explicit MapSlice(struct bpf_map* m);

  bool valid() const { return fd_ >= 0; }
  int fd() const { return fd_; }
  bool is_percpu() const { return percpu_; }
  size_t key_size() const { return key_size_; }
  size_t value_size() const { return value_size_; }

  // Regular-map single lookup into `out` (size value_size()).
  bool Lookup(const void* key, void* out) const;
  // PERCPU-map single lookup summed across CPUs into `out`.
  bool LookupPercpuSum(const void* key, void* out) const;

  // Iterates all entries. For PERCPU maps the value is the CPU-summed buffer.
  void ForEach(std::function<void(const void* key, const void* value)> fn) const;

  // lookup_and_delete_batch for the whole map, invoking fn per drained entry
  // (PERCPU values CPU-summed). Used to wipe DEEP result maps.
  void Drain(std::function<void(const void* key, const void* value)> fn) const;

  // Deletes every entry without invoking a callback (tolerates PERCPU maps via
  // lookup_and_delete_batch).
  void Wipe() const;

  // Reads a value into the caller-provided scratch (managed internally).
  std::vector<uint8_t>& ScratchValue() const { return scratch_value_; }

 private:
  int fd_ = -1;
  bool percpu_ = false;
  size_t key_size_ = 0;
  size_t value_size_ = 0;
  size_t aligned_ = 0;    // round_up(value_size, 8)
  size_t pcpu_stride_ = 0;  // aligned_ * ncpus
  int ncpus_ = 1;
  mutable std::vector<uint8_t> scratch_value_;
};

int PossibleCpus();

}  // namespace etrace_diag