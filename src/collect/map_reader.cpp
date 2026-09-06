#include "collect/map_reader.h"

#include <bpf/bpf.h>
#include <cstring>
#include <memory>

namespace etrace_diag {

namespace {
uint64_t RoundUp8(uint64_t v) { return (v + 7) & ~7ULL; }
}  // namespace

int PossibleCpus() { return libbpf_num_possible_cpus(); }

MapSlice::MapSlice(struct bpf_map* m) {
  if (!m) return;
  fd_ = bpf_map__fd(m);
  key_size_ = bpf_map__key_size(m);
  value_size_ = bpf_map__value_size(m);
  int t = bpf_map__type(m);
  percpu_ = t == BPF_MAP_TYPE_PERCPU_HASH || t == BPF_MAP_TYPE_PERCPU_ARRAY ||
            t == BPF_MAP_TYPE_LRU_PERCPU_HASH || t == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE;
  ncpus_ = libbpf_num_possible_cpus();
  aligned_ = RoundUp8(value_size_);
  pcpu_stride_ = aligned_ * (size_t)(ncpus_ > 0 ? ncpus_ : 1);
  scratch_value_.resize(percpu_ ? pcpu_stride_ : value_size_);
}

bool MapSlice::Lookup(const void* key, void* out) const {
  if (fd_ < 0) return false;
  return bpf_map_lookup_elem(fd_, key, out) == 0;
}

bool MapSlice::LookupPercpuSum(const void* key, void* out) const {
  if (fd_ < 0) return false;
  if (!percpu_) return Lookup(key, out);
  std::vector<uint8_t>& buf = scratch_value_;
  buf.assign(pcpu_stride_, 0);
  if (bpf_map_lookup_elem(fd_, key, buf.data()) != 0) return false;
  uint8_t* dst = static_cast<uint8_t*>(out);
  std::memset(dst, 0, value_size_);
  for (int cpu = 0; cpu < ncpus_; ++cpu) {
    const uint8_t* src = buf.data() + (size_t)cpu * aligned_;
    for (size_t i = 0; i < value_size_; ++i) dst[i] += src[i];
  }
  return true;
}

void MapSlice::ForEach(std::function<void(const void*, const void*)> fn) const {
  if (fd_ < 0) return;
  std::vector<uint8_t> key(key_size_), next(key_size_);
  std::vector<uint8_t> buf(percpu_ ? pcpu_stride_ : value_size_);
  std::vector<uint8_t> summed(value_size_);

  bool have_prev = false;
  for (;;) {
    void* prev = have_prev ? key.data() : nullptr;
    if (bpf_map_get_next_key(fd_, prev, next.data()) != 0) break;  // ENOENT = done
    if (percpu_) {
      if (bpf_map_lookup_elem(fd_, next.data(), buf.data()) != 0) break;
      std::memset(summed.data(), 0, value_size_);
      for (int cpu = 0; cpu < ncpus_; ++cpu) {
        const uint8_t* src = buf.data() + (size_t)cpu * aligned_;
        for (int b = 0; b < (int)value_size_; ++b) summed[b] += src[b];
      }
      fn(next.data(), summed.data());
    } else {
      if (bpf_map_lookup_elem(fd_, next.data(), buf.data()) != 0) break;
      fn(next.data(), buf.data());
    }
    key.swap(next);
    have_prev = true;
  }
}

void MapSlice::Drain(std::function<void(const void*, const void*)> fn) const {
  // Iterate with the previous key (never restart from NULL after a delete),
  // so concurrent inserts cannot starve the loop; cap iterations per call so
  // a continuously-filled map resumes on the next periodic tick instead of
  // spinning forever.
  constexpr uint32_t kMaxDrainIterations = 8192;
  std::vector<uint8_t> prev(key_size_), cur(key_size_);
  std::vector<uint8_t> buf(percpu_ ? pcpu_stride_ : value_size_);
  std::vector<uint8_t> summed(value_size_);
  uint32_t iterations = 0;
  for (;;) {
    if (++iterations > kMaxDrainIterations) break;
    const void* prevp = iterations > 1 ? prev.data() : nullptr;
    if (bpf_map_get_next_key(fd_, prevp, cur.data()) != 0) break;
    if (percpu_) {
      if (bpf_map_lookup_elem(fd_, cur.data(), buf.data()) != 0) break;
      std::memset(summed.data(), 0, value_size_);
      for (int cpu = 0; cpu < ncpus_; ++cpu) {
        const uint8_t* src = buf.data() + (size_t)cpu * aligned_;
        for (int b = 0; b < (int)value_size_; ++b) summed[b] += src[b];
      }
      fn(cur.data(), summed.data());
    } else {
      if (bpf_map_lookup_elem(fd_, cur.data(), buf.data()) != 0) break;
      fn(cur.data(), buf.data());
    }
    bpf_map_delete_elem(fd_, cur.data());
    std::swap(prev, cur);
  }
}

void MapSlice::Wipe() const {
  constexpr uint32_t kMaxWipeIterations = 8192;
  std::vector<uint8_t> prev(key_size_), cur(key_size_);
  uint32_t iterations = 0;
  for (;;) {
    if (++iterations > kMaxWipeIterations) break;
    const void* prevp = iterations > 1 ? prev.data() : nullptr;
    if (bpf_map_get_next_key(fd_, prevp, cur.data()) != 0) break;
    bpf_map_delete_elem(fd_, cur.data());
    std::swap(prev, cur);
  }
}

void DecodeSnapshot(const KernelSnapshotRec& r, CanonicalSnapshot& s) {
  s.ts_ns = r.ts_ns;
  s.tgid = r.tgid;
  s.tid = r.tid;
  std::memcpy(s.comm, r.comm, sizeof(s.comm));
  s.on_cpu_ns = r.on_cpu_ns;
  s.nr_sw_vol = r.nr_sw_vol;
  s.nr_sw_invol = r.nr_sw_invol;
  s.io_ops = r.io_ops;
  s.io_bytes = r.io_bytes;
  std::memcpy(s.io_hist, r.io_hist, sizeof(s.io_hist));
  s.pf_minor = r.pf_minor;
  s.pf_major = r.pf_major;
  s.lock_waits = r.lock_waits;
  s.lock_lat_ns = r.lock_lat_ns;
  std::memcpy(s.lock_hist, r.lock_hist, sizeof(s.lock_hist));
  s.syscall_count = r.syscall_count;
  s.syscall_lat_ns = r.syscall_lat_ns;
  std::memcpy(s.syscall_hist, r.syscall_hist, sizeof(s.syscall_hist));
  s.futex_waits = r.futex_waits;
  s.futex_lat_ns = r.futex_lat_ns;
  std::memcpy(s.futex_hist, r.futex_hist, sizeof(s.futex_hist));
  s.runq_wait_ns = r.runq_wait_ns;
  s.runq_wait_count = r.runq_wait_count;
  std::memcpy(s.runq_hist, r.runq_hist, sizeof(s.runq_hist));
  s.flags = r.flags;
}

}  // namespace etrace_diag