// x86_64 build. Shared programs live in etrace_common.h.
#include "etrace_common.h"

// ===========================================================================
// Syscall entry/exit — x86_64: fentry/fexit on do_syscall_64.
// pt_regs: orig_ax = syscall nr, si = 2nd arg (futex), ax = retval.
// ===========================================================================
#define ETD_NR_FUTEX 202  // x86_64
#define FUTEX_WAIT 0
#define FUTEX_WAIT_BITSET 9
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_CMD_MASK (~(FUTEX_PRIVATE_FLAG | 256))

#define ETD_SYSCALL_ARG1(regs) BPF_CORE_READ(regs, si)
#define ETD_SYSCALL_ORIG_NR(regs) BPF_CORE_READ(regs, orig_ax)
#define ETD_SYSCALL_RET(regs) BPF_CORE_READ(regs, ax)

SEC("fentry/do_syscall_64")
int BPF_PROG(fentry_sys, struct pt_regs *regs, unsigned int nr) {
  if (!deep_mode()) return 0;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;
  u64 id = ETD_SYSCALL_ORIG_NR(regs);
  u8 futex_wait = 0;
  if (id == ETD_NR_FUTEX) {
    unsigned long arg1 = ETD_SYSCALL_ARG1(regs);
    u64 cmd = arg1 & FUTEX_CMD_MASK;
    if (cmd == FUTEX_WAIT || cmd == FUTEX_WAIT_BITSET) futex_wait = 1;
  }
  struct sys_start_t st;
  st.id = (u32)id;
  st.ts = bpf_ktime_get_ns();
  st.futex_wait = futex_wait;
  bpf_map_update_elem(&sys_start, &tid, &st, BPF_ANY);
  return 0;
}

SEC("fexit/do_syscall_64")
int BPF_PROG(fexit_sys, struct pt_regs *regs, unsigned int nr) {
  if (!deep_mode()) return 0;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;
  struct sys_start_t *st = bpf_map_lookup_elem(&sys_start, &tid);
  if (!st) return 0;
  u64 lat = bpf_ktime_get_ns() - st->ts;
  long ret = (long)ETD_SYSCALL_RET(regs);
  syslat_account(tid, st->id, st->futex_wait, lat, ret);
  bpf_map_delete_elem(&sys_start, &tid);
  return 0;
}

// ===========================================================================
// DEEP: raw syscalls enter/exit (fallback for non-x86 or fentry-less kernels)
