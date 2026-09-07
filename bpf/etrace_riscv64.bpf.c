// riscv64 build.
// Shared programs live in etrace_common.h (identical collection logic).
#include "etrace_common.h"

// ===========================================================================
// Syscall entry/exit — riscv64: tp_btf/sys_enter + sys_exit tracepoints.
// Tracepoint context provides regs/id (enter) and regs/ret (exit) directly;
// only the futex wait-flag needs a raw pt_regs member (a0).
// ===========================================================================
#define ETD_NR_FUTEX 222
#define FUTEX_WAIT 0
#define FUTEX_WAIT_BITSET 9
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_CMD_MASK (~(FUTEX_PRIVATE_FLAG | 256))

#define ETD_SYSCALL_ARG1(regs) BPF_CORE_READ(regs, a0)  // a0 = 2nd syscall arg

SEC("tp_btf/sys_enter")
int BPF_PROG(on_sys_enter, struct pt_regs *regs, long id) {
  if (id < 0) return 0;  // compat (ia32/x32)
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;

  u8 futex_wait = 0;
  if (id == ETD_NR_FUTEX) {
    unsigned long arg1 = ETD_SYSCALL_ARG1(regs);
    u64 cmd = arg1 & FUTEX_CMD_MASK;
    if (cmd == FUTEX_WAIT || cmd == FUTEX_WAIT_BITSET) futex_wait = 1;
  }

  struct sys_start_t s;
  s.id = (u32)id;
  s.ts = bpf_ktime_get_ns();
  s.futex_wait = futex_wait;
  bpf_map_update_elem(&sys_start, &tid, &s, BPF_ANY);
  return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(on_sys_exit, struct pt_regs *regs, long ret) {
  (void)regs;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;
  struct sys_start_t *s = bpf_map_lookup_elem(&sys_start, &tid);
  if (!s) return 0;
  u64 lat = bpf_ktime_get_ns() - s->ts;

  syslat_account(tid, s->id, s->futex_wait, lat, ret);

  bpf_map_delete_elem(&sys_start, &tid);
  return 0;
}
