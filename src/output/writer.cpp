#include "etrace_diag/output_writer.h"

#include <sqlite3.h>

#include <cstdio>
#include <ctime>
#include <map>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "logging.h"

namespace etrace_diag {

namespace {

// Per-method prepared statement index (see kSql in OutputWriter::Prep).
enum Stmt : int {
  S_META_INS,
  S_HOST_INS,
  S_HOST_CPU_INS,
  S_HOST_DISK_INS,
  S_HOST_PROC_INS,
  S_NET_STACK_INS,
  S_NET_IFACE_INS,
  S_NET_SOFTNET_INS,
  S_GPU_DEV_INS,
  S_CGROUP_INS,
  S_CGROUP_IO_INS,
  S_ANOMALY_INS,
  S_ANOMALY_TID_INS,
  S_TARGETS_INS,
  S_OOM_INS,
  S_MEMEV_INS,
  S_BPF_INS,
  S_OVERHEAD_INS,
  S_LOGS_INS,
  S_EPISODE_INS,
  S_EPISODE_META,
  S_EPISODE_SUMMARY,
  S_SERIES_INS,
  S_GAP_INS,
  S_FOLDED_INS,
  S_SYSCALL_INS,
  S_LOCK_INS,
  S_RUNQ_INS,
  S_IOFILE_INS,
  S_DEEP_PROC_INS,
  S_DEEP_IODEV_INS,
  S_NET_FLOW_INS,
  S_NET_DROP_INS,
  S_NET_SOFTIRQ_INS,
  S_DEEP_GPU_PROC_INS,
  S_OFFCPU_INS,
  S_TID_COMM_LOOKUP,
  S_COUNT
};

std::string NowDirName() {
  time_t t = time(nullptr);
  struct tm tmv;
  localtime_r(&t, &tmv);
  char buf[64];
  strftime(buf, sizeof(buf), "%Y%m%d-%H%M%S", &tmv);
  return buf;
}

std::string NowIso() {
  time_t t = time(nullptr);
  struct tm tmv;
  localtime_r(&t, &tmv);
  char buf[64];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S%z", &tmv);
  return buf;
}

// 13-bin base-4 latency histogram as JSON text.
std::string HistJson(const uint32_t* h, int bins) {
  std::string out = "[";
  for (int i = 0; i < bins; ++i) {
    if (i) out += ",";
    out += std::to_string(h[i]);
  }
  out += "]";
  return out;
}

// Bind a uint64 that may be "invalid" as NULL (valid=false convention).
void BindU64(sqlite3_stmt* st, int& c, uint64_t v, bool valid) {
  if (valid)
    sqlite3_bind_int64(st, c++, (sqlite3_int64)v);
  else
    sqlite3_bind_null(st, c++);
}

void BindBool(sqlite3_stmt* st, int& c, bool v) { sqlite3_bind_int(st, c++, v ? 1 : 0); }

void BindText(sqlite3_stmt* st, int& c, const std::string& s) {
  sqlite3_bind_text(st, c++, s.c_str(), -1, SQLITE_TRANSIENT);
}

// Cache the latest comm for a tid by consulting targets_log (join/leave rows).
std::string LatestTidComm(sqlite3* db, uint32_t tid) {
  if (!db) return "";
  static const char* sql =
      "SELECT comm FROM targets_log WHERE tid=? ORDER BY seq DESC LIMIT 1";
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) return "";
  sqlite3_bind_int64(st, 1, (sqlite3_int64)tid);
  std::string out;
  if (sqlite3_step(st) == SQLITE_ROW) {
    const unsigned char* t = sqlite3_column_text(st, 0);
    if (t) out = reinterpret_cast<const char*>(t);
  }
  sqlite3_finalize(st);
  return out;
}

// x86_64 系统调用号 → 名称（内核 5.x 主流表；未知号回退 "syscall_<nr>"）。
// 采集到的是当前设备（x86_64）的 syscall nr，这里在存储时一并落名。
const char* SyscallName(uint32_t nr) {
  static const char* const kNames[512] = {
      /*0*/ "read", "write", "open", "close", "stat", "fstat", "lstat", "poll",
      /*8*/ "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
      /*16*/ "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select",
      /*24*/ "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl",
      /*32*/ "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid",
      /*40*/ "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg",
      /*48*/ "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt",
      /*56*/ "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname",
      /*64*/ "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl",
      /*72*/ "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd",
      /*80*/ "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink",
      /*88*/ "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask",
      /*96*/ "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog",
      /*104*/ "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
      /*112*/ "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresgid",
      /*120*/ "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending",
      /*128*/ "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality",
      /*136*/ "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam",
      /*144*/ "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall",
      /*152*/ "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex",
      /*160*/ "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon",
      /*168*/ "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module", "init_module",
      /*176*/ "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall",
      /*184*/ "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr",
      /*192*/ "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr",
      /*200*/ "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy",
      /*208*/ "io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old",
      /*216*/ "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime",
      /*224*/ "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group",
      /*232*/ "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy",
      /*240*/ "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid",
      /*248*/ "add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch",
      /*256*/ "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat",
      /*264*/ "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
      /*272*/ "unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages",
      /*280*/ "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime",
      /*288*/ "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv",
      /*296*/ "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at",
      /*304*/ "open_by_handle_at", "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev",
      /*312*/ "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2", "seccomp", "getrandom", "memfd_create",
      /*320*/ "kexec_file_load", "bpf", "execveat", "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2",
      /*328*/ "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free", "statx", "io_pgetevents", "rseq", "pidfd_send_signal",
      /*336*/ "io_uring_setup", "io_uring_enter", "io_uring_register", "open_tree", "move_mount", "fsopen", "fsconfig", "fsmount",
      /*344*/ "fspick", "pidfd_open", "clone3", "close_range", "openat2", "pidfd_getfd", "faccessat2", "process_madvise",
      /*352*/ "epoll_pwait2", "mount_setattr", "quotactl_fd", "landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self", "memfd_secret", "set_mempolicy_home_node",
      /*360*/ (const char*)nullptr,
  };
  if (nr < 360 && kNames[nr]) return kNames[nr];
  static thread_local char buf[32];
  snprintf(buf, sizeof(buf), "syscall_%u", nr);
  return buf;
}

const char* kDdl[] = {
    // ---- BASE ----
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS host ("
    " ts_ns INTEGER PRIMARY KEY,"
    " cu_user INTEGER NOT NULL, cu_nice INTEGER NOT NULL, cu_sys INTEGER NOT NULL,"
    " cu_idle INTEGER NOT NULL, cu_iowait INTEGER NOT NULL, cu_irq INTEGER NOT NULL,"
    " cu_softirq INTEGER NOT NULL, cu_steal INTEGER NOT NULL,"
    " cu_guest INTEGER, cu_guest_nice INTEGER,"
    " load1 REAL, load5 REAL, load15 REAL, nr_running INTEGER, nr_threads INTEGER,"
    " mem_total_kb INTEGER, mem_avail_kb INTEGER, mem_free_kb INTEGER, buffers_kb INTEGER,"
    " cached_kb INTEGER, swap_total_kb INTEGER, swap_free_kb INTEGER, anon_pages_kb INTEGER,"
    " sreclaimable_kb INTEGER, shmem_kb INTEGER, dirty_kb INTEGER, writeback_kb INTEGER,"
    " commit_limit_kb INTEGER, committed_as_kb INTEGER, mem_valid_mask INTEGER,"
    " vm_pgfault INTEGER, vm_pgmajfault INTEGER, vm_pswpin INTEGER, vm_pswpout INTEGER,"
    " vm_pgscan_kswapd INTEGER, vm_pgscan_direct INTEGER, vm_pgsteal_kswapd INTEGER,"
    " vm_pgsteal_direct INTEGER, vm_workingset_refault INTEGER, vm_nr_dirty INTEGER,"
    " vm_nr_writeback INTEGER, vm_valid_mask INTEGER,"
    " psi_cpu_s10 REAL, psi_cpu_s60 REAL, psi_cpu_s300 REAL, psi_cpu_s_valid INTEGER,"
    " psi_cpu_f10 REAL, psi_cpu_f60 REAL, psi_cpu_f300 REAL, psi_cpu_f_valid INTEGER,"
    " psi_io_s10 REAL, psi_io_s60 REAL, psi_io_s300 REAL, psi_io_s_valid INTEGER,"
    " psi_io_f10 REAL, psi_io_f60 REAL, psi_io_f300 REAL, psi_io_f_valid INTEGER,"
    " psi_mem_s10 REAL, psi_mem_s60 REAL, psi_mem_s300 REAL, psi_mem_s_valid INTEGER,"
    " psi_mem_f10 REAL, psi_mem_f60 REAL, psi_mem_f300 REAL, psi_mem_f_valid INTEGER,"
    " ctxt INTEGER, processes INTEGER, procs_running INTEGER, procs_blocked INTEGER)",
    "CREATE TABLE IF NOT EXISTS host_cpu ("
    " ts_ns INTEGER NOT NULL, cpu_idx INTEGER NOT NULL,"
    " usr INTEGER, nice INTEGER, sys INTEGER, idle INTEGER,"
    " iowait INTEGER, irq INTEGER, softirq INTEGER, steal INTEGER,"
    " guest INTEGER, guest_nice INTEGER,"
    " PRIMARY KEY (ts_ns, cpu_idx)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS host_disk ("
    " ts_ns INTEGER NOT NULL, name TEXT NOT NULL, major INTEGER, minor INTEGER,"
    " reads_completed INTEGER, writes_completed INTEGER,"
    " sectors_read INTEGER, sectors_written INTEGER,"
    " io_ticks_ms INTEGER, read_ticks_ms INTEGER, write_ticks_ms INTEGER,"
    " reads_merged INTEGER, writes_merged INTEGER, in_flight INTEGER,"
    " weighted_ticks_ms INTEGER, valid_mask INTEGER,"
    " PRIMARY KEY (ts_ns, name)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS host_proc ("
    " ts_ns INTEGER NOT NULL, pid INTEGER NOT NULL, tgid INTEGER, state INTEGER,"
    " start_time INTEGER, utime INTEGER, stime INTEGER,"
    " nvcsw INTEGER, nivcsw INTEGER, minflt INTEGER, majflt INTEGER,"
    " total_vm INTEGER, rss_kb INTEGER, comm TEXT,"
    " PRIMARY KEY (ts_ns, pid)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS net_stack ("
    " ts_ns INTEGER PRIMARY KEY, netns_ino INTEGER, source TEXT, valid INTEGER, error TEXT,"
    " active_opens INTEGER, passive_opens INTEGER, attempt_fails INTEGER, estab_resets INTEGER,"
    " curr_estab INTEGER, in_segs INTEGER, out_segs INTEGER, retrans_segs INTEGER,"
    " in_errs INTEGER, out_rsts INTEGER,"
    " listen_overflows INTEGER, listen_drops INTEGER, backlog_drop INTEGER, rcv_q_drop INTEGER,"
    " syn_retrans INTEGER, timeouts INTEGER, memory_pressures INTEGER,"
    " udp_in_datagrams INTEGER, udp_no_ports INTEGER, udp_in_errors INTEGER,"
    " udp_out_datagrams INTEGER, udp_rcvbuf_errors INTEGER, udp_sndbuf_errors INTEGER,"
    " tcp_sock_mem INTEGER, udp_sock_mem INTEGER, frag_sock_mem INTEGER,"
    " tcp_state_established INTEGER, tcp_state_syn_sent INTEGER, tcp_state_syn_recv INTEGER,"
    " tcp_state_fin_wait1 INTEGER, tcp_state_fin_wait2 INTEGER, tcp_state_time_wait INTEGER,"
    " tcp_state_close INTEGER, tcp_state_close_wait INTEGER, tcp_state_last_ack INTEGER,"
    " tcp_state_listen INTEGER, tcp_state_closing INTEGER,"
    " rqueue_bytes INTEGER, wqueue_bytes INTEGER, tcp_states_valid INTEGER)",
    "CREATE TABLE IF NOT EXISTS net_iface ("
    " ts_ns INTEGER NOT NULL, ifindex INTEGER NOT NULL, name TEXT,"
    " operstate INTEGER, mtu INTEGER, source TEXT, valid INTEGER, error TEXT,"
    " rx_bytes INTEGER, rx_packets INTEGER, rx_errors INTEGER, rx_dropped INTEGER,"
    " tx_bytes INTEGER, tx_packets INTEGER, tx_errors INTEGER, tx_dropped INTEGER,"
    " collisions INTEGER, carrier_changes INTEGER, rx_nohandler INTEGER,"
    " PRIMARY KEY (ts_ns, ifindex)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS net_softnet ("
    " ts_ns INTEGER NOT NULL, cpu_idx INTEGER NOT NULL,"
    " processed INTEGER, dropped INTEGER, time_squeeze INTEGER,"
    " received_rps INTEGER, flow_limit_count INTEGER, backlog_len INTEGER,"
    " net_rx_softirq INTEGER, net_tx_softirq INTEGER,"
    " valid INTEGER, error TEXT,"
    " PRIMARY KEY (ts_ns, cpu_idx)) WITHOUT ROWID",
    // ---- BASE GPU ----
    "CREATE TABLE IF NOT EXISTS gpu_device ("
    " ts_ns INTEGER NOT NULL, uuid TEXT NOT NULL, pci_bdf TEXT,"
    " vendor TEXT, model TEXT, source TEXT, available INTEGER, is_mig INTEGER,"
    " util_pct REAL, mem_util_pct REAL, mem_used_bytes INTEGER, mem_total_bytes INTEGER,"
    " temperature_c REAL, power_w REAL, power_limit_w REAL, energy_mj INTEGER,"
    " sm_clock_mhz INTEGER, mem_clock_mhz INTEGER,"
    " pcie_rx_kbps INTEGER, pcie_tx_kbps INTEGER,"
    " encoder_util_pct REAL, decoder_util_pct REAL, throttle_reasons INTEGER,"
    " ecc_sbe_total INTEGER, ecc_dbe_total INTEGER, retired_pages INTEGER,"
    " valid_mask INTEGER, error_code INTEGER, error_text TEXT,"
    " PRIMARY KEY (ts_ns, uuid)) WITHOUT ROWID",
    // ---- BASE cgroup (collector's own cgroup v2) ----
    "CREATE TABLE IF NOT EXISTS cgroup ("
    " ts_ns INTEGER PRIMARY KEY, available INTEGER, cgroup_path TEXT, error TEXT,"
    " cpu_usage_usec INTEGER, user_usec INTEGER, system_usec INTEGER,"
    " nr_periods INTEGER, nr_throttled INTEGER, throttled_usec INTEGER, cpu_valid INTEGER,"
    " memory_current_bytes INTEGER, memory_max_bytes INTEGER, memory_max_unlimited INTEGER,"
    " memory_events_low INTEGER, memory_events_high INTEGER, memory_events_max INTEGER,"
    " memory_events_oom INTEGER, memory_events_oom_kill INTEGER, memory_valid INTEGER,"
    " cpu_psi_s10 REAL, cpu_psi_s60 REAL, cpu_psi_s300 REAL, cpu_psi_s_valid INTEGER,"
    " cpu_psi_f10 REAL, cpu_psi_f60 REAL, cpu_psi_f300 REAL, cpu_psi_f_valid INTEGER,"
    " memory_psi_s10 REAL, memory_psi_s60 REAL, memory_psi_s300 REAL, memory_psi_s_valid INTEGER,"
    " memory_psi_f10 REAL, memory_psi_f60 REAL, memory_psi_f300 REAL, memory_psi_f_valid INTEGER)",
    "CREATE TABLE IF NOT EXISTS cgroup_io ("
    " ts_ns INTEGER NOT NULL, major INTEGER NOT NULL, minor INTEGER NOT NULL,"
    " rbytes INTEGER, wbytes INTEGER, rios INTEGER, wios INTEGER,"
    " dbytes INTEGER, dios INTEGER,"
    " PRIMARY KEY (ts_ns, major, minor)) WITHOUT ROWID",
    // ---- 1s anomaly feature vector ----
    "CREATE TABLE IF NOT EXISTS anomaly ("
    " ts_ns INTEGER PRIMARY KEY, seq INTEGER,"
    " on_cpu_ns_total INTEGER, switch_total INTEGER, io_ops_total INTEGER,"
    " io_bytes_total INTEGER, minor_faults_total INTEGER, major_faults_total INTEGER,"
    " lock_waits_total INTEGER)",
    "CREATE TABLE IF NOT EXISTS anomaly_tid ("
    " ts_ns INTEGER NOT NULL, tid INTEGER NOT NULL, comm TEXT,"
    " on_cpu_ns INTEGER, nr_sw_vol INTEGER, nr_sw_invol INTEGER,"
    " io_ops INTEGER, io_bytes INTEGER,"
    " pf_minor INTEGER, pf_major INTEGER, lock_waits INTEGER, lock_lat_ns INTEGER,"
    " PRIMARY KEY (ts_ns, tid)) WITHOUT ROWID",
    // ---- collector self overhead / BPF program stats (1s) ----
    "CREATE TABLE IF NOT EXISTS proc_overhead ("
    " ts_ns INTEGER PRIMARY KEY,"
    " utime_ns INTEGER, stime_ns INTEGER, nvcsw INTEGER, nivcsw INTEGER,"
    " minflt INTEGER, majflt INTEGER, rss_kb INTEGER, vmhwm_kb INTEGER)",
    "CREATE TABLE IF NOT EXISTS bpf_stats ("
    " ts_ns INTEGER NOT NULL, prog_name TEXT NOT NULL, prog_id INTEGER,"
    " run_cnt INTEGER, run_time_ns INTEGER, avg_ns REAL, interval_ns INTEGER,"
    " PRIMARY KEY (ts_ns, prog_name)) WITHOUT ROWID",
    // ---- memory / OOM / targets / logs ----
    "CREATE TABLE IF NOT EXISTS memory_events ("
    " ts_ns INTEGER PRIMARY KEY,"
    " kswapd_active INTEGER, direct_reclaim INTEGER, nr_reclaimed INTEGER)",
    "CREATE TABLE IF NOT EXISTS oom_events ("
    " ts_ns INTEGER PRIMARY KEY, pid INTEGER, comm TEXT)",
    "CREATE TABLE IF NOT EXISTS targets_log ("
    " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
    " ts_ns INTEGER NOT NULL, action TEXT NOT NULL, tgid INTEGER, tid INTEGER,"
    " comm TEXT, score REAL, rank INTEGER)",
    "CREATE TABLE IF NOT EXISTS logs ("
    " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
    " line TEXT NOT NULL)",
    // ---- DEEP evidence ----
    "CREATE TABLE IF NOT EXISTS deep_episodes ("
    " ordinal INTEGER PRIMARY KEY,"
    " meta_json TEXT, summary_text TEXT)",
    "CREATE TABLE IF NOT EXISTS deep_series ("
    " ordinal INTEGER NOT NULL,"
    " phase INTEGER NOT NULL,"
    " ts_ns INTEGER NOT NULL, tid INTEGER NOT NULL,"
    " tgid INTEGER, comm TEXT, flags INTEGER,"
    " on_cpu_ns INTEGER, nr_sw_vol INTEGER, nr_sw_invol INTEGER,"
    " io_ops INTEGER, io_bytes INTEGER, io_hist TEXT,"
    " pf_minor INTEGER, pf_major INTEGER,"
    " lock_waits INTEGER, lock_lat_ns INTEGER, lock_hist TEXT,"
    " syscall_count INTEGER, syscall_lat_ns INTEGER, syscall_hist TEXT,"
    " futex_waits INTEGER, futex_lat_ns INTEGER, futex_hist TEXT,"
    " runq_wait_count INTEGER, runq_wait_ns INTEGER, runq_hist TEXT,"
    " PRIMARY KEY (ordinal, phase, ts_ns, tid)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS deep_gap ("
    " ordinal INTEGER NOT NULL, ts_ns INTEGER NOT NULL,"
    " from_head INTEGER, to_head INTEGER)",
    "CREATE TABLE IF NOT EXISTS deep_folded ("
    " ordinal INTEGER NOT NULL, kind TEXT NOT NULL,"
    " frames TEXT NOT NULL, value INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS deep_syscall ("
    " ordinal INTEGER NOT NULL, tid INTEGER, syscall INTEGER, name TEXT,"
    " count INTEGER, avg_us REAL, p50_us REAL, p99_us REAL, error_count INTEGER)",
    "CREATE TABLE IF NOT EXISTS deep_lock ("
    " ordinal INTEGER NOT NULL, addr TEXT, sym TEXT, count INTEGER,"
    " total_wait_ns INTEGER, avg_wait_ns INTEGER)",
    "CREATE TABLE IF NOT EXISTS deep_runq ("
    " ordinal INTEGER NOT NULL, tid INTEGER, count INTEGER,"
    " avg_us REAL, p50_us REAL, p99_us REAL)",
    "CREATE TABLE IF NOT EXISTS deep_iofile ("
    " ordinal INTEGER NOT NULL, dev INTEGER, ino INTEGER,"
    " path TEXT, bytes INTEGER, ops INTEGER, errors INTEGER,"
    " lat_sum INTEGER, hist TEXT, p50_us REAL, p99_us REAL)",
    // ---- DEEP process / io-device / network / gpu / offcpu evidence ----
    "CREATE TABLE IF NOT EXISTS deep_proc ("
    " ordinal INTEGER NOT NULL, ts_ns INTEGER NOT NULL, tid INTEGER NOT NULL,"
    " tgid INTEGER, comm TEXT,"
    " vm_rss_kb INTEGER, rss_anon_kb INTEGER, rss_file_kb INTEGER, rss_shmem_kb INTEGER,"
    " vm_swap_kb INTEGER, status_valid INTEGER,"
    " rchar INTEGER, wchar INTEGER, read_bytes INTEGER, write_bytes INTEGER,"
    " syscr INTEGER, syscw INTEGER, io_valid INTEGER,"
    " sched_exec_runtime_ns INTEGER, sched_run_delay_ns INTEGER, sched_switch_count INTEGER,"
    " sched_valid INTEGER, available INTEGER, error TEXT,"
    " PRIMARY KEY (ordinal, ts_ns, tid)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS deep_io_device ("
    " ordinal INTEGER NOT NULL, dev INTEGER NOT NULL,"
    " ops INTEGER, bytes INTEGER, lat_sum INTEGER, hist TEXT, p50_us REAL, p99_us REAL,"
    " PRIMARY KEY (ordinal, dev)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS deep_net_flow ("
    " ordinal INTEGER NOT NULL, cookie INTEGER NOT NULL,"
    " tgid INTEGER, tid INTEGER, netns_ino INTEGER, family INTEGER,"
    " local_addr INTEGER, local_port INTEGER, remote_addr INTEGER, remote_port INTEGER,"
    " final_state INTEGER, start_ts_ns INTEGER, established_ts_ns INTEGER, end_ts_ns INTEGER,"
    " duration_us INTEGER, connect_latency_us INTEGER, tx_bytes INTEGER, rx_bytes INTEGER,"
    " retransmits INTEGER, rst_reason INTEGER,"
    " rtt_count INTEGER, rtt_avg_us INTEGER, rtt_p50_us INTEGER, rtt_p99_us INTEGER,"
    " closed INTEGER, owner_available INTEGER, error TEXT,"
    " PRIMARY KEY (ordinal, cookie)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS deep_net_drop ("
    " ordinal INTEGER NOT NULL, netns_ino INTEGER NOT NULL, ifindex INTEGER NOT NULL,"
    " reason_id INTEGER NOT NULL, reason TEXT, count INTEGER,"
    " PRIMARY KEY (ordinal, netns_ino, ifindex, reason_id)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS deep_net_softirq ("
    " ordinal INTEGER NOT NULL, cpu_idx INTEGER NOT NULL, vector INTEGER NOT NULL,"
    " vector_name TEXT, count INTEGER, time_ns INTEGER, hist TEXT,"
    " PRIMARY KEY (ordinal, cpu_idx, vector)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS deep_gpu_process ("
    " ordinal INTEGER NOT NULL, ts_ns INTEGER NOT NULL, gpu_uuid TEXT NOT NULL,"
    " pid INTEGER NOT NULL, tgid INTEGER, comm TEXT, source TEXT,"
    " sm_util_pct REAL, mem_util_pct REAL, enc_util_pct REAL, dec_util_pct REAL,"
    " fb_used_bytes INTEGER, source_ts_us INTEGER, valid_mask INTEGER, error TEXT,"
    " PRIMARY KEY (ordinal, ts_ns, gpu_uuid, pid)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS deep_offcpu ("
    " ordinal INTEGER NOT NULL, tid INTEGER NOT NULL,"
    " tgid INTEGER, comm TEXT, dwell_ns INTEGER, count INTEGER, stack_available INTEGER,"
    " PRIMARY KEY (ordinal, tid)) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS idx_deep_folded ON deep_folded(ordinal, kind)",
};

// Immutable statement SQL table; indexed by Stmt. Entries are positional and
// MUST match the Stmt enum order above.
const char* const kSql[] = {
    // S_META_INS
    "INSERT INTO meta(key,value) VALUES(?,?)",
    // S_HOST_INS
    // S_HOST_CPU_INS
    "INSERT INTO host (ts_ns,cu_user,cu_nice,cu_sys,cu_idle,cu_iowait,"
    "cu_irq,cu_softirq,cu_steal,cu_guest,cu_guest_nice,"
    "load1,load5,load15,nr_running,nr_threads,"
    "mem_total_kb,mem_avail_kb,mem_free_kb,buffers_kb,cached_kb,"
    "swap_total_kb,swap_free_kb,anon_pages_kb,sreclaimable_kb,shmem_kb,dirty_kb,"
    "writeback_kb,commit_limit_kb,committed_as_kb,mem_valid_mask,"
    "vm_pgfault,vm_pgmajfault,vm_pswpin,vm_pswpout,vm_pgscan_kswapd,"
    "vm_pgscan_direct,vm_pgsteal_kswapd,vm_pgsteal_direct,vm_workingset_refault,"
    "vm_nr_dirty,vm_nr_writeback,vm_valid_mask,"
    "psi_cpu_s10,psi_cpu_s60,psi_cpu_s300,psi_cpu_s_valid,"
    "psi_cpu_f10,psi_cpu_f60,psi_cpu_f300,psi_cpu_f_valid,"
    "psi_io_s10,psi_io_s60,psi_io_s300,psi_io_s_valid,"
    "psi_io_f10,psi_io_f60,psi_io_f300,psi_io_f_valid,"
    "psi_mem_s10,psi_mem_s60,psi_mem_s300,psi_mem_s_valid,"
    "psi_mem_f10,psi_mem_f60,psi_mem_f300,psi_mem_f_valid,"
    "ctxt,processes,procs_running,procs_blocked) "
    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
    "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    "INSERT INTO host_cpu (ts_ns,cpu_idx,usr,nice,sys,idle,iowait,irq,softirq,steal,"
    "guest,guest_nice) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
    // S_HOST_DISK_INS
    "INSERT INTO host_disk (ts_ns,name,major,minor,reads_completed,"
    "writes_completed,sectors_read,sectors_written,io_ticks_ms,"
    "read_ticks_ms,write_ticks_ms,reads_merged,writes_merged,in_flight,"
    "weighted_ticks_ms,valid_mask) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    // S_HOST_PROC_INS
    "INSERT INTO host_proc (ts_ns,pid,tgid,state,start_time,utime,stime,"
    "nvcsw,nivcsw,minflt,majflt,total_vm,rss_kb,comm) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    // S_NET_STACK_INS
    "INSERT INTO net_stack (ts_ns,netns_ino,source,valid,error,"
    "active_opens,passive_opens,attempt_fails,estab_resets,curr_estab,"
    "in_segs,out_segs,retrans_segs,in_errs,out_rsts,"
    "listen_overflows,listen_drops,backlog_drop,rcv_q_drop,syn_retrans,"
    "timeouts,memory_pressures,udp_in_datagrams,udp_no_ports,udp_in_errors,"
    "udp_out_datagrams,udp_rcvbuf_errors,udp_sndbuf_errors,"
    "tcp_sock_mem,udp_sock_mem,frag_sock_mem,"
    "tcp_state_established,tcp_state_syn_sent,tcp_state_syn_recv,"
    "tcp_state_fin_wait1,tcp_state_fin_wait2,tcp_state_time_wait,"
    "tcp_state_close,tcp_state_close_wait,tcp_state_last_ack,"
    "tcp_state_listen,tcp_state_closing,rqueue_bytes,wqueue_bytes,tcp_states_valid) "
    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
    "?,?,?,?,?,?,?,?,?,?,?)",
    // S_NET_IFACE_INS
    "INSERT INTO net_iface (ts_ns,ifindex,name,operstate,mtu,source,valid,error,"
    "rx_bytes,rx_packets,rx_errors,rx_dropped,"
    "tx_bytes,tx_packets,tx_errors,tx_dropped,"
    "collisions,carrier_changes,rx_nohandler) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    // S_NET_SOFTNET_INS
    "INSERT INTO net_softnet (ts_ns,cpu_idx,processed,dropped,time_squeeze,"
    "received_rps,flow_limit_count,backlog_len,net_rx_softirq,net_tx_softirq,"
    "valid,error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
    // S_GPU_DEV_INS
    "INSERT INTO gpu_device (ts_ns,uuid,pci_bdf,vendor,model,source,available,is_mig,"
    "util_pct,mem_util_pct,mem_used_bytes,mem_total_bytes,temperature_c,power_w,"
    "power_limit_w,energy_mj,sm_clock_mhz,mem_clock_mhz,pcie_rx_kbps,pcie_tx_kbps,"
    "encoder_util_pct,decoder_util_pct,throttle_reasons,ecc_sbe_total,ecc_dbe_total,"
    "retired_pages,valid_mask,error_code,error_text) "
    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    // S_CGROUP_INS
    "INSERT INTO cgroup (ts_ns,available,cgroup_path,error,"
    "cpu_usage_usec,user_usec,system_usec,nr_periods,nr_throttled,throttled_usec,cpu_valid,"
    "memory_current_bytes,memory_max_bytes,memory_max_unlimited,"
    "memory_events_low,memory_events_high,memory_events_max,"
    "memory_events_oom,memory_events_oom_kill,memory_valid,"
    "cpu_psi_s10,cpu_psi_s60,cpu_psi_s300,cpu_psi_s_valid,"
    "cpu_psi_f10,cpu_psi_f60,cpu_psi_f300,cpu_psi_f_valid,"
    "memory_psi_s10,memory_psi_s60,memory_psi_s300,memory_psi_s_valid,"
    "memory_psi_f10,memory_psi_f60,memory_psi_f300,memory_psi_f_valid) "
    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    // S_CGROUP_IO_INS
    "INSERT INTO cgroup_io (ts_ns,major,minor,rbytes,wbytes,rios,wios,dbytes,dios) "
    "VALUES(?,?,?,?,?,?,?,?,?)",
    // S_ANOMALY_INS
    "INSERT INTO anomaly (ts_ns,seq,on_cpu_ns_total,switch_total,"
    "io_ops_total,io_bytes_total,minor_faults_total,major_faults_total,"
    "lock_waits_total) VALUES(?,?,?,?,?,?,?,?,?)",
    // S_ANOMALY_TID_INS
    "INSERT INTO anomaly_tid (ts_ns,tid,comm,on_cpu_ns,nr_sw_vol,"
    "nr_sw_invol,io_ops,io_bytes,pf_minor,pf_major,lock_waits,"
    "lock_lat_ns) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
    // S_TARGETS_INS
    "INSERT INTO targets_log (ts_ns,action,tgid,tid,comm,score,rank) "
    "VALUES(?,?,?,?,?,?,?)",
    // S_OOM_INS
    "INSERT INTO oom_events (ts_ns,pid,comm) VALUES(?,?,?)",
    // S_MEMEV_INS
    "INSERT INTO memory_events (ts_ns,kswapd_active,direct_reclaim,"
    "nr_reclaimed) VALUES(?,?,?,?)",
    // S_BPF_INS
    "INSERT INTO bpf_stats (ts_ns,prog_name,prog_id,run_cnt,run_time_ns,"
    "avg_ns,interval_ns) VALUES(?,?,?,?,?,?,?)",
    // S_OVERHEAD_INS
    "INSERT INTO proc_overhead (ts_ns,utime_ns,stime_ns,nvcsw,nivcsw,"
    "minflt,majflt,rss_kb,vmhwm_kb) VALUES(?,?,?,?,?,?,?,?,?)",
    // S_LOGS_INS
    "INSERT INTO logs (line) VALUES(?)",
    // S_EPISODE_INS
    "INSERT INTO deep_episodes (ordinal) VALUES(?)",
    // S_EPISODE_META
    "UPDATE deep_episodes SET meta_json=? WHERE ordinal=?",
    // S_EPISODE_SUMMARY
    "UPDATE deep_episodes SET summary_text=? WHERE ordinal=?",
    // S_SERIES_INS
    "INSERT INTO deep_series (ordinal,phase,ts_ns,tid,tgid,comm,flags,"
    "on_cpu_ns,nr_sw_vol,nr_sw_invol,io_ops,io_bytes,io_hist,"
    "pf_minor,pf_major,lock_waits,lock_lat_ns,lock_hist,"
    "syscall_count,syscall_lat_ns,syscall_hist,"
    "futex_waits,futex_lat_ns,futex_hist,"
    "runq_wait_count,runq_wait_ns,runq_hist) "
    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    // S_GAP_INS
    "INSERT INTO deep_gap (ordinal,ts_ns,from_head,to_head) VALUES(?,?,?,?)",
    // S_FOLDED_INS
    "INSERT INTO deep_folded (ordinal,kind,frames,value) VALUES(?,?,?,?)",
    // S_SYSCALL_INS
    "INSERT INTO deep_syscall (ordinal,tid,syscall,name,count,avg_us,p50_us,"
    "p99_us,error_count) VALUES(?,?,?,?,?,?,?,?,?)",
    // S_LOCK_INS
    "INSERT INTO deep_lock (ordinal,addr,sym,count,total_wait_ns,avg_wait_ns) "
    "VALUES(?,?,?,?,?,?)",
    // S_RUNQ_INS
    "INSERT INTO deep_runq (ordinal,tid,count,avg_us,p50_us,p99_us) "
    "VALUES(?,?,?,?,?,?)",
    // S_IOFILE_INS
    "INSERT INTO deep_iofile (ordinal,dev,ino,path,bytes,ops,errors,lat_sum,hist,"
    "p50_us,p99_us) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
    // S_DEEP_PROC_INS
    "INSERT INTO deep_proc (ordinal,ts_ns,tid,tgid,comm,"
    "vm_rss_kb,rss_anon_kb,rss_file_kb,rss_shmem_kb,vm_swap_kb,status_valid,"
    "rchar,wchar,read_bytes,write_bytes,syscr,syscw,io_valid,"
    "sched_exec_runtime_ns,sched_run_delay_ns,sched_switch_count,sched_valid,"
    "available,error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    // S_DEEP_IODEV_INS
    "INSERT INTO deep_io_device (ordinal,dev,ops,bytes,lat_sum,hist,p50_us,p99_us) "
    "VALUES(?,?,?,?,?,?,?,?)",
    // S_NET_FLOW_INS
    "INSERT INTO deep_net_flow (ordinal,cookie,tgid,tid,netns_ino,family,"
    "local_addr,local_port,remote_addr,remote_port,final_state,"
    "start_ts_ns,established_ts_ns,end_ts_ns,duration_us,connect_latency_us,"
    "tx_bytes,rx_bytes,retransmits,rst_reason,"
    "rtt_count,rtt_avg_us,rtt_p50_us,rtt_p99_us,closed,owner_available,error) "
    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    // S_NET_DROP_INS
    "INSERT INTO deep_net_drop (ordinal,netns_ino,ifindex,reason_id,reason,count) "
    "VALUES(?,?,?,?,?,?)",
    // S_NET_SOFTIRQ_INS
    "INSERT INTO deep_net_softirq (ordinal,cpu_idx,vector,vector_name,count,time_ns,hist) "
    "VALUES(?,?,?,?,?,?,?)",
    // S_DEEP_GPU_PROC_INS
    "INSERT INTO deep_gpu_process (ordinal,ts_ns,gpu_uuid,pid,tgid,comm,source,"
    "sm_util_pct,mem_util_pct,enc_util_pct,dec_util_pct,fb_used_bytes,source_ts_us,"
    "valid_mask,error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    // S_OFFCPU_INS
    "INSERT INTO deep_offcpu (ordinal,tid,tgid,comm,dwell_ns,count,stack_available) "
    "VALUES(?,?,?,?,?,?,?)",
    // S_TID_COMM_LOOKUP
    "SELECT comm FROM targets_log WHERE tid=? ORDER BY seq DESC LIMIT 1",
};

}  // namespace

sqlite3_stmt* OutputWriter::Prep(int idx) {
  if (!db_ || idx < 0 || idx >= stmt_count_) return nullptr;
  if (stmts_[idx]) return stmts_[idx];
  if (sqlite3_prepare_v2(db_, kSql[idx], -1, &stmts_[idx], nullptr) != SQLITE_OK) {
    LogError("sqlite prepare(%d): %s", idx, sqlite3_errmsg(db_));
    stmts_[idx] = nullptr;
    return nullptr;
  }
  return stmts_[idx];
}

bool OutputWriter::Step(int idx, const char* table) {
  sqlite3_stmt* st = Prep(idx);
  if (!st) return false;
  int rc = sqlite3_step(st);
  sqlite3_reset(st);
  if (rc != SQLITE_DONE) {
    LogError("sqlite write %s failed: %s", table, sqlite3_errmsg(db_));
    return false;
  }
  return true;
}

bool OutputWriter::Exec(const char* sql) {
  char* err = nullptr;
  if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
    LogError("sqlite exec failed: %s (%s)", err ? err : "?", sql);
    sqlite3_free(err);
    return false;
  }
  return true;
}

bool OutputWriter::Init(const Config& cfg) {
  std::string base = cfg.output.dir;
  if (base.empty()) base = "out";
  session_dir_ = base + "/" + NowDirName() + "_" + std::to_string(getpid());

  if (mkdir(cfg.output.dir.c_str(), 0755) != 0 && errno != EEXIST) {
    LogError("cannot create output dir '%s'", cfg.output.dir.c_str());
    return false;
  }
  if (mkdir(session_dir_.c_str(), 0755) != 0) {
    LogError("cannot create session dir '%s'", session_dir_.c_str());
    return false;
  }

  std::string dbp = db_path();
  if (sqlite3_open_v2(dbp.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                      nullptr) != SQLITE_OK) {
    LogError("cannot open database '%s': %s", dbp.c_str(),
             db_ ? sqlite3_errmsg(db_) : "open failed");
    if (db_) sqlite3_close(db_);
    db_ = nullptr;
    return false;
  }

  sqlite3_busy_timeout(db_, 2000);

  if (!Exec("PRAGMA journal_mode=WAL") || !Exec("PRAGMA synchronous=NORMAL") ||
      !Exec("PRAGMA temp_store=MEMORY") || !Exec("PRAGMA user_version=2")) {
    sqlite3_close(db_);
    db_ = nullptr;
    return false;
  }

  stmts_.reset(new sqlite3_stmt*[S_COUNT]());
  stmt_count_ = S_COUNT;

  for (const char* ddl : kDdl) {
    if (!Exec(ddl)) {
      sqlite3_close(db_);
      db_ = nullptr;
      return false;
    }
  }

  // meta rows: schema_version / created_wall / collector_pid
  if (!Exec("BEGIN IMMEDIATE")) {
    sqlite3_close(db_);
    db_ = nullptr;
    return false;
  }
  {
    sqlite3_stmt* st = Prep(S_META_INS);
    if (st) {
      std::string iso = NowIso();
      std::string pid = std::to_string(getpid());
      struct { const char* k; const char* v; } rows[3] = {
          {"schema_version", "2"},
          {"created_wall", iso.c_str()},
          {"collector_pid", pid.c_str()},
      };
      sqlite3_reset(st);
      for (const auto& r : rows) {
        sqlite3_reset(st);
        sqlite3_bind_text(st, 1, r.k, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, r.v, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE)
          LogError("meta insert failed: %s", sqlite3_errmsg(db_));
      }
      sqlite3_reset(st);
    }
  }
  Exec("COMMIT");

  LogInfo("session dir: %s (etrace.sqlite3)", session_dir_.c_str());
  return true;
}

void OutputWriter::Close() {
  if (!db_) return;
  if (batch_depth_ > 0) {
    Exec("ROLLBACK");
    batch_depth_ = 0;
  }
  Exec("PRAGMA wal_checkpoint(TRUNCATE)");
  if (stmts_) {
    for (int i = 0; i < stmt_count_; ++i) {
      if (stmts_[i]) sqlite3_finalize(stmts_[i]);
    }
    stmts_.reset();
  }
  sqlite3_close(db_);
  db_ = nullptr;
}

// ---------------------------------------------------------------------------
// BASE
// ---------------------------------------------------------------------------
void OutputWriter::WriteHostRow(const HostSnapshot& s, const NetworkSnapshot& net,
                                const GpuSnapshot& gpu, const CgroupSnapshot& cg) {
  if (!db_) return;
  sqlite3_stmt* st = Prep(S_HOST_INS);
  if (st) {
    sqlite3_reset(st);
    int c = 1;
    const uint32_t mv = s.mem.valid_mask;
    const uint32_t vv = s.vm.valid_mask;
    sqlite3_bind_int64(st, c++, (sqlite3_int64)s.ts_ns);
    sqlite3_bind_int64(st, c++, s.total.user);
    sqlite3_bind_int64(st, c++, s.total.nice);
    sqlite3_bind_int64(st, c++, s.total.system);
    sqlite3_bind_int64(st, c++, s.total.idle);
    sqlite3_bind_int64(st, c++, s.total.iowait);
    sqlite3_bind_int64(st, c++, s.total.irq);
    sqlite3_bind_int64(st, c++, s.total.softirq);
    sqlite3_bind_int64(st, c++, s.total.steal);
    sqlite3_bind_int64(st, c++, s.total.guest);
    sqlite3_bind_int64(st, c++, s.total.guest_nice);
    sqlite3_bind_double(st, c++, s.load.load1);
    sqlite3_bind_double(st, c++, s.load.load5);
    sqlite3_bind_double(st, c++, s.load.load15);
    sqlite3_bind_int64(st, c++, s.load.nr_running);
    sqlite3_bind_int64(st, c++, s.load.nr_threads);
    BindU64(st, c, s.mem.mem_total_kb, mv & (1u << 0));
    BindU64(st, c, s.mem.mem_available_kb, mv & (1u << 1));
    BindU64(st, c, s.mem.mem_free_kb, mv & (1u << 2));
    BindU64(st, c, s.mem.buffers_kb, mv & (1u << 3));
    BindU64(st, c, s.mem.cached_kb, mv & (1u << 4));
    BindU64(st, c, s.mem.swap_total_kb, mv & (1u << 5));
    BindU64(st, c, s.mem.swap_free_kb, mv & (1u << 6));
    BindU64(st, c, s.mem.anon_pages_kb, mv & (1u << 7));
    BindU64(st, c, s.mem.sreclaimable_kb, mv & (1u << 8));
    BindU64(st, c, s.mem.shmem_kb, mv & (1u << 9));
    BindU64(st, c, s.mem.dirty_kb, mv & (1u << 10));
    BindU64(st, c, s.mem.writeback_kb, mv & (1u << 11));
    BindU64(st, c, s.mem.commit_limit_kb, mv & (1u << 12));
    BindU64(st, c, s.mem.committed_as_kb, mv & (1u << 13));
    sqlite3_bind_int64(st, c++, (sqlite3_int64)mv);
    BindU64(st, c, s.vm.pgfault, vv & (1u << 0));
    BindU64(st, c, s.vm.pgmajfault, vv & (1u << 1));
    BindU64(st, c, s.vm.pswpin, vv & (1u << 2));
    BindU64(st, c, s.vm.pswpout, vv & (1u << 3));
    BindU64(st, c, s.vm.pgscan_kswapd, vv & (1u << 4));
    BindU64(st, c, s.vm.pgscan_direct, vv & (1u << 5));
    BindU64(st, c, s.vm.pgsteal_kswapd, vv & (1u << 6));
    BindU64(st, c, s.vm.pgsteal_direct, vv & (1u << 7));
    BindU64(st, c, s.vm.workingset_refault, vv & (1u << 8));
    BindU64(st, c, s.vm.nr_dirty, vv & (1u << 9));
    BindU64(st, c, s.vm.nr_writeback, vv & (1u << 10));
    sqlite3_bind_int64(st, c++, (sqlite3_int64)vv);
    const PsiWindow* psis[3] = {&s.psi.cpu, &s.psi.io, &s.psi.memory};
    for (int k = 0; k < 3; ++k) {
      const PsiWindow& p = *psis[k];
      if (p.some_valid) {
        sqlite3_bind_double(st, c++, p.avg10);
        sqlite3_bind_double(st, c++, p.avg60);
        sqlite3_bind_double(st, c++, p.avg300);
      } else {
        sqlite3_bind_null(st, c++);
        sqlite3_bind_null(st, c++);
        sqlite3_bind_null(st, c++);
      }
      BindBool(st, c, p.some_valid);
      if (p.full_valid) {
        sqlite3_bind_double(st, c++, p.avg10);
        sqlite3_bind_double(st, c++, p.avg60);
        sqlite3_bind_double(st, c++, p.avg300);
      } else {
        sqlite3_bind_null(st, c++);
        sqlite3_bind_null(st, c++);
        sqlite3_bind_null(st, c++);
      }
      BindBool(st, c, p.full_valid);
    }
    sqlite3_bind_int64(st, c++, (sqlite3_int64)s.ctxt);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)s.processes);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)s.procs_running);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)s.procs_blocked);
    Step(S_HOST_INS, "host");
  }

  size_t ci = 0;
  for (const auto& cpu : s.cpus) {
    st = Prep(S_HOST_CPU_INS);
    if (!st) return;
    sqlite3_reset(st);
    int c = 1;
    sqlite3_bind_int64(st, c++, (sqlite3_int64)s.ts_ns);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)ci);
    sqlite3_bind_int64(st, c++, cpu.user);
    sqlite3_bind_int64(st, c++, cpu.nice);
    sqlite3_bind_int64(st, c++, cpu.system);
    sqlite3_bind_int64(st, c++, cpu.idle);
    sqlite3_bind_int64(st, c++, cpu.iowait);
    sqlite3_bind_int64(st, c++, cpu.irq);
    sqlite3_bind_int64(st, c++, cpu.softirq);
    sqlite3_bind_int64(st, c++, cpu.steal);
    sqlite3_bind_int64(st, c++, cpu.guest);
    sqlite3_bind_int64(st, c++, cpu.guest_nice);
    Step(S_HOST_CPU_INS, "host_cpu");
    ++ci;
  }

  for (const auto& d : s.disks) {
    st = Prep(S_HOST_DISK_INS);
    if (!st) return;
    sqlite3_reset(st);
    int c = 1;
    const uint32_t dv = d.valid_mask;
    sqlite3_bind_int64(st, c++, (sqlite3_int64)s.ts_ns);
    sqlite3_bind_text(st, c++, d.name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, c++, d.major);
    sqlite3_bind_int64(st, c++, d.minor);
    BindU64(st, c, d.reads_completed, dv & (1u << 0));
    BindU64(st, c, d.writes_completed, dv & (1u << 4));
    BindU64(st, c, d.sectors_read, dv & (1u << 2));
    BindU64(st, c, d.sectors_written, dv & (1u << 6));
    BindU64(st, c, d.read_ticks_ms, dv & (1u << 3));
    BindU64(st, c, d.write_ticks_ms, dv & (1u << 7));
    BindU64(st, c, d.reads_merged, dv & (1u << 1));
    BindU64(st, c, d.writes_merged, dv & (1u << 5));
    BindU64(st, c, d.ios_in_flight, dv & (1u << 8));
    BindU64(st, c, d.weighted_ticks_ms, dv & (1u << 10));
    sqlite3_bind_int64(st, c++, (sqlite3_int64)dv);
    Step(S_HOST_DISK_INS, "host_disk");
  }

  for (const auto& p : s.procs) {
    st = Prep(S_HOST_PROC_INS);
    if (!st) return;
    sqlite3_reset(st);
    int c = 1;
    sqlite3_bind_int64(st, c++, (sqlite3_int64)s.ts_ns);
    sqlite3_bind_int64(st, c++, p.pid);
    sqlite3_bind_int64(st, c++, p.tgid);
    sqlite3_bind_int64(st, c++, p.state);
    sqlite3_bind_int64(st, c++, p.start_time);
    sqlite3_bind_int64(st, c++, p.utime);
    sqlite3_bind_int64(st, c++, p.stime);
    sqlite3_bind_int64(st, c++, p.nvcsw);
    sqlite3_bind_int64(st, c++, p.nivcsw);
    sqlite3_bind_int64(st, c++, p.minflt);
    sqlite3_bind_int64(st, c++, p.majflt);
    sqlite3_bind_int64(st, c++, p.total_vm);
    if (p.rss_valid)
      sqlite3_bind_int64(st, c++, (sqlite3_int64)p.rss_kb);
    else
      sqlite3_bind_null(st, c++);
    sqlite3_bind_text(st, c++, p.comm, -1, SQLITE_TRANSIENT);
    Step(S_HOST_PROC_INS, "host_proc");
  }

  // network: one net_stack row + per-iface/per-cpu rows
  {
    const auto& t = net.stack;
    st = Prep(S_NET_STACK_INS);
    if (st) {
      sqlite3_reset(st);
      int c = 1;
      sqlite3_bind_int64(st, c++, (sqlite3_int64)net.ts_ns);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.netns_ino);
      BindText(st, c, t.source);
      BindBool(st, c, t.valid);
      BindText(st, c, t.error);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.active_opens);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.passive_opens);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.attempt_fails);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.estab_resets);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.curr_estab);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.in_segs);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.out_segs);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.retrans_segs);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.in_errs);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.out_rsts);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.listen_overflows);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.listen_drops);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.backlog_drop);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.rcv_q_drop);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.syn_retrans);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.timeouts);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.memory_pressures);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.udp_in_datagrams);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.udp_no_ports);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.udp_in_errors);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.udp_out_datagrams);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.udp_rcvbuf_errors);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.udp_sndbuf_errors);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.tcp_sock_mem);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.udp_sock_mem);
      sqlite3_bind_int64(st, c++, (sqlite3_int64)t.frag_sock_mem);
      auto bind_state = [&](uint64_t v) {
        if (t.tcp_states_valid)
          sqlite3_bind_int64(st, c++, (sqlite3_int64)v);
        else
          sqlite3_bind_null(st, c++);
      };
      bind_state(t.tcp_state_established);
      bind_state(t.tcp_state_syn_sent);
      bind_state(t.tcp_state_syn_recv);
      bind_state(t.tcp_state_fin_wait1);
      bind_state(t.tcp_state_fin_wait2);
      bind_state(t.tcp_state_time_wait);
      bind_state(t.tcp_state_close);
      bind_state(t.tcp_state_close_wait);
      bind_state(t.tcp_state_last_ack);
      bind_state(t.tcp_state_listen);
      bind_state(t.tcp_state_closing);
      bind_state(t.rqueue_bytes);
      bind_state(t.wqueue_bytes);
      BindBool(st, c, t.tcp_states_valid);
      Step(S_NET_STACK_INS, "net_stack");
    }
  }
  for (const auto& i : net.ifaces) {
    st = Prep(S_NET_IFACE_INS);
    if (!st) return;
    sqlite3_reset(st);
    int c = 1;
    sqlite3_bind_int64(st, c++, (sqlite3_int64)net.ts_ns);
    sqlite3_bind_int64(st, c++, i.ifindex);
    BindText(st, c, i.name);
    if (i.operstate >= 0)
      sqlite3_bind_int(st, c++, i.operstate);
    else
      sqlite3_bind_null(st, c++);
    sqlite3_bind_int64(st, c++, i.mtu);
    BindText(st, c, "netlink");
    BindBool(st, c, i.valid);
    BindText(st, c, i.error);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)i.rx_bytes);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)i.rx_packets);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)i.rx_errors);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)i.rx_dropped);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)i.tx_bytes);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)i.tx_packets);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)i.tx_errors);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)i.tx_dropped);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)i.collisions);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)i.carrier_changes);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)i.rx_nohandler);
    Step(S_NET_IFACE_INS, "net_iface");
  }
  for (const auto& n : net.softnets) {
    st = Prep(S_NET_SOFTNET_INS);
    if (!st) return;
    sqlite3_reset(st);
    int c = 1;
    sqlite3_bind_int64(st, c++, (sqlite3_int64)net.ts_ns);
    sqlite3_bind_int64(st, c++, n.cpu_idx);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)n.processed);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)n.dropped);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)n.time_squeeze);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)n.received_rps);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)n.flow_limit_count);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)n.backlog_len);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)n.net_rx_softirq);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)n.net_tx_softirq);
    BindBool(st, c, n.valid);
    BindText(st, c, n.error);
    Step(S_NET_SOFTNET_INS, "net_softnet");
  }

  // GPU: one row per device per tick (disabled/unavailable devices included).
  for (const auto& d : gpu.devices) {
    st = Prep(S_GPU_DEV_INS);
    if (!st) return;
    sqlite3_reset(st);
    int c = 1;
    sqlite3_bind_int64(st, c++, (sqlite3_int64)gpu.ts_ns);
    BindText(st, c, d.uuid);
    BindText(st, c, d.pci_bdf);
    BindText(st, c, d.vendor);
    BindText(st, c, d.model);
    BindText(st, c, d.source);
    BindBool(st, c, d.available);
    BindBool(st, c, d.is_mig);
    sqlite3_bind_double(st, c++, d.util_pct);
    sqlite3_bind_double(st, c++, d.mem_util_pct);
    BindU64(st, c, d.mem_used_bytes, d.valid_mask & (1u << 2));
    BindU64(st, c, d.mem_total_bytes, d.valid_mask & (1u << 3));
    sqlite3_bind_double(st, c++, d.temperature_c);
    sqlite3_bind_double(st, c++, d.power_w);
    sqlite3_bind_double(st, c++, d.power_limit_w);
    BindU64(st, c, d.energy_mj, d.valid_mask & (1u << 7));
    sqlite3_bind_int(st, c++, (int)d.sm_clock_mhz);
    sqlite3_bind_int(st, c++, (int)d.mem_clock_mhz);
    BindU64(st, c, d.pcie_rx_kbps, d.valid_mask & (1u << 10));
    BindU64(st, c, d.pcie_tx_kbps, d.valid_mask & (1u << 11));
    sqlite3_bind_double(st, c++, d.encoder_util_pct);
    sqlite3_bind_double(st, c++, d.decoder_util_pct);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)d.throttle_reasons);
    BindU64(st, c, d.ecc_sbe_total, d.valid_mask & (1u << 15));
    BindU64(st, c, d.ecc_dbe_total, d.valid_mask & (1u << 16));
    BindU64(st, c, d.retired_pages, d.valid_mask & (1u << 17));
    sqlite3_bind_int64(st, c++, (sqlite3_int64)d.valid_mask);
    sqlite3_bind_int(st, c++, (int)d.error_code);
    BindText(st, c, d.error_text);
    Step(S_GPU_DEV_INS, "gpu_device");
  }

  // cgroup
  {
    st = Prep(S_CGROUP_INS);
    if (st) {
      sqlite3_reset(st);
      int c = 1;
      sqlite3_bind_int64(st, c++, (sqlite3_int64)cg.ts_ns);
      BindBool(st, c, cg.available);
      BindText(st, c, cg.cgroup_path);
      BindText(st, c, cg.error);
      BindU64(st, c, cg.cpu_usage_usec, cg.cpu_valid);
      BindU64(st, c, cg.user_usec, cg.cpu_valid);
      BindU64(st, c, cg.system_usec, cg.cpu_valid);
      BindU64(st, c, cg.nr_periods, cg.cpu_valid);
      BindU64(st, c, cg.nr_throttled, cg.cpu_valid);
      BindU64(st, c, cg.throttled_usec, cg.cpu_valid);
      BindBool(st, c, cg.cpu_valid);
      BindU64(st, c, cg.memory_current_bytes, cg.memory_valid);
      if (cg.memory_valid && cg.memory_max_unlimited)
        sqlite3_bind_null(st, c++);
      else
        BindU64(st, c, cg.memory_max_bytes, cg.memory_valid);
      if (cg.memory_valid)
        BindBool(st, c, cg.memory_max_unlimited);
      else
        sqlite3_bind_null(st, c++);
      BindU64(st, c, cg.memory_events_low, cg.memory_valid);
      BindU64(st, c, cg.memory_events_high, cg.memory_valid);
      BindU64(st, c, cg.memory_events_max, cg.memory_valid);
      BindU64(st, c, cg.memory_events_oom, cg.memory_valid);
      BindU64(st, c, cg.memory_events_oom_kill, cg.memory_valid);
      BindBool(st, c, cg.memory_valid);
      const PsiWindow* cps[2] = {&cg.cpu_psi, &cg.memory_psi};
      for (int k = 0; k < 2; ++k) {
        const PsiWindow& p = *cps[k];
        if (p.some_valid) {
          sqlite3_bind_double(st, c++, p.avg10);
          sqlite3_bind_double(st, c++, p.avg60);
          sqlite3_bind_double(st, c++, p.avg300);
        } else {
          sqlite3_bind_null(st, c++);
          sqlite3_bind_null(st, c++);
          sqlite3_bind_null(st, c++);
        }
        BindBool(st, c, p.some_valid);
        if (p.full_valid) {
          sqlite3_bind_double(st, c++, p.avg10);
          sqlite3_bind_double(st, c++, p.avg60);
          sqlite3_bind_double(st, c++, p.avg300);
        } else {
          sqlite3_bind_null(st, c++);
          sqlite3_bind_null(st, c++);
          sqlite3_bind_null(st, c++);
        }
        BindBool(st, c, p.full_valid);
      }
      Step(S_CGROUP_INS, "cgroup");
    }
  }
  for (const auto& io : cg.io) {
    st = Prep(S_CGROUP_IO_INS);
    if (!st) return;
    sqlite3_reset(st);
    int c = 1;
    sqlite3_bind_int64(st, c++, (sqlite3_int64)cg.ts_ns);
    sqlite3_bind_int(st, c++, (int)io.major);
    sqlite3_bind_int(st, c++, (int)io.minor);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)io.rbytes);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)io.wbytes);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)io.rios);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)io.wios);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)io.dbytes);
    sqlite3_bind_int64(st, c++, (sqlite3_int64)io.dios);
    Step(S_CGROUP_IO_INS, "cgroup_io");
  }
}

void OutputWriter::WriteAnomalyFeatures(const nlohmann::json& f) {
  if (!db_) return;
  uint64_t ts = f.value("ts_ns", 0ULL);
  const nlohmann::json& eb = f.value("ebpf", nlohmann::json::object());

  sqlite3_stmt* st = Prep(S_ANOMALY_INS);
  if (st) {
    sqlite3_reset(st);
    int c = 1;
    sqlite3_bind_int64(st, c++, (sqlite3_int64)ts);
    sqlite3_bind_int64(st, c++, f.value("seq", 0ULL));
    sqlite3_bind_int64(st, c++, eb.value("on_cpu_ns_total", 0ULL));
    sqlite3_bind_int64(st, c++, eb.value("switch_total", 0ULL));
    sqlite3_bind_int64(st, c++, eb.value("io_ops_total", 0ULL));
    sqlite3_bind_int64(st, c++, eb.value("io_bytes_total", 0ULL));
    sqlite3_bind_int64(st, c++, eb.value("minor_faults_total", 0ULL));
    sqlite3_bind_int64(st, c++, eb.value("major_faults_total", 0ULL));
    sqlite3_bind_int64(st, c++, eb.value("lock_waits_total", 0ULL));
    Step(S_ANOMALY_INS, "anomaly");
  }

  for (const auto& t : eb.value("per_tid", nlohmann::json::array())) {
    st = Prep(S_ANOMALY_TID_INS);
    if (!st) return;
    sqlite3_reset(st);
    uint32_t tid = t.value("tid", 0U);
    std::string comm = LatestTidComm(db_, tid);
    int c = 1;
    sqlite3_bind_int64(st, c++, (sqlite3_int64)ts);
    sqlite3_bind_int64(st, c++, tid);
    sqlite3_bind_text(st, c++, comm.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, c++, t.value("on_cpu_ns", 0ULL));
    sqlite3_bind_int64(st, c++, t.value("nr_sw_vol", 0ULL));
    sqlite3_bind_int64(st, c++, t.value("nr_sw_invol", 0ULL));
    sqlite3_bind_int64(st, c++, t.value("io_ops", 0ULL));
    sqlite3_bind_int64(st, c++, t.value("io_bytes", 0ULL));
    sqlite3_bind_int64(st, c++, t.value("pf_minor", 0ULL));
    sqlite3_bind_int64(st, c++, t.value("pf_major", 0ULL));
    sqlite3_bind_int64(st, c++, t.value("lock_waits", 0ULL));
    sqlite3_bind_int64(st, c++, t.value("lock_lat_ns", 0ULL));
    Step(S_ANOMALY_TID_INS, "anomaly_tid");
  }
}

void OutputWriter::WriteTargetsEvent(const nlohmann::json& e) {
  if (!db_) return;
  sqlite3_stmt* st = Prep(S_TARGETS_INS);
  if (!st) return;
  sqlite3_reset(st);
  int c = 1;
  sqlite3_bind_int64(st, c++, e.value("ts_ns", 0ULL));
  sqlite3_bind_text(st, c++, e.value("action", "").c_str(), -1, SQLITE_TRANSIENT);
  if (e.contains("tgid") && e["tgid"].is_number_integer())
    sqlite3_bind_int64(st, c++, e["tgid"].get<int64_t>());
  else
    sqlite3_bind_null(st, c++);
  sqlite3_bind_int64(st, c++, e.value("tid", 0U));
  sqlite3_bind_text(st, c++, e.value("comm", "").c_str(), -1, SQLITE_TRANSIENT);
  if (e.contains("score") && e["score"].is_number())
    sqlite3_bind_double(st, c++, e["score"].get<double>());
  else
    sqlite3_bind_null(st, c++);
  if (e.contains("rank") && e["rank"].is_number_integer())
    sqlite3_bind_int64(st, c++, e["rank"].get<int64_t>());
  else
    sqlite3_bind_null(st, c++);
  Step(S_TARGETS_INS, "targets_log");
}

void OutputWriter::WriteMemoryEvent(const nlohmann::json& e) {
  if (!db_) return;
  uint64_t ts = e.value("ts_ns", 0ULL);
  if (e.contains("pid")) {
    sqlite3_stmt* st = Prep(S_OOM_INS);
    if (!st) return;
    sqlite3_reset(st);
    sqlite3_bind_int64(st, 1, (sqlite3_int64)ts);
    sqlite3_bind_int64(st, 2, e["pid"].get<int64_t>());
    sqlite3_bind_text(st, 3, e.value("comm", "").c_str(), -1, SQLITE_TRANSIENT);
    Step(S_OOM_INS, "oom_events");
  } else {
    sqlite3_stmt* st = Prep(S_MEMEV_INS);
    if (!st) return;
    sqlite3_reset(st);
    sqlite3_bind_int64(st, 1, (sqlite3_int64)ts);
    sqlite3_bind_int64(st, 2, e.value("kswapd_active", 0U));
    sqlite3_bind_int64(st, 3, e.value("direct_reclaim", 0U));
    sqlite3_bind_int64(st, 4, e.value("nr_reclaimed", 0ULL));
    Step(S_MEMEV_INS, "memory_events");
  }
}

void OutputWriter::WriteBpfStats(const BpfStatsSnapshot& s) {
  if (!db_) return;
  for (const auto& p : s.progs) {
    sqlite3_stmt* st = Prep(S_BPF_INS);
    if (!st) return;
    sqlite3_reset(st);
    sqlite3_bind_int64(st, 1, (sqlite3_int64)s.ts_ns);
    sqlite3_bind_text(st, 2, p.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, p.id);
    sqlite3_bind_int64(st, 4, p.run_cnt);
    sqlite3_bind_int64(st, 5, p.run_time_ns);
    sqlite3_bind_double(st, 6, p.run_cnt ? (double)p.run_time_ns / (double)p.run_cnt : 0.0);
    sqlite3_bind_int64(st, 7, (sqlite3_int64)s.interval_ns);
    Step(S_BPF_INS, "bpf_stats");
  }
}

void OutputWriter::WriteProcOverhead(const ProcOverhead& s) {
  if (!db_) return;
  sqlite3_stmt* st = Prep(S_OVERHEAD_INS);
  if (!st) return;
  sqlite3_reset(st);
  sqlite3_bind_int64(st, 1, (sqlite3_int64)s.ts_ns);
  sqlite3_bind_int64(st, 2, s.utime_ns);
  sqlite3_bind_int64(st, 3, s.stime_ns);
  sqlite3_bind_int64(st, 4, s.nvcsw);
  sqlite3_bind_int64(st, 5, s.nivcsw);
  sqlite3_bind_int64(st, 6, s.minflt);
  sqlite3_bind_int64(st, 7, s.majflt);
  sqlite3_bind_int64(st, 8, s.rss_kb);
  sqlite3_bind_int64(st, 9, s.vmhwm_kb);
  Step(S_OVERHEAD_INS, "proc_overhead");
}

void OutputWriter::WriteLogLine(const std::string& line) {
  if (!db_) return;
  sqlite3_stmt* st = Prep(S_LOGS_INS);
  if (!st) return;
  sqlite3_reset(st);
  sqlite3_bind_text(st, 1, line.c_str(), -1, SQLITE_TRANSIENT);
  Step(S_LOGS_INS, "logs");
}

// ---------------------------------------------------------------------------
// DEEP
// ---------------------------------------------------------------------------
bool OutputWriter::OpenDeep(int ordinal) {
  if (!db_) return false;
  ordinal_ = ordinal;
  last_deep_ts_ = 0;
  sqlite3_stmt* st = Prep(S_EPISODE_INS);
  if (!st) return false;
  sqlite3_reset(st);
  sqlite3_bind_int(st, 1, ordinal);
  return Step(S_EPISODE_INS, "deep_episodes");
}

void OutputWriter::CloseDeep() {
  ordinal_ = -1;
  last_deep_ts_ = 0;
}

void OutputWriter::WritePreSeries(const CanonicalSnapshot& s) { WriteSeries(0, s); }
void OutputWriter::WritePostSeries(const CanonicalSnapshot& s) { WriteSeries(1, s); }

void OutputWriter::WriteSeries(int phase, const CanonicalSnapshot& s) {
  if (!db_ || ordinal_ < 0) return;
  last_deep_ts_ = s.ts_ns;
  sqlite3_stmt* st = Prep(S_SERIES_INS);
  if (!st) return;
  sqlite3_reset(st);
  int c = 1;
  sqlite3_bind_int(st, c++, ordinal_);
  sqlite3_bind_int(st, c++, phase);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)s.ts_ns);
  sqlite3_bind_int64(st, c++, s.tid);
  sqlite3_bind_int64(st, c++, s.tgid);
  sqlite3_bind_text(st, c++, s.comm, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, c++, s.flags);
  sqlite3_bind_int64(st, c++, s.on_cpu_ns);
  sqlite3_bind_int64(st, c++, s.nr_sw_vol);
  sqlite3_bind_int64(st, c++, s.nr_sw_invol);
  sqlite3_bind_int64(st, c++, s.io_ops);
  sqlite3_bind_int64(st, c++, s.io_bytes);
  std::string io_hist = HistJson(s.io_hist, kBase4HistBins);
  sqlite3_bind_text(st, c++, io_hist.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, c++, s.pf_minor);
  sqlite3_bind_int64(st, c++, s.pf_major);
  sqlite3_bind_int64(st, c++, s.lock_waits);
  sqlite3_bind_int64(st, c++, s.lock_lat_ns);
  std::string lock_hist = HistJson(s.lock_hist, kBase4HistBins);
  sqlite3_bind_text(st, c++, lock_hist.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, c++, s.syscall_count);
  sqlite3_bind_int64(st, c++, s.syscall_lat_ns);
  std::string syscall_hist = HistJson(s.syscall_hist, kBase4HistBins);
  sqlite3_bind_text(st, c++, syscall_hist.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, c++, s.futex_waits);
  sqlite3_bind_int64(st, c++, s.futex_lat_ns);
  std::string futex_hist = HistJson(s.futex_hist, kBase4HistBins);
  sqlite3_bind_text(st, c++, futex_hist.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, c++, s.runq_wait_count);
  sqlite3_bind_int64(st, c++, s.runq_wait_ns);
  std::string runq_hist = HistJson(s.runq_hist, kBase4HistBins);
  sqlite3_bind_text(st, c++, runq_hist.c_str(), -1, SQLITE_TRANSIENT);
  Step(S_SERIES_INS, "deep_series");
}

void OutputWriter::WritePostSeriesGap(uint64_t from_head, uint64_t to_head) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_GAP_INS);
  if (!st) return;
  sqlite3_reset(st);
  sqlite3_bind_int(st, 1, ordinal_);
  sqlite3_bind_int64(st, 2, (sqlite3_int64)last_deep_ts_);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)from_head);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)to_head);
  Step(S_GAP_INS, "deep_gap");
}

void OutputWriter::WriteMeta(const nlohmann::json& meta_json) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_EPISODE_META);
  if (!st) return;
  sqlite3_reset(st);
  std::string s = meta_json.dump();
  sqlite3_bind_text(st, 1, s.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(st, 2, ordinal_);
  Step(S_EPISODE_META, "deep_episodes.meta_json");
}

void OutputWriter::WriteSummary(const std::string& content) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_EPISODE_SUMMARY);
  if (!st) return;
  sqlite3_reset(st);
  sqlite3_bind_text(st, 1, content.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(st, 2, ordinal_);
  Step(S_EPISODE_SUMMARY, "deep_episodes.summary_text");
}

nlohmann::json OutputWriter::BuildEvidence(int ordinal) {
  nlohmann::json ev;
  ev["series"] = nlohmann::json::array();
  ev["events"] = nlohmann::json::object();
  if (!db_) return ev;

  auto prep = [&](const char* sql, int arg) -> sqlite3_stmt* {
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) {
      LogWarn("evidence prep failed: %s", sqlite3_errmsg(db_));
      return nullptr;
    }
    sqlite3_bind_int(st, 1, arg);
    return st;
  };

  // ---- deep_series: per-(tick,tgid) process series + per-tid thread series.
  // Process entities carry resource counters; thread entities carry the
  // latency/contention metrics where thread identity matters (lock/runq/
  // futex/syscall). tgid==0 rows degrade to per-tid entities only.
  struct TAcc { uint64_t cpu = 0, io_ops = 0, io_bytes = 0, pf_min = 0, pf_maj = 0,
                 lock_w = 0, lock_lat = 0, futex_w = 0, futex_lat = 0,
                 sys_c = 0, sys_lat = 0, runq_c = 0, runq_lat = 0; };
  std::map<uint64_t, std::map<uint32_t, TAcc>> per_ts_proc;  // ts -> tgid -> acc
  {
    sqlite3_stmt* st = prep(
        "SELECT ts_ns, tid, tgid, on_cpu_ns, io_ops, io_bytes, pf_minor, pf_major,"
        " lock_waits, lock_lat_ns, futex_waits, futex_lat_ns, syscall_count,"
        " syscall_lat_ns, runq_wait_count, runq_wait_ns FROM deep_series"
        " WHERE ordinal = ? ORDER BY ts_ns, tid",
        ordinal);
    if (st) {
      while (sqlite3_step(st) == SQLITE_ROW) {
        uint64_t ts = (uint64_t)sqlite3_column_int64(st, 0);
        uint32_t tid = (uint32_t)sqlite3_column_int64(st, 1);
        uint32_t tgid = (uint32_t)sqlite3_column_int64(st, 2);
        if (tgid != 0) {
          TAcc& a = per_ts_proc[ts][tgid];
          a.cpu += (uint64_t)sqlite3_column_int64(st, 3);
          a.io_ops += (uint64_t)sqlite3_column_int64(st, 4);
          a.io_bytes += (uint64_t)sqlite3_column_int64(st, 5);
          a.pf_min += (uint64_t)sqlite3_column_int64(st, 6);
          a.pf_maj += (uint64_t)sqlite3_column_int64(st, 7);
          a.lock_w += (uint64_t)sqlite3_column_int64(st, 8);
          a.lock_lat += (uint64_t)sqlite3_column_int64(st, 9);
          a.futex_w += (uint64_t)sqlite3_column_int64(st, 10);
          a.futex_lat += (uint64_t)sqlite3_column_int64(st, 11);
          a.sys_c += (uint64_t)sqlite3_column_int64(st, 12);
          a.sys_lat += (uint64_t)sqlite3_column_int64(st, 13);
          a.runq_c += (uint64_t)sqlite3_column_int64(st, 14);
          a.runq_lat += (uint64_t)sqlite3_column_int64(st, 15);
        }
        // per-thread contention/latency series
        auto trow = [&](const char* metric, uint64_t v) {
          ev["series"].push_back({{"entity", "t" + std::to_string(tid)},
                                  {"metric", metric}, {"ts_ns", ts}, {"value", v}});
        };
        trow("on_cpu_ns", (uint64_t)sqlite3_column_int64(st, 3));
        trow("lock_waits", (uint64_t)sqlite3_column_int64(st, 8));
        trow("lock_lat_ns", (uint64_t)sqlite3_column_int64(st, 9));
        trow("futex_waits", (uint64_t)sqlite3_column_int64(st, 10));
        trow("futex_lat_ns", (uint64_t)sqlite3_column_int64(st, 11));
        trow("syscall_count", (uint64_t)sqlite3_column_int64(st, 12));
        trow("syscall_lat_ns", (uint64_t)sqlite3_column_int64(st, 13));
        trow("runq_wait_count", (uint64_t)sqlite3_column_int64(st, 14));
        trow("runq_wait_ns", (uint64_t)sqlite3_column_int64(st, 15));
      }
      sqlite3_finalize(st);
    }
    for (const auto& [ts, by_tgid] : per_ts_proc) {
      for (const auto& [tgid, a] : by_tgid) {
        auto prow = [&](const char* metric, uint64_t v) {
          ev["series"].push_back({{"entity", "proc" + std::to_string(tgid)},
                                  {"metric", metric}, {"ts_ns", ts}, {"value", v}});
        };
        prow("on_cpu_ns", a.cpu); prow("io_ops", a.io_ops); prow("io_bytes", a.io_bytes);
        prow("pf_minor", a.pf_min); prow("pf_major", a.pf_maj);
        prow("lock_waits", a.lock_w); prow("lock_lat_ns", a.lock_lat);
        prow("futex_waits", a.futex_w); prow("futex_lat_ns", a.futex_lat);
        prow("syscall_count", a.sys_c); prow("syscall_lat_ns", a.sys_lat);
        prow("runq_wait_count", a.runq_c); prow("runq_wait_ns", a.runq_lat);
      }
    }
  }

  // ---- host-level memory pressure series
  {
    sqlite3_stmt* st = prep(
        "SELECT ts_ns, kswapd_active, direct_reclaim, nr_reclaimed FROM memory_events",
        ordinal);
    (void)st;
    if (st) {
      sqlite3_reset(st);  // no ordinal binding for memory_events; re-prepare
      sqlite3_finalize(st);
    }
  }
  {
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
        "SELECT ts_ns, kswapd_active, direct_reclaim, nr_reclaimed FROM memory_events",
        -1, &st, nullptr) == SQLITE_OK) {
      while (sqlite3_step(st) == SQLITE_ROW) {
        uint64_t ts = (uint64_t)sqlite3_column_int64(st, 0);
        auto hrow = [&](const char* metric, int64_t v) {
          ev["series"].push_back({{"entity", "host"}, {"metric", metric},
                                  {"ts_ns", ts}, {"value", v}});
        };
        hrow("kswapd_active", sqlite3_column_int64(st, 1));
        hrow("direct_reclaim", sqlite3_column_int64(st, 2));
        hrow("nr_reclaimed", sqlite3_column_int64(st, 3));
      }
      sqlite3_finalize(st);
    }
  }

  ev["events"]["oom"] = nlohmann::json::array();
  ev["events"]["syscall"] = nlohmann::json::array();
  ev["events"]["lock"] = nlohmann::json::array();
  ev["events"]["runq"] = nlohmann::json::array();
  ev["events"]["iofile"] = nlohmann::json::array();

  {
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT ts_ns, pid, comm FROM oom_events",
                           -1, &st, nullptr) == SQLITE_OK) {
      while (sqlite3_step(st) == SQLITE_ROW) {
        ev["events"]["oom"].push_back(
            {{"ts_ns", (uint64_t)sqlite3_column_int64(st, 0)},
             {"entity", "host"}, {"kind", "kill"},
             {"pid", (uint64_t)sqlite3_column_int64(st, 1)},
             {"comm", (const char*)sqlite3_column_text(st, 2)}});
      }
      sqlite3_finalize(st);
    }
  }
  {
    sqlite3_stmt* st = prep(
        "SELECT tid, name, count, avg_us, p99_us, error_count FROM deep_syscall"
        " WHERE ordinal = ?", ordinal);
    if (st) {
      while (sqlite3_step(st) == SQLITE_ROW) {
        uint32_t tid = (uint32_t)sqlite3_column_int64(st, 0);
        ev["events"]["syscall"].push_back(
            {{"entity", "t" + std::to_string(tid)},
             {"name", (const char*)sqlite3_column_text(st, 1)},
             {"count", (uint64_t)sqlite3_column_int64(st, 2)},
             {"avg_us", sqlite3_column_double(st, 3)},
             {"p99_us", sqlite3_column_double(st, 4)},
             {"error_count", (uint64_t)sqlite3_column_int64(st, 5)}});
      }
      sqlite3_finalize(st);
    }
  }
  {
    sqlite3_stmt* st = prep(
        "SELECT addr, sym, count, total_wait_ns, avg_wait_ns FROM deep_lock"
        " WHERE ordinal = ?", ordinal);
    if (st) {
      while (sqlite3_step(st) == SQLITE_ROW) {
        ev["events"]["lock"].push_back(
            {{"entity", "host"},
             {"addr", (uint64_t)sqlite3_column_int64(st, 0)},
             {"sym", (const char*)sqlite3_column_text(st, 1)},
             {"count", (uint64_t)sqlite3_column_int64(st, 2)},
             {"total_wait_ns", (uint64_t)sqlite3_column_int64(st, 3)},
             {"avg_wait_ns", (uint64_t)sqlite3_column_int64(st, 4)}});
      }
      sqlite3_finalize(st);
    }
  }
  {
    sqlite3_stmt* st = prep(
        "SELECT tid, count, avg_us, p50_us, p99_us FROM deep_runq WHERE ordinal = ?",
        ordinal);
    if (st) {
      while (sqlite3_step(st) == SQLITE_ROW) {
        uint32_t tid = (uint32_t)sqlite3_column_int64(st, 0);
        double p99 = sqlite3_column_double(st, 4);
        ev["events"]["runq"].push_back(
            {{"entity", "t" + std::to_string(tid)},
             {"count", (uint64_t)sqlite3_column_int64(st, 1)},
             {"avg_us", sqlite3_column_double(st, 2)},
             {"p50_us", sqlite3_column_double(st, 3)},
             {"p99_us", p99},
             {"wait_ns", (uint64_t)(p99 * 1000.0)}});
      }
      sqlite3_finalize(st);
    }
  }
  {
    sqlite3_stmt* st = prep(
        "SELECT dev, ino, path, bytes, ops, errors, lat_sum, p50_us, p99_us"
        " FROM deep_iofile WHERE ordinal = ?", ordinal);
    if (st) {
      while (sqlite3_step(st) == SQLITE_ROW) {
        uint32_t dev = (uint32_t)sqlite3_column_int64(st, 0);
        uint32_t major = dev >> 20;
        uint32_t minor = dev & 0xFFFFF;
        double p99 = sqlite3_column_double(st, 9);
        ev["events"]["iofile"].push_back(
            {{"entity", "dev" + std::to_string(major) + "m" + std::to_string(minor)},
             {"ino", (uint64_t)sqlite3_column_int64(st, 1)},
             {"path", (const char*)sqlite3_column_text(st, 2)},
             {"bytes", (uint64_t)sqlite3_column_int64(st, 3)},
             {"ops", (uint64_t)sqlite3_column_int64(st, 4)},
             {"errors", (uint64_t)sqlite3_column_int64(st, 5)},
             {"lat_sum", (uint64_t)sqlite3_column_int64(st, 6)},
             {"p50_us", sqlite3_column_double(st, 7)},
             {"p99_us", p99},
             {"wait_ns", (uint64_t)(p99 * 1000.0)}});
      }
      sqlite3_finalize(st);
    }
  }
  return ev;
}

void OutputWriter::WriteFoldedLine(const std::string& kind, const std::string& frames,
                                   uint64_t value) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_FOLDED_INS);
  if (!st) return;
  sqlite3_reset(st);
  sqlite3_bind_int(st, 1, ordinal_);
  sqlite3_bind_text(st, 2, kind.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 3, frames.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)value);
  Step(S_FOLDED_INS, "deep_folded");
}

void OutputWriter::WriteDeepSyscall(uint32_t tid, uint32_t id, uint64_t count, float avg_us,
                                    float p50_us, float p99_us, uint64_t error_count) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_SYSCALL_INS);
  if (!st) return;
  sqlite3_reset(st);
  const char* name = SyscallName(id);
  sqlite3_bind_int(st, 1, ordinal_);
  sqlite3_bind_int64(st, 2, tid);
  sqlite3_bind_int64(st, 3, id);
  sqlite3_bind_text(st, 4, name, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)count);
  sqlite3_bind_double(st, 6, avg_us);
  sqlite3_bind_double(st, 7, p50_us);
  sqlite3_bind_double(st, 8, p99_us);
  sqlite3_bind_int64(st, 9, (sqlite3_int64)error_count);
  Step(S_SYSCALL_INS, "deep_syscall");
}

void OutputWriter::WriteDeepLock(uint64_t addr, uint64_t count, uint64_t lat_sum,
                                 const char* sym) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_LOCK_INS);
  if (!st) return;
  sqlite3_reset(st);
  char buf[32];
  snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)addr);
  sqlite3_bind_int(st, 1, ordinal_);
  sqlite3_bind_text(st, 2, buf, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 3, sym ? sym : "", -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)count);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)lat_sum);
  sqlite3_bind_int64(st, 6, count ? (sqlite3_int64)(lat_sum / count) : 0);
  Step(S_LOCK_INS, "deep_lock");
}

void OutputWriter::WriteDeepRunq(uint32_t tid, uint64_t count, float avg_us, float p50_us,
                                 float p99_us) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_RUNQ_INS);
  if (!st) return;
  sqlite3_reset(st);
  sqlite3_bind_int(st, 1, ordinal_);
  sqlite3_bind_int64(st, 2, tid);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)count);
  sqlite3_bind_double(st, 4, avg_us);
  sqlite3_bind_double(st, 5, p50_us);
  sqlite3_bind_double(st, 6, p99_us);
  Step(S_RUNQ_INS, "deep_runq");
}

void OutputWriter::WriteDeepIoFile(uint32_t dev, uint64_t ino, const char* path, uint64_t bytes,
                                   uint32_t ops, uint64_t errors, uint64_t lat_sum,
                                   const uint32_t* hist, float p50_us, float p99_us) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_IOFILE_INS);
  if (!st) return;
  sqlite3_reset(st);
  sqlite3_bind_int(st, 1, ordinal_);
  sqlite3_bind_int64(st, 2, dev);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)ino);
  sqlite3_bind_text(st, 4, path ? path : "", -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)bytes);
  sqlite3_bind_int64(st, 6, ops);
  sqlite3_bind_int64(st, 7, (sqlite3_int64)errors);
  sqlite3_bind_int64(st, 8, (sqlite3_int64)lat_sum);
  std::string h = HistJson(hist ? hist : (const uint32_t*)nullptr, 0);
  // HistJson with bins=0 is empty; bind real bins below.
  h = hist ? HistJson(hist, kBase4HistBins) : "[]";
  sqlite3_bind_text(st, 9, h.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_double(st, 10, p50_us);
  sqlite3_bind_double(st, 11, p99_us);
  Step(S_IOFILE_INS, "deep_iofile");
}

void OutputWriter::WriteDeepProcess(const DeepProcessRow& r) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_DEEP_PROC_INS);
  if (!st) return;
  sqlite3_reset(st);
  int c = 1;
  sqlite3_bind_int(st, c++, ordinal_);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.ts_ns);
  sqlite3_bind_int64(st, c++, r.tid);
  sqlite3_bind_int64(st, c++, r.tgid);
  BindText(st, c, r.comm);
  BindU64(st, c, r.vm_rss_kb, r.status_valid);
  BindU64(st, c, r.rss_anon_kb, r.status_valid);
  BindU64(st, c, r.rss_file_kb, r.status_valid);
  BindU64(st, c, r.rss_shmem_kb, r.status_valid);
  BindU64(st, c, r.vm_swap_kb, r.status_valid);
  BindBool(st, c, r.status_valid);
  BindU64(st, c, r.rchar, r.io_valid);
  BindU64(st, c, r.wchar, r.io_valid);
  BindU64(st, c, r.read_bytes, r.io_valid);
  BindU64(st, c, r.write_bytes, r.io_valid);
  BindU64(st, c, r.syscr, r.io_valid);
  BindU64(st, c, r.syscw, r.io_valid);
  BindBool(st, c, r.io_valid);
  BindU64(st, c, r.sched_exec_runtime_ns, r.sched_valid);
  BindU64(st, c, r.sched_run_delay_ns, r.sched_valid);
  BindU64(st, c, r.sched_switch_count, r.sched_valid);
  BindBool(st, c, r.sched_valid);
  BindBool(st, c, r.available);
  BindText(st, c, r.error);
  Step(S_DEEP_PROC_INS, "deep_proc");
}

void OutputWriter::WriteDeepIoDevice(const DeepIoDeviceRow& r) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_DEEP_IODEV_INS);
  if (!st) return;
  sqlite3_reset(st);
  sqlite3_bind_int(st, 1, ordinal_);
  sqlite3_bind_int64(st, 2, r.dev);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)r.ops);
  sqlite3_bind_int64(st, 4, (sqlite3_int64)r.bytes);
  sqlite3_bind_int64(st, 5, (sqlite3_int64)r.lat_sum);
  std::string h = HistJson(r.hist, kBase4HistBins);
  sqlite3_bind_text(st, 6, h.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_double(st, 7, r.p50_us);
  sqlite3_bind_double(st, 8, r.p99_us);
  Step(S_DEEP_IODEV_INS, "deep_io_device");
}

void OutputWriter::WriteDeepNetFlow(const DeepNetFlowRow& r) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_NET_FLOW_INS);
  if (!st) return;
  sqlite3_reset(st);
  int c = 1;
  sqlite3_bind_int(st, c++, ordinal_);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.cookie);
  sqlite3_bind_int64(st, c++, r.tgid);
  sqlite3_bind_int64(st, c++, r.tid);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.netns_ino);
  sqlite3_bind_int64(st, c++, r.family);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.local_addr);
  sqlite3_bind_int64(st, c++, r.local_port);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.remote_addr);
  sqlite3_bind_int64(st, c++, r.remote_port);
  sqlite3_bind_int64(st, c++, r.final_state);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.start_ts_ns);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.established_ts_ns);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.end_ts_ns);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.duration_us);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.connect_latency_us);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.tx_bytes);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.rx_bytes);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.retransmits);
  sqlite3_bind_int64(st, c++, r.rst_reason);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.rtt_count);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.rtt_avg_us);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.rtt_p50_us);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.rtt_p99_us);
  BindBool(st, c, r.closed);
  BindBool(st, c, r.owner_available);
  BindText(st, c, r.error);
  Step(S_NET_FLOW_INS, "deep_net_flow");
}

void OutputWriter::WriteDeepNetDrop(const DeepNetDropRow& r) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_NET_DROP_INS);
  if (!st) return;
  sqlite3_reset(st);
  int c = 1;
  sqlite3_bind_int(st, c++, ordinal_);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.netns_ino);
  sqlite3_bind_int64(st, c++, r.ifindex);
  sqlite3_bind_int(st, c++, (int)r.reason_id);
  BindText(st, c, r.reason);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.count);
  Step(S_NET_DROP_INS, "deep_net_drop");
}

void OutputWriter::WriteDeepNetSoftirq(const DeepNetSoftirqRow& r) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_NET_SOFTIRQ_INS);
  if (!st) return;
  sqlite3_reset(st);
  int c = 1;
  sqlite3_bind_int(st, c++, ordinal_);
  sqlite3_bind_int64(st, c++, r.cpu_idx);
  sqlite3_bind_int(st, c++, (int)r.vector);
  BindText(st, c, r.vector_name);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.count);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.time_ns);
  BindText(st, c, r.hist);
  Step(S_NET_SOFTIRQ_INS, "deep_net_softirq");
}

void OutputWriter::WriteDeepGpuProcess(const DeepGpuProcessRow& r) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_DEEP_GPU_PROC_INS);
  if (!st) return;
  sqlite3_reset(st);
  int c = 1;
  sqlite3_bind_int(st, c++, ordinal_);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.ts_ns);
  BindText(st, c, r.gpu_uuid);
  sqlite3_bind_int64(st, c++, r.pid);
  sqlite3_bind_int64(st, c++, r.tgid);
  BindText(st, c, r.comm);
  BindText(st, c, r.source);
  sqlite3_bind_double(st, c++, r.sm_util_pct);
  sqlite3_bind_double(st, c++, r.mem_util_pct);
  sqlite3_bind_double(st, c++, r.enc_util_pct);
  sqlite3_bind_double(st, c++, r.dec_util_pct);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.fb_used_bytes);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.source_ts_us);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.valid_mask);
  BindText(st, c, r.error);
  Step(S_DEEP_GPU_PROC_INS, "deep_gpu_process");
}

void OutputWriter::WriteDeepOffcpu(const DeepOffcpuRow& r) {
  if (!db_ || ordinal_ < 0) return;
  sqlite3_stmt* st = Prep(S_OFFCPU_INS);
  if (!st) return;
  sqlite3_reset(st);
  int c = 1;
  sqlite3_bind_int(st, c++, ordinal_);
  sqlite3_bind_int64(st, c++, r.tid);
  sqlite3_bind_int64(st, c++, r.tgid);
  BindText(st, c, r.comm);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.dwell_ns);
  sqlite3_bind_int64(st, c++, (sqlite3_int64)r.count);
  sqlite3_bind_int(st, c++, r.stack_available);
  Step(S_OFFCPU_INS, "deep_offcpu");
}

// ---------------------------------------------------------------------------
// Batch
// ---------------------------------------------------------------------------
void OutputWriter::BeginBatch() {
  if (!db_) return;
  if (batch_depth_++ == 0) Exec("BEGIN IMMEDIATE");
}

void OutputWriter::CommitBatch() {
  if (!db_) return;
  if (batch_depth_ <= 0) return;
  if (--batch_depth_ == 0) Exec("COMMIT");
}

}  // namespace etrace_diag
