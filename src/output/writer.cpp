#include "etrace_diag/output_writer.h"

#include <sqlite3.h>

#include <cstdio>
#include <ctime>
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
  S_ANOMALY_INS,
  S_ANOMALY_TID_INS,
  S_TARGETS_INS,
  S_OOM_INS,
  S_MEMEV_INS,
  S_IODEV_INS,
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
      /*112*/ "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid",
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
    " load1 REAL, load5 REAL, load15 REAL, nr_running INTEGER, nr_threads INTEGER,"
    " mem_total_kb INTEGER, mem_avail_kb INTEGER, mem_free_kb INTEGER, buffers_kb INTEGER,"
    " cached_kb INTEGER, swap_total_kb INTEGER, swap_free_kb INTEGER, anon_pages_kb INTEGER,"
    " vm_pgfault INTEGER, vm_pgmajfault INTEGER, vm_pswpin INTEGER, vm_pswpout INTEGER,"
    " vm_free_pages INTEGER, vm_anon_pages INTEGER,"
    " psi_cpu10 REAL, psi_cpu60 REAL, psi_cpu300 REAL,"
    " psi_io10 REAL, psi_io60 REAL, psi_io300 REAL,"
    " psi_mem10 REAL, psi_mem60 REAL, psi_mem300 REAL)",
    "CREATE TABLE IF NOT EXISTS host_cpu ("
    " ts_ns INTEGER NOT NULL, cpu_idx INTEGER NOT NULL,"
    " usr INTEGER, nice INTEGER, sys INTEGER, idle INTEGER,"
    " iowait INTEGER, irq INTEGER, softirq INTEGER, steal INTEGER,"
    " PRIMARY KEY (ts_ns, cpu_idx)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS host_disk ("
    " ts_ns INTEGER NOT NULL, name TEXT NOT NULL, major INTEGER, minor INTEGER,"
    " reads_completed INTEGER, writes_completed INTEGER,"
    " sectors_read INTEGER, sectors_written INTEGER,"
    " io_ticks_ms INTEGER, read_ticks_ms INTEGER, write_ticks_ms INTEGER,"
    " PRIMARY KEY (ts_ns, name)) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS host_proc ("
    " ts_ns INTEGER NOT NULL, pid INTEGER NOT NULL, tgid INTEGER, state INTEGER,"
    " start_time INTEGER, utime INTEGER, stime INTEGER,"
    " nvcsw INTEGER, nivcsw INTEGER, total_vm INTEGER, rss_kb INTEGER, comm TEXT,"
    " PRIMARY KEY (ts_ns, pid)) WITHOUT ROWID",
    // ---- 1s anomaly feature vector ----
    "CREATE TABLE IF NOT EXISTS anomaly ("
    " ts_ns INTEGER PRIMARY KEY, seq INTEGER,"
    " on_cpu_ns_total INTEGER, switch_total INTEGER, io_ops_total INTEGER,"
    " io_bytes_total INTEGER, faults_total INTEGER, lock_waits_total INTEGER)",
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
    // ---- device IO / memory / OOM / targets / logs ----
    "CREATE TABLE IF NOT EXISTS io_devices ("
    " ts_ns INTEGER NOT NULL, dev INTEGER NOT NULL,"
    " ops INTEGER, bytes INTEGER, lat_sum INTEGER,"
    " PRIMARY KEY (ts_ns, dev)) WITHOUT ROWID",
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
    " count INTEGER, avg_us REAL, p50_us REAL, p99_us REAL)",
    "CREATE TABLE IF NOT EXISTS deep_lock ("
    " ordinal INTEGER NOT NULL, addr TEXT, sym TEXT, count INTEGER,"
    " total_wait_ns INTEGER, avg_wait_ns INTEGER)",
    "CREATE TABLE IF NOT EXISTS deep_runq ("
    " ordinal INTEGER NOT NULL, tid INTEGER, count INTEGER,"
    " avg_us REAL, p50_us REAL, p99_us REAL)",
    "CREATE TABLE IF NOT EXISTS deep_iofile ("
    " ordinal INTEGER NOT NULL, dev INTEGER, ino INTEGER,"
    " path TEXT, bytes INTEGER, ops INTEGER)",
    "CREATE INDEX IF NOT EXISTS idx_deep_folded ON deep_folded(ordinal, kind)",
};

// Immutable statement SQL table; indexed by Stmt. Entries are positional and
// MUST match the Stmt enum order above (C++20 has no array-designator
// initializers).
const char* const kSql[] = {
    // S_META_INS
    "INSERT INTO meta(key,value) VALUES(?,?)",
    // S_HOST_INS
    "INSERT INTO host (ts_ns,cu_user,cu_nice,cu_sys,cu_idle,cu_iowait,"
    "cu_irq,cu_softirq,cu_steal,load1,load5,load15,nr_running,nr_threads,"
    "mem_total_kb,mem_avail_kb,mem_free_kb,buffers_kb,cached_kb,"
    "swap_total_kb,swap_free_kb,anon_pages_kb,vm_pgfault,vm_pgmajfault,"
    "vm_pswpin,vm_pswpout,vm_free_pages,vm_anon_pages,psi_cpu10,psi_cpu60,"
    "psi_cpu300,psi_io10,psi_io60,psi_io300,psi_mem10,psi_mem60,psi_mem300) "
    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
    "?,?,?,?,?,?,?,?,?)",
    // S_HOST_CPU_INS
    "INSERT INTO host_cpu (ts_ns,cpu_idx,usr,nice,sys,idle,iowait,irq,softirq,steal) "
    "VALUES(?,?,?,?,?,?,?,?,?,?)",
    // S_HOST_DISK_INS
    "INSERT INTO host_disk (ts_ns,name,major,minor,reads_completed,"
    "writes_completed,sectors_read,sectors_written,io_ticks_ms,"
    "read_ticks_ms,write_ticks_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
    // S_HOST_PROC_INS
    "INSERT INTO host_proc (ts_ns,pid,tgid,state,start_time,utime,stime,"
    "nvcsw,nivcsw,total_vm,rss_kb,comm) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
    // S_ANOMALY_INS
    "INSERT INTO anomaly (ts_ns,seq,on_cpu_ns_total,switch_total,"
    "io_ops_total,io_bytes_total,faults_total,lock_waits_total) "
    "VALUES(?,?,?,?,?,?,?,?)",
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
    // S_IODEV_INS
    "INSERT INTO io_devices (ts_ns,dev,ops,bytes,lat_sum) VALUES(?,?,?,?,?)",
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
    "p99_us) VALUES(?,?,?,?,?,?,?,?)",
    // S_LOCK_INS
    "INSERT INTO deep_lock (ordinal,addr,sym,count,total_wait_ns,avg_wait_ns) "
    "VALUES(?,?,?,?,?,?)",
    // S_RUNQ_INS
    "INSERT INTO deep_runq (ordinal,tid,count,avg_us,p50_us,p99_us) "
    "VALUES(?,?,?,?,?,?)",
    // S_IOFILE_INS
    "INSERT INTO deep_iofile (ordinal,dev,ino,path,bytes,ops) VALUES(?,?,?,?,?,?)",
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
      !Exec("PRAGMA temp_store=MEMORY") || !Exec("PRAGMA user_version=1")) {
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
          {"schema_version", "1"},
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
void OutputWriter::WriteHostRow(const HostSnapshot& s) {
  if (!db_) return;
  sqlite3_stmt* st = Prep(S_HOST_INS);
  if (!st) return;
  sqlite3_reset(st);
  int c = 1;
  sqlite3_bind_int64(st, c++, (sqlite3_int64)s.ts_ns);
  sqlite3_bind_int64(st, c++, s.total.user);
  sqlite3_bind_int64(st, c++, s.total.nice);
  sqlite3_bind_int64(st, c++, s.total.system);
  sqlite3_bind_int64(st, c++, s.total.idle);
  sqlite3_bind_int64(st, c++, s.total.iowait);
  sqlite3_bind_int64(st, c++, s.total.irq);
  sqlite3_bind_int64(st, c++, s.total.softirq);
  sqlite3_bind_int64(st, c++, s.total.steal);
  sqlite3_bind_double(st, c++, s.load.load1);
  sqlite3_bind_double(st, c++, s.load.load5);
  sqlite3_bind_double(st, c++, s.load.load15);
  sqlite3_bind_int64(st, c++, s.load.nr_running);
  sqlite3_bind_int64(st, c++, s.load.nr_threads);
  sqlite3_bind_int64(st, c++, s.mem.mem_total_kb);
  sqlite3_bind_int64(st, c++, s.mem.mem_available_kb);
  sqlite3_bind_int64(st, c++, s.mem.mem_free_kb);
  sqlite3_bind_int64(st, c++, s.mem.buffers_kb);
  sqlite3_bind_int64(st, c++, s.mem.cached_kb);
  sqlite3_bind_int64(st, c++, s.mem.swap_total_kb);
  sqlite3_bind_int64(st, c++, s.mem.swap_free_kb);
  sqlite3_bind_int64(st, c++, s.mem.anon_pages_kb);
  sqlite3_bind_int64(st, c++, s.vm.pgfault);
  sqlite3_bind_int64(st, c++, s.vm.pgmajfault);
  sqlite3_bind_int64(st, c++, s.vm.pswpin);
  sqlite3_bind_int64(st, c++, s.vm.pswpout);
  sqlite3_bind_int64(st, c++, s.vm.nr_free_pages);
  sqlite3_bind_int64(st, c++, s.vm.nr_anon_pages);
  sqlite3_bind_double(st, c++, s.psi.cpu10);
  sqlite3_bind_double(st, c++, s.psi.cpu60);
  sqlite3_bind_double(st, c++, s.psi.cpu300);
  sqlite3_bind_double(st, c++, s.psi.io10);
  sqlite3_bind_double(st, c++, s.psi.io60);
  sqlite3_bind_double(st, c++, s.psi.io300);
  sqlite3_bind_double(st, c++, s.psi.mem10);
  sqlite3_bind_double(st, c++, s.psi.mem60);
  sqlite3_bind_double(st, c++, s.psi.mem300);
  Step(S_HOST_INS, "host");

  size_t ci = 0;
  for (const auto& cpu : s.cpus) {
    st = Prep(S_HOST_CPU_INS);
    if (!st) return;
    sqlite3_reset(st);
    c = 1;
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
    Step(S_HOST_CPU_INS, "host_cpu");
    ++ci;
  }

  for (const auto& d : s.disks) {
    st = Prep(S_HOST_DISK_INS);
    if (!st) return;
    sqlite3_reset(st);
    c = 1;
    sqlite3_bind_int64(st, c++, (sqlite3_int64)s.ts_ns);
    sqlite3_bind_text(st, c++, d.name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, c++, d.major);
    sqlite3_bind_int64(st, c++, d.minor);
    sqlite3_bind_int64(st, c++, d.reads_completed);
    sqlite3_bind_int64(st, c++, d.writes_completed);
    sqlite3_bind_int64(st, c++, d.sectors_read);
    sqlite3_bind_int64(st, c++, d.sectors_written);
    sqlite3_bind_int64(st, c++, d.io_ticks_ms);
    sqlite3_bind_int64(st, c++, d.read_ticks_ms);
    sqlite3_bind_int64(st, c++, d.write_ticks_ms);
    Step(S_HOST_DISK_INS, "host_disk");
  }

  for (const auto& p : s.procs) {
    st = Prep(S_HOST_PROC_INS);
    if (!st) return;
    sqlite3_reset(st);
    c = 1;
    sqlite3_bind_int64(st, c++, (sqlite3_int64)s.ts_ns);
    sqlite3_bind_int64(st, c++, p.pid);
    sqlite3_bind_int64(st, c++, p.tgid);
    sqlite3_bind_int64(st, c++, p.state);
    sqlite3_bind_int64(st, c++, p.start_time);
    sqlite3_bind_int64(st, c++, p.utime);
    sqlite3_bind_int64(st, c++, p.stime);
    sqlite3_bind_int64(st, c++, p.nvcsw);
    sqlite3_bind_int64(st, c++, p.nivcsw);
    sqlite3_bind_int64(st, c++, p.total_vm);
    sqlite3_bind_int64(st, c++, p.rss_kb);
    sqlite3_bind_text(st, c++, p.comm, -1, SQLITE_TRANSIENT);
    Step(S_HOST_PROC_INS, "host_proc");
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
    sqlite3_bind_int64(st, c++, eb.value("faults_total", 0ULL));
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

void OutputWriter::WriteIoDevice(const nlohmann::json& e) {
  if (!db_) return;
  sqlite3_stmt* st = Prep(S_IODEV_INS);
  if (!st) return;
  sqlite3_reset(st);
  sqlite3_bind_int64(st, 1, (sqlite3_int64)e.value("ts_ns", 0ULL));
  sqlite3_bind_int64(st, 2, e.value("dev", 0ULL));
  sqlite3_bind_int64(st, 3, e.value("ops", 0ULL));
  sqlite3_bind_int64(st, 4, e.value("bytes", 0ULL));
  sqlite3_bind_int64(st, 5, e.value("lat_sum", 0ULL));
  Step(S_IODEV_INS, "io_devices");
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
                                    float p50_us, float p99_us) {
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
                                   uint32_t ops) {
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
  Step(S_IOFILE_INS, "deep_iofile");
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