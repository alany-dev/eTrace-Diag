#pragma once

#include <cstdint>

#include "etrace_diag/metrics.h"

namespace etrace_diag {

// Stateless BASE network collector. Prefers one NETLINK_ROUTE RTM_GETLINK dump
// for interface stats (IFLA_STATS64), falls back to /proc/net/dev (source
// "fallback"). Reads /proc/net/{snmp,netstat,sockstat,sockstat6,softnet_stat},
// /proc/softirqs (NET_RX/NET_TX) and a NETLINK_INET_DIAG TCP state summary of
// the current network namespace. Any missing/unreadable source degrades to
// valid=false / error text — never throws, never fail-fasts.
class NetworkMetrics {
 public:
  static NetworkSnapshot Snapshot(uint64_t ts_ns, bool enabled);
};

}  // namespace etrace_diag
