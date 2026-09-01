#include "collect/network_metrics.h"

#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace etrace_diag {

namespace {

std::string ReadFile(const std::string& path) {
  std::ifstream f(path);
  if (!f.good()) return {};
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

std::vector<std::string> SplitWs(const std::string& s) {
  std::istringstream is(s);
  std::vector<std::string> out;
  std::string t;
  while (is >> t) out.push_back(t);
  return out;
}

uint64_t ParseU64(const std::string& s, uint64_t dflt = 0) {
  if (s.empty()) return dflt;
  char* end = nullptr;
  unsigned long long v = strtoull(s.c_str(), &end, 10);
  return end == s.c_str() ? dflt : (uint64_t)v;
}

// ---------------------------------------------------------------------------
// NETLINK_ROUTE RTM_GETLINK dump
// ---------------------------------------------------------------------------
struct LinkRow {
  NetInterfaceRow row;
  bool has_stats = false;
};

// Minimal netlink request/response walker for RTM_GETLINK.
std::vector<LinkRow> NetlinkLinks() {
  std::vector<LinkRow> out;
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) return out;

  struct {
    nlmsghdr nlh;
    ifinfomsg ifm;
  } req = {};
  req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(ifinfomsg));
  req.nlh.nlmsg_type = RTM_GETLINK;
  req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.nlh.nlmsg_seq = 1;
  req.ifm.ifi_family = AF_UNSPEC;

  if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
    close(fd);
    return out;
  }

  std::string buf(1 << 16, 0);
  bool done = false;
  while (!done) {
    ssize_t n = recv(fd, buf.data(), buf.size(), 0);
    if (n < 0) break;
    for (nlmsghdr* h = (nlmsghdr*)buf.data(); NLMSG_OK(h, (unsigned)n);
         h = NLMSG_NEXT(h, n)) {
      if (h->nlmsg_type == NLMSG_DONE) {
        done = true;
        break;
      }
      if (h->nlmsg_type == NLMSG_ERROR) {
        done = true;
        break;
      }
      if (h->nlmsg_type != RTM_NEWLINK) continue;
      ifinfomsg* im = (ifinfomsg*)NLMSG_DATA(h);
      LinkRow lr;
      lr.row.ifindex = im->ifi_index;
      // Approximate operstate from flags (replaced by IFLA_OPERSTATE below
      // when the attribute is present).
      lr.row.operstate = (im->ifi_flags & IFF_UP)
                             ? ((im->ifi_flags & IFF_RUNNING) ? 6 /*IF_OPER_UP*/
                                                              : 2 /*IF_OPER_DOWN*/)
                             : 2;
      lr.row.valid = true;
      lr.row.source = "netlink";
      int len = (int)h->nlmsg_len - NLMSG_LENGTH(sizeof(ifinfomsg));
      rtattr* attr = IFLA_RTA(im);
      for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        switch (attr->rta_type) {
          case IFLA_IFNAME:
            lr.row.name = (const char*)RTA_DATA(attr);
            break;
          case IFLA_MTU:
            lr.row.mtu = *(uint32_t*)RTA_DATA(attr);
            break;
          case IFLA_OPERSTATE:
            lr.row.operstate = *(uint8_t*)RTA_DATA(attr);
            break;
          case IFLA_CARRIER_CHANGES:
            lr.row.carrier_changes = *(uint32_t*)RTA_DATA(attr);
            break;
          case IFLA_STATS64: {
            const rtnl_link_stats64* s64 = (const rtnl_link_stats64*)RTA_DATA(attr);
            lr.has_stats = true;
            lr.row.rx_bytes = s64->rx_bytes;
            lr.row.rx_packets = s64->rx_packets;
            lr.row.rx_errors = s64->rx_errors;
            lr.row.rx_dropped = s64->rx_dropped;
            lr.row.tx_bytes = s64->tx_bytes;
            lr.row.tx_packets = s64->tx_packets;
            lr.row.tx_errors = s64->tx_errors;
            lr.row.tx_dropped = s64->tx_dropped;
            lr.row.collisions = s64->collisions;
            lr.row.rx_nohandler = s64->rx_nohandler;
            break;
          }
          case IFLA_STATS: {
            const rtnl_link_stats* s = (const rtnl_link_stats*)RTA_DATA(attr);
            lr.has_stats = true;
            lr.row.rx_bytes = s->rx_bytes;
            lr.row.rx_packets = s->rx_packets;
            lr.row.rx_errors = s->rx_errors;
            lr.row.rx_dropped = s->rx_dropped;
            lr.row.tx_bytes = s->tx_bytes;
            lr.row.tx_packets = s->tx_packets;
            lr.row.tx_errors = s->tx_errors;
            lr.row.tx_dropped = s->tx_dropped;
            lr.row.collisions = s->collisions;
            lr.row.rx_nohandler = s->rx_nohandler;
            break;
          }
          default:
            break;
        }
      }
      if (!lr.row.name.empty() && lr.has_stats) out.push_back(lr);
    }
  }
  close(fd);
  return out;
}

// /proc/net/dev fallback: "iface: rx-bytes pkts errs drop ... tx-bytes ..."
std::vector<LinkRow> ProcDevFallback(const std::string& err) {
  std::vector<LinkRow> out;
  std::istringstream is(ReadFile("/proc/net/dev"));
  std::string line;
  bool header_done = false;
  while (std::getline(is, line)) {
    if (!header_done) {
      if (line.find("Inter-|") != std::string::npos ||
          line.find("face |") != std::string::npos)
        header_done = true;
      continue;
    }
    size_t colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string name = line.substr(0, colon);
    // trim
    size_t b = name.find_first_not_of(" \t");
    name = b == std::string::npos ? "" : name.substr(b);
    auto toks = SplitWs(line.substr(colon + 1));
    if (toks.size() < 16) continue;
    LinkRow lr;
    lr.row.ifindex = if_nametoindex(name.c_str());
    lr.row.name = name;
    lr.row.source = "fallback";
    lr.row.error = err;
    lr.row.rx_bytes = ParseU64(toks[0]);
    lr.row.rx_packets = ParseU64(toks[1]);
    lr.row.rx_errors = ParseU64(toks[2]);
    lr.row.rx_dropped = ParseU64(toks[3]);
    lr.row.tx_bytes = ParseU64(toks[8]);
    lr.row.tx_packets = ParseU64(toks[9]);
    lr.row.tx_errors = ParseU64(toks[10]);
    lr.row.tx_dropped = ParseU64(toks[11]);
    lr.row.collisions = ParseU64(toks[13]);
    lr.row.valid = true;
    lr.has_stats = true;
    out.push_back(lr);
  }
  return out;
}

// ---------------------------------------------------------------------------
// /proc/net/snmp + netstat keyed-field parsing
// ---------------------------------------------------------------------------

// Values positioned by the header (keys) line: returns false when key absent.
bool KeyedValue(const std::string& keys_line, const std::string& vals_line,
                const std::string& key, uint64_t& out) {
  auto ks = SplitWs(keys_line);
  auto vs = SplitWs(vals_line);
  for (size_t i = 0; i < ks.size() && i < vs.size(); ++i) {
    if (ks[i] == key) {
      out = ParseU64(vs[i]);
      return true;
    }
  }
  return false;
}

// Sections in snmp/netstat files are "<name>: <keys...>" then "<name>: <vals...>".
struct ProcNetSection {
  std::string keys;
  std::string vals;
  bool ok = false;
};

ProcNetSection FindSection(const std::string& text, const std::string& name) {
  ProcNetSection out;
  std::istringstream is(text);
  std::string line;
  while (std::getline(is, line)) {
    if (line.rfind(name + ":", 0) != 0) continue;
    if (!out.ok) {
      out.keys = line.substr(name.size() + 1);
      out.ok = true;
    } else {
      out.vals = line.substr(name.size() + 1);
      return out;
    }
  }
  out.ok = false;
  return out;
}

// "TCP: inuse N orphan M tw L alloc K mem P" -> mem pages; sockstat6 adds "UDP6" etc.
uint64_t SockstatMem(const std::string& text, const std::string& proto) {
  std::istringstream is(text);
  std::string line;
  while (std::getline(is, line)) {
    if (line.rfind(proto + ":", 0) != 0) continue;
    auto toks = SplitWs(line.substr(proto.size() + 1));
    for (size_t i = 0; i + 1 < toks.size(); ++i)
      if (toks[i] == "mem") return ParseU64(toks[i + 1]);
  }
  return 0;
}

// ---------------------------------------------------------------------------
// softnet_stat + /proc/softirqs
// ---------------------------------------------------------------------------
struct SoftnetOut {
  std::vector<NetSoftnetRow> softnets;
  bool ok = false;
};

SoftnetOut ReadSoftnet() {
  SoftnetOut out;
  std::string text = ReadFile("/proc/net/softnet_stat");
  if (text.empty()) return out;
  std::istringstream is(text);
  std::string line;
  uint32_t cpu = 0;
  while (std::getline(is, line)) {
    auto toks = SplitWs(line);
    if (toks.size() < 4) continue;
    NetSoftnetRow n;
    n.cpu_idx = cpu++;
    n.processed = ParseU64(toks[0], 0);
    n.dropped = ParseU64(toks[1], 0);
    n.time_squeeze = ParseU64(toks[2], 0);
    // kernel >= 5.15 prints 13 columns: idx9 received_rps, idx10 flow_limit,
    // idx11 backlog_len. Older kernels print 11: idx3 received_rps, idx4 flow_limit.
    if (toks.size() >= 12) {
      n.received_rps = ParseU64(toks[9], 0);
      n.flow_limit_count = ParseU64(toks[10], 0);
      n.backlog_len = ParseU64(toks[11], 0);
    } else {
      n.received_rps = ParseU64(toks[3], 0);
      n.flow_limit_count = ParseU64(toks[4], 0);
      n.backlog_len = 0;
    }
    n.valid = true;
    out.softnets.push_back(n);
  }
  out.ok = !out.softnets.empty();
  // /proc/softirqs NET_RX / NET_TX per-cpu cumulative counts.
  std::string sq = ReadFile("/proc/softirqs");
  if (!sq.empty()) {
    std::istringstream ss(sq);
    std::string l;
    std::vector<std::string> hdr;
    bool have_hdr = false;
    size_t rx_col = std::string::npos, tx_col = std::string::npos;
    while (std::getline(ss, l)) {
      if (!have_hdr) {
        hdr = SplitWs(l);
        for (size_t i = 0; i < hdr.size(); ++i) {
          if (hdr[i] == "NET_RX") rx_col = i;
          if (hdr[i] == "NET_TX") tx_col = i;
        }
        have_hdr = true;
        continue;
      }
      auto toks = SplitWs(l);
      if (toks.empty() || toks[0].rfind("CPU", 0) != 0) continue;
      uint32_t idx = (uint32_t)ParseU64(toks[0].substr(3));
      auto get = [&](size_t col) -> uint64_t {
        // row tokens: CPU<n> col1 col2 ... (cols align with header)
        return (col != std::string::npos && col + 1 < toks.size()) ? ParseU64(toks[col + 1]) : 0;
      };
      uint64_t rx = get(rx_col), tx = get(tx_col);
      if (idx < out.softnets.size()) {
        out.softnets[idx].net_rx_softirq = rx;
        out.softnets[idx].net_tx_softirq = tx;
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// NETLINK_INET_DIAG TCP state summary (current netns)
// ---------------------------------------------------------------------------
struct TcpDiagSummary {
  NetStackSnapshot& stack;
};

bool DiagTcpStates(NetStackSnapshot& s) {
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
  if (fd < 0) return false;

  struct {
    nlmsghdr nlh;
    inet_diag_req_v2 r;
  } req = {};
  req.nlh.nlmsg_len = sizeof(req);
  req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
  req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.nlh.nlmsg_seq = 1;
  req.r.sdiag_family = AF_INET;
  req.r.sdiag_protocol = IPPROTO_TCP;
  req.r.idiag_states = ~0u;

  uint64_t states[13] = {0};  // TCP_ESTABLISHED..TCP_CLOSING
  uint64_t rq = 0, wq = 0;
  bool any = false;

  // Walk both AF_INET and AF_INET6.
  for (int pass = 0; pass < 2; ++pass) {
    req.r.sdiag_family = pass == 0 ? AF_INET : AF_INET6;
    if (send(fd, &req, sizeof(req), 0) < 0) continue;
    std::string buf(1 << 16, 0);
    bool done = false;
    while (!done) {
      ssize_t n = recv(fd, buf.data(), buf.size(), 0);
      if (n < 0) break;
      for (nlmsghdr* h = (nlmsghdr*)buf.data(); NLMSG_OK(h, (unsigned)n);
           h = NLMSG_NEXT(h, n)) {
        if (h->nlmsg_type == NLMSG_DONE) {
          done = true;
          break;
        }
        if (h->nlmsg_type == NLMSG_ERROR) {
          done = true;
          break;
        }
        inet_diag_msg* m = (inet_diag_msg*)NLMSG_DATA(h);
        uint8_t st = m->idiag_state;
        if (st >= 1 && st <= 13) states[st - 1]++;
        rq += m->idiag_rqueue;
        wq += m->idiag_wqueue;
        any = true;
      }
    }
  }
  close(fd);
  if (!any) return false;
  s.tcp_state_established = states[TCP_ESTABLISHED - 1];
  s.tcp_state_syn_sent = states[TCP_SYN_SENT - 1];
  s.tcp_state_syn_recv = states[TCP_SYN_RECV - 1];
  s.tcp_state_fin_wait1 = states[TCP_FIN_WAIT1 - 1];
  s.tcp_state_fin_wait2 = states[TCP_FIN_WAIT2 - 1];
  s.tcp_state_time_wait = states[TCP_TIME_WAIT - 1];
  s.tcp_state_close = states[TCP_CLOSE - 1];
  s.tcp_state_close_wait = states[TCP_CLOSE_WAIT - 1];
  s.tcp_state_last_ack = states[TCP_LAST_ACK - 1];
  s.tcp_state_listen = states[TCP_LISTEN - 1];
  s.tcp_state_closing = states[TCP_CLOSING - 1];
  s.rqueue_bytes = rq;
  s.wqueue_bytes = wq;
  s.tcp_states_valid = true;
  return true;
}

}  // namespace

NetworkSnapshot NetworkMetrics::Snapshot(uint64_t ts_ns, bool enabled) {
  NetworkSnapshot s;
  s.ts_ns = ts_ns;
  s.enabled = enabled;
  NetStackSnapshot& t = s.stack;

  struct stat ns_st;
  if (stat("/proc/self/ns/net", &ns_st) == 0) t.netns_ino = (uint64_t)ns_st.st_ino;

  if (!enabled) {
    t.valid = false;
    t.error = "disabled";
    t.source = "disabled";
    return s;
  }

  // interfaces: netlink first, /proc/net/dev fallback.
  std::string link_err;
  auto links = NetlinkLinks();
  if (links.empty()) {
    link_err = "netlink RTM_GETLINK failed";
    links = ProcDevFallback(link_err);
  }
  for (auto& l : links) s.ifaces.push_back(l.row);

  // protocol stack
  std::string snmp = ReadFile("/proc/net/snmp");
  std::string netstat = ReadFile("/proc/net/netstat");
  t.valid = !snmp.empty();
  t.source = t.valid ? "procfs" : "unavailable";
  if (!t.valid) t.error = "/proc/net/snmp unreadable";
  {
    auto get_snmp = [&](const char* section, const char* key, uint64_t& out) {
      auto sec = FindSection(snmp, section);
      if (sec.ok) KeyedValue(sec.keys, sec.vals, key, out);
    };
    get_snmp("Tcp", "ActiveOpens", t.active_opens);
    get_snmp("Tcp", "PassiveOpens", t.passive_opens);
    get_snmp("Tcp", "AttemptFails", t.attempt_fails);
    get_snmp("Tcp", "EstabResets", t.estab_resets);
    get_snmp("Tcp", "CurrEstab", t.curr_estab);
    get_snmp("Tcp", "InSegs", t.in_segs);
    get_snmp("Tcp", "OutSegs", t.out_segs);
    get_snmp("Tcp", "RetransSegs", t.retrans_segs);
    get_snmp("Tcp", "InErrs", t.in_errs);
    get_snmp("Tcp", "OutRsts", t.out_rsts);
    get_snmp("Udp", "InDatagrams", t.udp_in_datagrams);
    get_snmp("Udp", "NoPorts", t.udp_no_ports);
    get_snmp("Udp", "InErrors", t.udp_in_errors);
    get_snmp("Udp", "OutDatagrams", t.udp_out_datagrams);
    get_snmp("Udp", "RcvbufErrors", t.udp_rcvbuf_errors);
    get_snmp("Udp", "SndbufErrors", t.udp_sndbuf_errors);
  }
  if (!netstat.empty()) {
    auto sec = FindSection(netstat, "TcpExt");
    if (sec.ok) {
      KeyedValue(sec.keys, sec.vals, "ListenOverflows", t.listen_overflows);
      KeyedValue(sec.keys, sec.vals, "ListenDrops", t.listen_drops);
      KeyedValue(sec.keys, sec.vals, "TCPBacklogDrop", t.backlog_drop);
      KeyedValue(sec.keys, sec.vals, "TCPRcvQDrop", t.rcv_q_drop);
      KeyedValue(sec.keys, sec.vals, "TCPSynRetrans", t.syn_retrans);
      KeyedValue(sec.keys, sec.vals, "TCPTimeouts", t.timeouts);
      KeyedValue(sec.keys, sec.vals, "TCPMemoryPressures", t.memory_pressures);
    }
  }
  {
    std::string sk = ReadFile("/proc/net/sockstat");
    std::string sk6 = ReadFile("/proc/net/sockstat6");
    t.tcp_sock_mem = SockstatMem(sk, "TCP") + SockstatMem(sk6, "TCP6");
    t.udp_sock_mem = SockstatMem(sk, "UDP") + SockstatMem(sk6, "UDP6");
    t.frag_sock_mem = SockstatMem(sk, "FRAG") + SockstatMem(sk6, "FRAG6");
  }

  auto sn = ReadSoftnet();
  s.softnets = std::move(sn.softnets);

  if (!DiagTcpStates(t)) {
    t.tcp_states_valid = false;
    if (t.valid) t.error = "NETLINK_INET_DIAG failed (state columns NULL)";
  }

  return s;
}

}  // namespace etrace_diag
