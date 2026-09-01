#include "collect/gpu_metrics.h"

#include <dlfcn.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

#include "logging.h"

namespace etrace_diag {

namespace {

std::string ReadFileTrim(const std::string& path) {
  std::ifstream f(path);
  if (!f.good()) return {};
  std::string s;
  std::getline(f, s);
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
  return s;
}

uint64_t ParseU64(const std::string& s, uint64_t dflt = 0) {
  if (s.empty()) return dflt;
  char* end = nullptr;
  unsigned long long v = strtoull(s.c_str(), &end, 10);
  return end == s.c_str() ? dflt : (uint64_t)v;
}

double ParseD(const std::string& s, double dflt = 0.0) {
  if (s.empty()) return dflt;
  char* end = nullptr;
  double v = strtod(s.c_str(), &end);
  return end == s.c_str() ? dflt : v;
}

uint32_t TgidOf(uint32_t pid) {
  std::ifstream f("/proc/" + std::to_string(pid) + "/status");
  std::string line;
  while (std::getline(f, line)) {
    if (line.rfind("Tgid:", 0) == 0) return (uint32_t)ParseU64(line.substr(5));
  }
  return pid;
}

std::string CommOf(uint32_t pid) {
  std::string c = ReadFileTrim("/proc/" + std::to_string(pid) + "/comm");
  return c;
}

}  // namespace

// ---- NVML dynamic API (no link-time dependency) ----
struct GpuMetrics::NvmlApi {
  void* lib = nullptr;
  int (*Init)(void) = nullptr;
  int (*Shutdown)(void) = nullptr;
  int (*Count)(unsigned int*) = nullptr;
  int (*HandleByIndex)(unsigned int, void**) = nullptr;
  int (*Uuid)(void*, char*, unsigned int) = nullptr;
  int (*Name)(void*, char*, unsigned int) = nullptr;
  int (*PciInfo)(void*, void*) = nullptr;                 // nvmlPciInfo_t v3
  int (*Utilization)(void*, void*) = nullptr;             // nvmlUtilization_t
  int (*MemoryInfo)(void*, void*) = nullptr;              // nvmlMemory_t
  int (*Temperature)(void*, int, unsigned int*) = nullptr;
  int (*PowerUsage)(void*, unsigned int*) = nullptr;
  int (*PowerLimit)(void*, unsigned int*) = nullptr;
  int (*Energy)(void*, unsigned long long*) = nullptr;
  int (*ClockInfo)(void*, int, unsigned int*) = nullptr;
  int (*PcieThroughput)(void*, int, unsigned int*) = nullptr;
  int (*EncoderUtil)(void*, unsigned int*, unsigned int*) = nullptr;
  int (*DecoderUtil)(void*, unsigned int*, unsigned int*) = nullptr;
  int (*ThrottleReasons)(void*, unsigned long long*) = nullptr;
  int (*EccErrors)(void*, int, int, unsigned long long*) = nullptr;
  int (*RetiredPages)(void*, int, unsigned long long*) = nullptr;
  int (*MigMode)(void*, unsigned int*, unsigned int*) = nullptr;
  int (*ProcCount)(void*, unsigned int*) = nullptr;
  int (*ProcInfo)(void*, unsigned int*, void*) = nullptr;  // (dev, *count, nvmlProcessInfo_t*)

  bool Load() {
    lib = dlopen("libnvidia-ml.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!lib) return false;
    auto sym = [&](const char* n) -> void* { return dlsym(lib, n); };
    Init = (decltype(Init))sym("nvmlInit_v2");
    Shutdown = (decltype(Shutdown))sym("nvmlShutdown");
    Count = (decltype(Count))sym("nvmlDeviceGetCount_v2");
    HandleByIndex = (decltype(HandleByIndex))sym("nvmlDeviceGetHandleByIndex_v2");
    Uuid = (decltype(Uuid))sym("nvmlDeviceGetUUID");
    Name = (decltype(Name))sym("nvmlDeviceGetName");
    PciInfo = (decltype(PciInfo))sym("nvmlDeviceGetPciInfo_v3");
    Utilization = (decltype(Utilization))sym("nvmlDeviceGetUtilizationRates");
    MemoryInfo = (decltype(MemoryInfo))sym("nvmlDeviceGetMemoryInfo");
    Temperature = (decltype(Temperature))sym("nvmlDeviceGetTemperature");
    PowerUsage = (decltype(PowerUsage))sym("nvmlDeviceGetPowerUsage");
    PowerLimit = (decltype(PowerLimit))sym("nvmlDeviceGetPowerManagementLimit");
    Energy = (decltype(Energy))sym("nvmlDeviceGetTotalEnergyConsumption");
    ClockInfo = (decltype(ClockInfo))sym("nvmlDeviceGetClockInfo");
    PcieThroughput = (decltype(PcieThroughput))sym("nvmlDeviceGetPcieThroughput");
    EncoderUtil = (decltype(EncoderUtil))sym("nvmlDeviceGetEncoderUtilization");
    DecoderUtil = (decltype(DecoderUtil))sym("nvmlDeviceGetDecoderUtilization");
    ThrottleReasons = (decltype(ThrottleReasons))sym("nvmlDeviceGetCurrentClocksThrottleReasons");
    EccErrors = (decltype(EccErrors))sym("nvmlDeviceGetTotalEccErrors");
    RetiredPages = (decltype(RetiredPages))sym("nvmlDeviceGetRetiredPages");
    MigMode = (decltype(MigMode))sym("nvmlDeviceGetMigMode");
    ProcCount = (decltype(ProcCount))sym("nvmlDeviceGetComputeRunningProcesses_v2");
    ProcInfo = (decltype(ProcInfo))sym("nvmlDeviceGetGraphicsRunningProcesses_v2");
    if (!Init || !Count || !HandleByIndex) {
      dlclose(lib);
      lib = nullptr;
      return false;
    }
    return true;
  }

  void Close() {
    if (lib) {
      if (Shutdown) Shutdown();
      dlclose(lib);
      lib = nullptr;
    }
  }
};

// ABI-compatible structs (nvml.h is not available at build time; layouts are
// frozen by NVML ABI).
struct NvmlUtilization { unsigned int gpu; unsigned int memory; };
struct NvmlMemory { unsigned long long total; unsigned long long free; unsigned long long used; };
struct NvmlPciInfo {
  char busIdLegacy[16];
  unsigned int domain;
  unsigned int bus;
  unsigned int device;
  unsigned int pciDeviceId;
  unsigned int pciSubSystemId;
  char busId[32];
  unsigned int reserved[3];
};
struct NvmlProcessInfo {
  unsigned int pid;
  unsigned long long usedGpuMemory;
};

// NVML constants (from nvml.h)
constexpr int NVML_TEMPERATURE_GPU = 0;
constexpr int NVML_CLOCK_SM = 0;
constexpr int NVML_CLOCK_MEM = 2;
constexpr int NVML_PCIE_UTIL_TX_BYTES = 1;
constexpr int NVML_PCIE_UTIL_RX_BYTES = 2;
constexpr int NVML_VOLATILE_ECC = 0;
constexpr int NVML_SINGLE_BIT_ECC = 1;
constexpr int NVML_DOUBLE_BIT_ECC = 2;
constexpr int NVML_MULTIPLE_SINGLE_BIT_ECC = 1;
constexpr int NVML_DOUBLE_BIT_ECC_PAGE = 2;
constexpr unsigned long long NVML_PAGE_RETIREMENT_CAUSE_DOUBLE_BIT_ECC_ERROR = 2ULL;
constexpr unsigned long long NVML_PAGE_RETIREMENT_CAUSE_MULTIPLE_SINGLE_BIT_ECC_ERROR = 1ULL;
constexpr unsigned int NVML_SUCCESS = 0;

bool GpuMetrics::InitNvml() {
  auto* api = new NvmlApi();
  if (!api->Load()) {
    fail_reason_ = "libnvidia-ml.so.1 not loadable";
    delete api;
    return false;
  }
  if (api->Init() != NVML_SUCCESS) {
    fail_reason_ = "nvmlInit failed (driver/permission)";
    api->Close();
    delete api;
    return false;
  }
  unsigned int count = 0;
  if (api->Count(&count) != NVML_SUCCESS || count == 0) {
    fail_reason_ = "no NVML devices";
    api->Close();
    delete api;
    return false;
  }
  nvml_ = api;
  nvml_count_ = count;
  active_ = "nvml";
  return true;
}

bool GpuMetrics::InitDrm() {
  // Enumerate /sys/class/drm/card*/device.
  for (int i = 0; i < 64; ++i) {
    std::string path = "/sys/class/drm/card" + std::to_string(i) + "/device";
    std::ifstream f(path + "/vendor");
    if (!f.good()) continue;
    drm_cards_.push_back(path);
  }
  if (drm_cards_.empty()) {
    fail_reason_ = "no DRM card devices";
    return false;
  }
  active_ = "drm";
  return true;
}

bool GpuMetrics::Init(const std::string& source) {
  Close();
  source_ = source;
  if (source == "off") {
    active_ = "off";
    return true;
  }
  if (source == "nvml") {
    return InitNvml();
  }
  if (source == "drm") {
    return InitDrm();
  }
  // auto: NVML -> DRM
  if (InitNvml()) return true;
  std::string nvml_reason = fail_reason_;
  if (InitDrm()) return true;
  fail_reason_ = "nvml: " + nvml_reason + "; drm: " + fail_reason_;
  return false;
}

GpuDeviceRow GpuMetrics::NvmlDevice(uint32_t index) const {
  GpuDeviceRow d;
  d.source = "nvml";
  void* dev = nullptr;
  if (!nvml_ || nvml_->HandleByIndex(index, &dev) != NVML_SUCCESS || !dev) {
    d.available = false;
    d.error_text = "nvmlDeviceGetHandleByIndex failed";
    return d;
  }
  d.available = true;

  char buf[96] = {0};
  if (nvml_->Uuid && nvml_->Uuid(dev, buf, sizeof(buf)) == NVML_SUCCESS) d.uuid = buf;
  if (d.uuid.empty()) d.uuid = "nvml-" + std::to_string(index);
  buf[0] = 0;
  if (nvml_->Name && nvml_->Name(dev, buf, sizeof(buf)) == NVML_SUCCESS) d.model = buf;

  NvmlPciInfo pci = {};
  if (nvml_->PciInfo && nvml_->PciInfo(dev, &pci) == NVML_SUCCESS) {
    if (pci.busId[0]) {
      d.pci_bdf = pci.busId;
    } else {
      char b[32];
      snprintf(b, sizeof(b), "%04x:%02x:%02x.0", pci.domain, pci.bus, pci.device);
      d.pci_bdf = b;
    }
  }

  NvmlUtilization u = {};
  if (nvml_->Utilization && nvml_->Utilization(dev, &u) == NVML_SUCCESS) {
    d.util_pct = u.gpu;
    d.valid_mask |= 1u << 0;
  }
  NvmlMemory m = {};
  if (nvml_->MemoryInfo && nvml_->MemoryInfo(dev, &m) == NVML_SUCCESS) {
    d.mem_used_bytes = m.used;
    d.mem_total_bytes = m.total;
    d.valid_mask |= 1u << 2;
    d.valid_mask |= 1u << 3;
    if (m.total) {
      d.mem_util_pct = 100.0 * (double)m.used / (double)m.total;
      d.valid_mask |= 1u << 1;
    }
  }
  unsigned int t = 0;
  if (nvml_->Temperature && nvml_->Temperature(dev, NVML_TEMPERATURE_GPU, &t) == NVML_SUCCESS) {
    d.temperature_c = t;
    d.valid_mask |= 1u << 4;
  }
  unsigned int pw = 0;
  if (nvml_->PowerUsage && nvml_->PowerUsage(dev, &pw) == NVML_SUCCESS) {
    d.power_w = pw / 1000.0;
    d.valid_mask |= 1u << 5;
  }
  if (nvml_->PowerLimit && nvml_->PowerLimit(dev, &pw) == NVML_SUCCESS) {
    d.power_limit_w = pw / 1000.0;
    d.valid_mask |= 1u << 6;
  }
  unsigned long long en = 0;
  if (nvml_->Energy && nvml_->Energy(dev, &en) == NVML_SUCCESS) {
    d.energy_mj = en;
    d.valid_mask |= 1u << 7;
  }
  unsigned int clk = 0;
  if (nvml_->ClockInfo && nvml_->ClockInfo(dev, NVML_CLOCK_SM, &clk) == NVML_SUCCESS) {
    d.sm_clock_mhz = clk;
    d.valid_mask |= 1u << 8;
  }
  if (nvml_->ClockInfo && nvml_->ClockInfo(dev, NVML_CLOCK_MEM, &clk) == NVML_SUCCESS) {
    d.mem_clock_mhz = clk;
    d.valid_mask |= 1u << 9;
  }
  unsigned int thr = 0;
  if (nvml_->PcieThroughput &&
      nvml_->PcieThroughput(dev, NVML_PCIE_UTIL_TX_BYTES, &thr) == NVML_SUCCESS) {
    d.pcie_tx_kbps = thr;
    d.valid_mask |= 1u << 11;
  }
  if (nvml_->PcieThroughput &&
      nvml_->PcieThroughput(dev, NVML_PCIE_UTIL_RX_BYTES, &thr) == NVML_SUCCESS) {
    d.pcie_rx_kbps = thr;
    d.valid_mask |= 1u << 10;
  }
  unsigned int enc = 0, encs = 0;
  if (nvml_->EncoderUtil && nvml_->EncoderUtil(dev, &enc, &encs) == NVML_SUCCESS) {
    d.encoder_util_pct = enc;
    d.valid_mask |= 1u << 12;
  }
  unsigned int dec = 0, decs = 0;
  if (nvml_->DecoderUtil && nvml_->DecoderUtil(dev, &dec, &decs) == NVML_SUCCESS) {
    d.decoder_util_pct = dec;
    d.valid_mask |= 1u << 13;
  }
  unsigned long long reasons = 0;
  if (nvml_->ThrottleReasons && nvml_->ThrottleReasons(dev, &reasons) == NVML_SUCCESS) {
    d.throttle_reasons = reasons;
    d.valid_mask |= 1u << 14;
  }
  unsigned long long sbe = 0, dbe = 0;
  if (nvml_->EccErrors &&
      nvml_->EccErrors(dev, NVML_SINGLE_BIT_ECC, NVML_VOLATILE_ECC, &sbe) == NVML_SUCCESS) {
    d.ecc_sbe_total = sbe;
    d.valid_mask |= 1u << 15;
  }
  if (nvml_->EccErrors &&
      nvml_->EccErrors(dev, NVML_DOUBLE_BIT_ECC, NVML_VOLATILE_ECC, &dbe) == NVML_SUCCESS) {
    d.ecc_dbe_total = dbe;
    d.valid_mask |= 1u << 16;
  }
  unsigned long long retired = 0, pending = 0;
  if (nvml_->RetiredPages &&
      nvml_->RetiredPages(dev,
                          NVML_PAGE_RETIREMENT_CAUSE_MULTIPLE_SINGLE_BIT_ECC_ERROR |
                              NVML_PAGE_RETIREMENT_CAUSE_DOUBLE_BIT_ECC_ERROR,
                          &retired) == NVML_SUCCESS) {
    d.retired_pages = retired;
    d.valid_mask |= 1u << 17;
  }
  (void)pending;
  unsigned int mode = 0, pending_mode = 0;
  if (nvml_->MigMode && nvml_->MigMode(dev, &mode, &pending_mode) == NVML_SUCCESS) {
    d.is_mig = mode != 0;
  }
  return d;
}

GpuDeviceRow GpuMetrics::DrmDevice(const std::string& dev_path) const {
  GpuDeviceRow d;
  d.source = "drm";
  d.available = true;

  // vendor
  std::string vendor = ReadFileTrim(dev_path + "/vendor");
  unsigned long vid = strtoul(vendor.c_str(), nullptr, 16);
  if (vid == 0x10de) d.vendor = "nvidia";
  else if (vid == 0x1002) d.vendor = "amd";
  else if (vid == 0x8086) d.vendor = "intel";
  else d.vendor = "unknown";

  // pci_bdf from the card's device symlink (e.g. .../0000:01:00.0)
  {
    std::string dev_sym = dev_path;  // .../device
    char buf[512] = {0};
    ssize_t n = readlink(dev_sym.c_str(), buf, sizeof(buf) - 1);
    if (n > 0) {
      buf[n] = 0;
      std::string target = buf;
      size_t slash = target.find_last_of('/');
      d.pci_bdf = (slash == std::string::npos) ? target : target.substr(slash + 1);
      d.uuid = d.pci_bdf;
    } else {
      d.uuid = dev_path;
    }
  }

  std::string model = ReadFileTrim(dev_path + "/product_name");
  if (model.empty()) model = ReadFileTrim(dev_path + "/model");
  d.model = model;

  double busy = ParseD(ReadFileTrim(dev_path + "/gpu_busy_percent"), -1);
  if (busy >= 0) {
    d.util_pct = busy;
    d.valid_mask |= 1u << 0;
  }
  uint64_t used = ParseU64(ReadFileTrim(dev_path + "/mem_info_vram_used"));
  uint64_t total = ParseU64(ReadFileTrim(dev_path + "/mem_info_vram_total"));
  if (total) {
    d.mem_used_bytes = used;
    d.mem_total_bytes = total;
    d.valid_mask |= 1u << 2;
    d.valid_mask |= 1u << 3;
    d.mem_util_pct = 100.0 * (double)used / (double)total;
    d.valid_mask |= 1u << 1;
  }
  // hwmon: temperature / power
  for (int h = 0; h < 8; ++h) {
    std::string hw = dev_path + "/hwmon/hwmon" + std::to_string(h);
    std::ifstream probe(hw + "/temp1_input");
    if (!probe.good()) continue;
    double t = ParseD(ReadFileTrim(hw + "/temp1_input"), -1);
    if (t >= 0) {
      d.temperature_c = t / 1000.0;
      d.valid_mask |= 1u << 4;
    }
    double pw = ParseD(ReadFileTrim(hw + "/power1_average"), -1);
    if (pw >= 0) {
      d.power_w = pw / 1000000.0;
      d.valid_mask |= 1u << 5;
    }
    double cap = ParseD(ReadFileTrim(hw + "/power1_cap"), -1);
    if (cap >= 0) {
      d.power_limit_w = cap / 1000000.0;
      d.valid_mask |= 1u << 6;
    }
    break;
  }
  // pp_dpm_sclk: parse only a trivially parseable active line ("*" marker).
  {
    std::string sclk = ReadFileTrim(dev_path + "/pp_dpm_sclk");
    if (!sclk.empty() && sclk.find('*') != std::string::npos) {
      // format: "0: 500Mhz *" — parse the numeric before MHz/Mhz.
      char unit = 0;
      unsigned long v = 0;
      size_t star = sclk.find('*');
      std::istringstream is(sclk);
      std::string line;
      while (std::getline(is, line)) {
        if (line.find('*') == std::string::npos) continue;
        if (sscanf(line.c_str(), "%*d: %lu %c", &v, &unit) == 2) {
          d.sm_clock_mhz = unit == 'G' ? v * 1000 : v;
          d.valid_mask |= 1u << 8;
        }
        break;
      }
      (void)star;
    }
  }
  return d;
}

GpuSnapshot GpuMetrics::Snapshot(uint64_t ts_ns) {
  GpuSnapshot s;
  s.ts_ns = ts_ns;
  if (active_ == "off") {
    GpuDeviceRow d;
    d.uuid = "disabled";
    d.source = "off";
    d.available = false;
    d.error_text = "disabled";
    s.devices.push_back(d);
    return s;
  }
  if (active_ == "nvml") {
    for (uint32_t i = 0; i < nvml_count_; ++i) s.devices.push_back(NvmlDevice(i));
    return s;
  }
  if (active_ == "drm") {
    for (const auto& c : drm_cards_) s.devices.push_back(DrmDevice(c));
    return s;
  }
  // unavailable
  GpuDeviceRow d;
  d.uuid = "unavailable";
  d.source = source_ == "auto" ? "auto" : source_;
  d.available = false;
  d.error_text = fail_reason_;
  s.devices.push_back(d);
  return s;
}

void GpuMetrics::BeginDeep() {
  // NVML process snapshots use device handles enumerated on demand; nothing
  // to prepare.
}

std::vector<DeepGpuProcessRow> GpuMetrics::NvmlProcesses(
    const std::unordered_set<uint32_t>& tgids, uint64_t collector_ts_ns) {
  std::vector<DeepGpuProcessRow> out;
  if (!nvml_) return out;

  for (uint32_t i = 0; i < nvml_count_; ++i) {
    void* dev = nullptr;
    if (nvml_->HandleByIndex(i, &dev) != NVML_SUCCESS || !dev) continue;
    std::string uuid;
    {
      char buf[96] = {0};
      if (nvml_->Uuid && nvml_->Uuid(dev, buf, sizeof(buf)) == NVML_SUCCESS) uuid = buf;
      if (uuid.empty()) uuid = "nvml-" + std::to_string(i);
    }
    unsigned long long mem_total = 0;
    {
      NvmlMemory m = {};
      if (nvml_->MemoryInfo && nvml_->MemoryInfo(dev, &m) == NVML_SUCCESS) mem_total = m.total;
    }
    NvmlProcessInfo procs[128];
    unsigned int n = 128;
    if (!nvml_->ProcInfo || nvml_->ProcInfo(dev, &n, procs) != NVML_SUCCESS) n = 0;
    if (n > 128) n = 128;
    (void)0;
    for (unsigned int k = 0; k < n && k < 128; ++k) {
      uint32_t pid = procs[k].pid;
      if (!pid) continue;
      uint32_t tgid = TgidOf(pid);
      if (!tgids.count(tgid)) continue;
      DeepGpuProcessRow r;
      r.ts_ns = collector_ts_ns;
      r.gpu_uuid = uuid;
      r.pid = pid;
      r.tgid = tgid;
      r.comm = CommOf(pid);
      r.source = "nvml";
      r.fb_used_bytes = procs[k].usedGpuMemory;
      r.valid_mask |= 1u << 4;  // fb used
      if (mem_total && procs[k].usedGpuMemory) {
        r.mem_util_pct = 100.0 * (double)procs[k].usedGpuMemory / (double)mem_total;
        r.valid_mask |= 1u << 1;
      }
      out.push_back(r);
    }
  }
  return out;
}

std::vector<DeepGpuProcessRow> GpuMetrics::SnapshotProcesses(
    const std::unordered_set<uint32_t>& tgids, uint64_t collector_ts_ns) {
  if (active_ != "nvml") return {};
  return NvmlProcesses(tgids, collector_ts_ns);
}

void GpuMetrics::Close() {
  if (nvml_) {
    nvml_->Close();
    delete nvml_;
    nvml_ = nullptr;
  }
  nvml_count_ = 0;
  drm_cards_.clear();
  active_.clear();
  fail_reason_.clear();
}

}  // namespace etrace_diag
