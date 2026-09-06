# Locates bpftool and exposes:
#   ETD_BPFTOOL  (absolute path)
#   ETD_BPFTOOL_PROG
# Also locates clang for the BPF compile step:
#   ETD_CLANG
find_program(ETD_BPFTOOL bpftool)
if(DEFINED BPFTOOL_PATH AND NOT BPFTOOL_PATH STREQUAL "")
  set(ETD_BPFTOOL ${BPFTOOL_PATH})
endif()
if(NOT ETD_BPFTOOL)
  # Also search versioned kernel-tools paths (openKylin ships bpftool under
  # /usr/lib/linux-tools/<ver>/).
  file(GLOB _bpftool_candidates
       /usr/lib/linux-tools*/bpftool
       /usr/lib/linux-tools*/*/bpftool)
  if(_bpftool_candidates)
    list(GET _bpftool_candidates 0 ETD_BPFTOOL)
  endif()
endif()
if(NOT ETD_BPFTOOL)
  message(FATAL_ERROR
    "bpftool not found. Install it (apt install bpftool or linux-tools-$(uname -r)) "
    "or pass -DBPFTOOL_PATH=/path/to/bpftool.")
endif()
message(STATUS "etrace-diag: using bpftool ${ETD_BPFTOOL}")

find_program(ETD_CLANG clang)
if(DEFINED CLANG_PATH AND NOT CLANG_PATH STREQUAL "")
  set(ETD_CLANG ${CLANG_PATH})
endif()
if(NOT ETD_CLANG)
  message(FATAL_ERROR "clang not found; required to compile BPF (clang -target bpf). "
                      "Pipeline install it or pass -DCLANG_PATH=/path/to/clang.")
endif()
message(STATUS "etrace-diag: using clang ${ETD_CLANG}")

# Host architecture -> __TARGET_ARCH_* token for BPF compilation.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
  set(ETD_BPF_ARCH_DEFINE -D__TARGET_ARCH_x86)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
  set(ETD_BPF_ARCH_DEFINE -D__TARGET_ARCH_arm64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "loongarch64|loong64")
  set(ETD_BPF_ARCH_DEFINE -D__TARGET_ARCH_loongarch)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
  set(ETD_BPF_ARCH_DEFINE -D__TARGET_ARCH_riscv)
else()
  message(WARNING "Unrecognized arch '${CMAKE_SYSTEM_PROCESSOR}'; defaulting to x86")
  set(ETD_BPF_ARCH_DEFINE -D__TARGET_ARCH_x86)
endif()