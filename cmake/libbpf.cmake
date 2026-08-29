# Locates (or fetches) libbpf and exposes:
#   ETD_LIBBPF_INCLUDE_DIRS
#   ETD_LIBBPF_LIBRARY_DIRS
#   ETD_LIBBPF_LIBRARIES
#   libbpf_build  (custom target, only in the FetchContent path)
#
# Preference order (per design):
#   1. system libbpf via pkg-config
#   2. FetchContent of github.com/libbpf/libbpf built with `make -C <libbpf> src`

find_package(PkgConfig QUIET)

set(ETD_LIBBPF_INCLUDE_DIRS "" CACHE INTERNAL "")
set(ETD_LIBBPF_LIBRARY_DIRS "" CACHE INTERNAL "")
set(ETD_LIBBPF_LIBRARIES "" CACHE INTERNAL "")

if(PKG_CONFIG_FOUND)
  pkg_check_modules(LIBBPF QUIET libbpf)
endif()

if(LIBBPF_FOUND)
  message(STATUS "etrace-diag: using system libbpf ${LIBBPF_VERSION}")
  set(ETD_LIBBPF_INCLUDE_DIRS ${LIBBPF_INCLUDE_DIRS})
  set(ETD_LIBBPF_LIBRARY_DIRS ${LIBBPF_LIBRARY_DIRS})

  # Prefer a static libbpf.a when present (smaller deployment, no runtime
  # libbpf.so dependency); otherwise fall back to pkg-config's result.
  set(_sid_checked FALSE)
  foreach(_d ${LIBBPF_LIBRARY_DIRS} /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/lib/aarch64-linux-gnu)
    if(EXISTS "${_d}/libbpf.a")
      set(ETD_LIBBPF_LIBRARIES "${_d}/libbpf.a")
      set(_sid_checked TRUE)
      break()
    endif()
  endforeach()
  if(NOT _sid_checked)
    set(ETD_LIBBPF_LIBRARIES ${LIBBPF_LIBRARIES})
  endif()
else()
  message(STATUS "etrace-diag: libbpf not found via pkg-config; fetching and building libbpf")
  include(ExternalProject)

  set(LIBBPF_TAG v1.7.0 CACHE STRING "libbpf git tag")
  set(LIBBPF_PREFIX ${CMAKE_BINARY_DIR}/_deps/libbpf)
  set(LIBBPF_SOURCE_DIR ${LIBBPF_PREFIX}/src/libbpf_proj)
  set(LIBBPF_INSTALL ${LIBBPF_PREFIX}/install)

  ExternalProject_Add(
    libbpf_proj
    GIT_REPOSITORY https://github.com/libbpf/libbpf.git
    GIT_TAG ${LIBBPF_TAG}
    GIT_SHALLOW TRUE
    PREFIX ${LIBBPF_PREFIX}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND $(MAKE) -C src BUILD_STATIC_ONLY=1 -j &&
                  $(MAKE) -C src install_headers DESTDIR=${LIBBPF_INSTALL} PREFIX=/usr
    INSTALL_COMMAND ""
    LOG_BUILD ON
    LOG_DOWNLOAD ON)

  set(ETD_LIBBPF_STATIC_LIB ${LIBBPF_SOURCE_DIR}/src/libbpf.a)

  # install_headers yields <prefix>/usr/include/bpf/*.h; the uapi linux/*.h
  # headers come from the source tree.
  set(ETD_LIBBPF_INCLUDE_DIRS
      ${LIBBPF_INSTALL}/usr/include
      ${LIBBPF_SOURCE_DIR}/include/uapi)
  set(ETD_LIBBPF_LIBRARY_DIRS ${LIBBPF_SOURCE_DIR}/src)
  set(ETD_LIBBPF_LIBRARIES ${ETD_LIBBPF_STATIC_LIB})

  add_custom_target(
    libbpf_build ALL
    DEPENDS ${ETD_LIBBPF_STATIC_LIB}
    COMMENT "Building libbpf (make -C src)")
endif()

if(NOT ETD_LIBBPF_INCLUDE_DIRS)
  message(FATAL_ERROR "libbpf headers could not be located")
endif()