# - Try to find libbpf
#
# Once done this will define
#  BPF_FOUND        - System has libbpf
#  BPF_INCLUDE_DIRS - The libbpf include directories
#  BPF_LIBRARIES    - The libraries needed to use libbpf

find_package(PkgConfig QUIET)
pkg_check_modules(PC_LIBBPF libbpf)

find_path(BPF_INCLUDE_DIR
  NAMES bpf/bpf.h
  HINTS ${PC_LIBBPF_INCLUDE_DIRS})

find_library(
  BPF_LIBRARY
  NAMES bpf
  HINTS ${PC_LIBBPF_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  BPF
  REQUIRED_VARS BPF_LIBRARY BPF_INCLUDE_DIR
  VERSION_VAR BPF_VERSION
  FAIL_MESSAGE "libbpf not found!")

if(BPF_FOUND AND NOT TARGET BPF::BPF)
  add_library(BPF::BPF INTERFACE IMPORTED)
  set_target_properties(
    BPF::BPF
    PROPERTIES INTERFACE_LINK_LIBRARIES "${BPF_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${BPF_INCLUDE_DIR}"
    INTERFACE_COMPILE_OPTIONS "${BPF_CFLAGS_OTHER}")
endif()
