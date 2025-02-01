# ~~~
# - Try to find libxdp
#
# Once done this will define
#
#  XDP_FOUND        - System has libxdp
#  XDP_INCLUDE_DIRS - The libxdp include directories
#  XDP_LIBRARIES    - The libraries needed to use libxdp
# ~~~

find_package(PkgConfig QUIET)
pkg_check_modules(PC_LIBBPF libxdp)

find_path(
  XDP_INCLUDE_DIRS
  NAMES xdp/xsk.h
  HINTS ${PC_LIBXDP_INCLUDE_DIRS})

find_library(
  XDP
  NAMES xdp
  HINTS ${PC_LIBXDP_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  XDP
  REQUIRED_VARS XDP XDP_INCLUDE_DIRS
  VERSION_VAR XDP_VERSION
  FAIL_MESSAGE "libxdp not found!")

if(XDP_FOUND AND NOT TARGET XDP::XDP)
  add_library(XDP::XDP INTERFACE IMPORTED)
  set_target_properties(XDP::XDP PROPERTIES INTERFACE_LINK_LIBRARIES "${XDP_LIBRARIES}" INTERFACE_INCLUDE_DIRECTORIES "${XDP_INCLUDE_DIRS}")
endif()
