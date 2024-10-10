# ~~~
# - Try to find DPDK include dirs and libraries
#
# Find the DPDK includes and client library
# This module defines:
#  DPDK_FOUND, If false, do not try to use DPDK.
#  DPDK_INCLUDE_DIRS, where to find rte_config.h and rte_version.h
#  DPDK_LIBRARIES, the libraries needed by a DPDK user
#  DPDK_CFLAGS_OTHER, the compile flags to use
#  DPDK_VERSION, the version of the library
# ~~~

include(FindPackageHandleStandardArgs)

function(DPDK_READ_VERSION DPDK_VERSION DPDK_VERSION_FILE)
  if(NOT DPDK_VERSION_FILE)
    return()
  endif()

  file(READ "${DPDK_VERSION_FILE}" DPDK_VERSION_STR)
  string(REGEX MATCH "#define RTE_VER_YEAR ([0-9]+)" _ ${DPDK_VERSION_STR})
  set(DPDK_VERSION_MAJOR ${CMAKE_MATCH_1})

  string(REGEX MATCH "#define RTE_VER_MONTH ([0-9]+)" _ ${DPDK_VERSION_STR})
  set(DPDK_VERSION_MINOR ${CMAKE_MATCH_1})

  string(REGEX MATCH "#define RTE_VER_MINOR ([0-9]+)" _ ${DPDK_VERSION_STR})
  set(DPDK_VERSION_PATCH ${CMAKE_MATCH_1})

  set(DPDK_VERSION "${DPDK_VERSION_MAJOR}.${DPDK_VERSION_MINOR}.${DPDK_VERSION_PATCH}" PARENT_SCOPE)
endfunction()

# Try to find DPDK with pkg-config first!
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(DPDK QUIET IMPORTED_TARGET libdpdk>=18.11)
endif()

# We found using Pkg-Config!
if(DPDK_FOUND)
  message("DPDK found with pkg-config")
  if(DPDK_DEBUG)
    message("-----------")
    message("Libraries: ${DPDK_LIBRARIES}")
    message("Link Libraries: ${DPDK_LINK_LIBRARIES}")
    message("Library DIr: ${DPDK_LIBRARY_DIRS}")
    message("Ldflags: ${DPDK_LDFLAGS}")
    message("Include Dirs: ${DPDK_INCLUDE_DIRS}")
    message("Cflags: ${DPDK_CFLAGS}")
    message("Cflags Other: ${DPDK_CFLAGS_OTHER}")
    message("Version: ${DPDK_VERSION}")
    message("-----------")
  endif()
else()
  message("DPDK not found with pkg-config trying legacy mode")

  # Find the include dirs and get the version
  find_path(DPDK_VERSION_INCLUDE_DIR rte_version.h REQUIRED PATH_SUFFIXES dpdk include)
  find_path(DPDK_CONFIG_INCLUDE_DIR rte_config.h REQUIRED PATH_SUFFIXES dpdk include)

  set(DPDK_INCLUDE_DIRS ${DPDK_INCLUDE_DIRS})
  list(APPEND DPDK_INCLUDE_DIRS ${DPDK_VERSION_INCLUDE_DIR})
  list(APPEND DPDK_INCLUDE_DIRS ${DPDK_CONFIG_INCLUDE_DIR})
  list(REMOVE_DUPLICATES DPDK_INCLUDE_DIRS)

  dpdk_read_version(DPDK_VERSION "${DPDK_VERSION_INCLUDE_DIR}/rte_version.h")
  # If no version found fall back to rte_build_config.h
  if(DPDK_VERSION STREQUAL "..")
    find_file(DPDK_BUILD_CONFIG_INCLUDE rte_build_config.h PATHS ${DPDK_INCLUDE_DIRS})
    if(DPDK_BUILD_CONFIG_INCLUDE)
      dpdk_read_version(DPDK_VERSION "${DPDK_BUILD_CONFIG_INCLUDE_DIR}/rte_build_config.h")
    endif()
    if(DPDK_VERSION STREQUAL "..")
      message(WARN "Can't parse DPDK version!")
    endif()
  endif()

  # Get all the libraries regarding the version
  list(
    APPEND
    _DPDK_LOOK_FOR_LIBS
    net
    kni
    ethdev
    mbuf
    eal
    mempool
    ring
    kvargs
    hash
    cmdline
    pci
    bus_pci
    bus_vdev
    mempool_ring
  )

  if(DPDK_VERSION VERSION_LESS "20.11")
    list(
      APPEND
      _DPDK_LOOK_FOR_LIBS
      pmd_bond
      pmd_vmxnet3
      pmd_virtio
      pmd_enic
      pmd_i40e
      pmd_fm10k
      pmd_ixgbe
      pmd_e1000
      pmd_ring
      pmd_af_packet
    )
  endif()

  # Check that all libraries exists
  foreach(lib ${_DPDK_LOOK_FOR_LIBS})
    # Regarding the build system used make or meson the librte_pmd_vmxnet3 could be named librte_pmd_vmxnet3_uio
    find_library(rte_${lib} NAMES rte_${lib} rte_${lib}_uio NAMES_PER_DIR REQUIRED)
    list(APPEND DPDK_LIBRARIES ${rte_${lib}})

    get_filename_component(_DPDK_LIBRARY_DIR ${rte_${lib}} PATH)
    list(APPEND DPDK_LIBRARY_DIRS ${_DPDK_LIBRARY_DIR})
  endforeach()
  unset(_DPDK_LOOK_FOR_LIBS)
  unset(_DPDK_LIBRARY_DIR)
  list(REMOVE_DUPLICATES DPDK_LIBRARY_DIRS)

  # We also need NUMA, Threads and DL
  find_package(NUMA REQUIRED)
  find_package(Threads REQUIRED)

  list(APPEND DPDK_LIBRARIES Threads::Threads)
  list(APPEND DPDK_LIBRARIES NUMA::NUMA)
  list(APPEND DPDK_LIBRARIES ${CMAKE_DL_LIBS})

  # Add the CFLAGS
  list(APPEND DPDK_CFLAGS_OTHER "-include;rte_config.h")
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64|x86_64|AMD64")
    list(APPEND DPDK_CFLAGS_OTHER "-march=native")
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM")
    list(APPEND DPDK_CFLAGS_OTHER "-march=armv7-a")
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|AARCH64")
    list(APPEND DPDK_CFLAGS_OTHER "-march=armv8-a+crc")
  endif()

  if(DPDK_DEBUG)
    message("-----------")
    message("Libraries: ${DPDK_LIBRARIES}")
    message("Library Dir: ${DPDK_LIBRARY_DIRS}")
    message("Include Dirs: ${DPDK_INCLUDE_DIRS}")
    message("Cflags Other: ${DPDK_CFLAGS_OTHER}")
    message("Version: ${DPDK_VERSION}")
    message("-----------")
  endif()
endif()

find_package_handle_standard_args(DPDK REQUIRED_VARS DPDK_INCLUDE_DIRS DPDK_LIBRARIES VERSION_VAR DPDK_VERSION)

if(NOT TARGET DPDK::DPDK)
  add_library(DPDK::DPDK INTERFACE IMPORTED)
  find_package(Threads QUIET)
  set_target_properties(
    DPDK::DPDK
    PROPERTIES
      INTERFACE_LINK_LIBRARIES "${DPDK_LIBRARIES}"
      INTERFACE_INCLUDE_DIRECTORIES "${DPDK_INCLUDE_DIRS}"
      INTERFACE_COMPILE_OPTIONS "${DPDK_CFLAGS_OTHER}"
  )

  # At this steps DPDK is found check if KNI is supported
  include(CheckIncludeFiles)
  check_include_files(rte_kni.h HAVE_DPDK_RTE_KNI)
endif()

if(DPDK_DEBUG)
  include(CMakePrintHelpers)
  cmake_print_properties(
    TARGETS DPDK::DPDK
    PROPERTIES INTERFACE_LINK_LIBRARIES INTERFACE_COMPILE_OPTIONS INTERFACE_INCLUDE_DIRECTORIES
  )
endif()
