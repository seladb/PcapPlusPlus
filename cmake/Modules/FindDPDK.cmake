# Try to find DPDK
#
# Once done, this will define
#
# DPDK_FOUND
# DPDK_INCLUDE_DIRS
# DPDK_LIBRARIES

find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(DPDK QUIET libdpdk)
endif()
message(STATUS "Executing FindDPDK")
if(NOT DPDK_INCLUDE_DIRS)
  message(STATUS "Executing find_path")
  find_path(DPDK_config_INCLUDE_DIR rte_config.h
    HINTS
      ${DPDK_HOME}
    PATH_SUFFIXES
      DPDK
      include
)
  find_path(DPDK_common_INCLUDE_DIR rte_common.h
    HINTS
      ${DPDK_HOME}
    PATH_SUFFIXES
      DPDK
      include
)
  set(DPDK_INCLUDE_DIRS "${DPDK_config_INCLUDE_DIR}")
  if(NOT DPDK_config_INCLUDE_DIR EQUAL DPDK_common_INCLUDE_DIR)
    list(APPEND DPDK_INCLUDE_DIRS "${DPDK_common_INCLUDE_DIR}")
  endif()

  set(components
    bus_pci
    cmdline
    eal
    ethdev
    hash
    kvargs
    mbuf
    mempool
    mempool_ring
    mempool_stack
    pci
    pmd_af_packet
    pmd_bond
    pmd_i40e
    pmd_ixgbe
    pmd_mlx5
    pmd_ring
    pmd_vmxnet3_uio
    ring)

  set(DPDK_LIBRARIES)

  foreach(c ${components})
    find_library(DPDK_rte_${c}_LIBRARY rte_${c}
      HINTS
        ${DPDK_HOME}
        ${DPDK_LIBRARY_DIRS}
      PATH_SUFFIXES lib)
    if(DPDK_rte_${c}_LIBRARY)
      set(DPDK_lib DPDK::${c})
      if (NOT TARGET ${DPDK_lib})
        add_library(${DPDK_lib} UNKNOWN IMPORTED)
        set_target_properties(${DPDK_lib} PROPERTIES
          INTERFACE_INCLUDE_DIRECTORIES "${DPDK_INCLUDE_DIRS}"
          IMPORTED_LOCATION "${DPDK_rte_${c}_LIBRARY}")
        if(c STREQUAL pmd_mlx5)
          find_package(verbs QUIET)
          if(verbs_FOUND)
            target_link_libraries(${DPDK_lib} INTERFACE IBVerbs::verbs)
          endif()
        endif()
      endif()
      list(APPEND DPDK_LIBRARIES ${DPDK_lib})
    endif()
  endforeach()

  #
  # Where the heck did this list come from?  libdpdk on Ubuntu 20.04,
  # for example, doesn't even *have* -ldpdk; that's why we go with
  # pkg-config, in the hopes that it provides a correct set of flags
  # for this tangled mess.
  #
  list(APPEND DPDK_LIBRARIES dpdk rt m dl)
endif()

mark_as_advanced(DPDK_INCLUDE_DIRS ${DPDK_LIBRARIES})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DPDK DEFAULT_MSG
  DPDK_INCLUDE_DIRS
  DPDK_LIBRARIES)

if(DPDK_FOUND)
  if(NOT TARGET DPDK::cflags)
     if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64|x86_64|AMD64")
      set(rte_cflags "-march=core2")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM")
      set(rte_cflags "-march=armv7-a")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|AARCH64")
      set(rte_cflags "-march=armv8-a+crc")
    endif()
    add_library(DPDK::cflags INTERFACE IMPORTED)
    if (rte_cflags)
      set_target_properties(DPDK::cflags PROPERTIES
        INTERFACE_COMPILE_OPTIONS "${rte_cflags}")
    endif()
  endif()

  if(NOT TARGET DPDK::DPDK)
    add_library(DPDK::DPDK INTERFACE IMPORTED)
    find_package(Threads QUIET)
    list(APPEND DPDK_LIBRARIES
      Threads::Threads
      DPDK::cflags)
    set_target_properties(DPDK::DPDK PROPERTIES
      INTERFACE_LINK_LIBRARIES "${DPDK_LIBRARIES}"
      INTERFACE_INCLUDE_DIRECTORIES "${DPDK_INCLUDE_DIRS}")
  endif()
endif()
