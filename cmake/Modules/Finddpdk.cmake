# Try to find dpdk
#
# Once done, this will define
#
# dpdk::dpdk
# dpdk_FOUND
# dpdk_INCLUDE_DIR
# dpdk_LIBRARIES

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(dpdk QUIET libdpdk)
endif()

if(dpdk_INCLUDE_DIRS)
  # good
elseif(TARGET dpdk::dpdk)
  get_target_property(dpdk_INCLUDE_DIRS dpdk::dpdk
                      INTERFACE_INCLUDE_DIRECTORIES)
else()
  find_path(
    dpdk_config_INCLUDE_DIR rte_config.h
    HINTS ENV DPDK_DIR
    PATH_SUFFIXES dpdk include)
  find_path(
    dpdk_common_INCLUDE_DIR rte_common.h
    HINTS ENV DPDK_DIR
    PATH_SUFFIXES dpdk include)
  set(dpdk_INCLUDE_DIRS "${dpdk_config_INCLUDE_DIR}")
  if(NOT dpdk_config_INCLUDE_DIR STREQUAL dpdk_common_INCLUDE_DIR)
    list(APPEND dpdk_INCLUDE_DIRS "${dpdk_common_INCLUDE_DIR}")
  endif()
endif()

# Order is important ! Taken from the DPKT pkg-config file
set(components
    common_cpt
    common_dpaax
    common_iavf
    common_octeontx
    common_octeontx2
    common_sfc_efx
    bus_dpaa
    bus_fslmc
    bus_ifpga
    bus_pci
    bus_vdev
    bus_vmbus
    common_qat
    mempool_bucket
    mempool_dpaa
    mempool_dpaa2
    mempool_octeontx
    mempool_octeontx2
    mempool_ring
    mempool_stack
    net_af_packet
    net_ark
    net_atlantic
    net_avp
    net_axgbe
    net_bond
    net_bnxt
    net_cxgbe
    net_dpaa
    net_dpaa2
    net_e1000
    net_ena
    net_enetc
    net_enic
    net_failsafe
    net_fm10k
    net_i40e
    net_hinic
    net_hns3
    net_iavf
    net_ice
    net_igc
    net_ixgbe
    net_kni
    net_liquidio
    net_memif
    net_netvsc
    net_nfp
    net_null
    net_octeontx
    net_octeontx2
    net_pcap
    net_pfe
    net_qede
    net_ring
    net_sfc
    net_softnic
    net_tap
    net_thunderx
    net_txgbe
    net_vdev_netvsc
    net_vhost
    net_virtio
    net_vmxnet3
    raw_dpaa2_cmdif
    raw_dpaa2_qdma
    raw_ioat
    raw_ntb
    raw_octeontx2_dma
    raw_octeontx2_ep
    raw_skeleton
    crypto_bcmfs
    crypto_caam_jr
    crypto_dpaa_sec
    crypto_dpaa2_sec
    crypto_nitrox
    crypto_null
    crypto_octeontx
    crypto_octeontx2
    crypto_scheduler
    crypto_virtio
    compress_octeontx
    regex_octeontx2
    vdpa_ifc
    event_dlb
    event_dlb2
    event_dpaa
    event_dpaa2
    event_octeontx2
    event_opdl
    event_skeleton
    event_sw
    event_dsw
    event_octeontx
    baseband_null
    baseband_turbo_sw
    baseband_fpga_lte_fec
    baseband_fpga_5gnr_fec
    baseband_acc100
    node
    graph
    bpf
    flow_classify
    pipeline
    table
    port
    fib
    ipsec
    vhost
    stack
    security
    sched
    reorder
    rib
    regexdev
    rawdev
    pdump
    power
    member
    lpm
    latencystats
    kni
    jobstats
    ip_frag
    gso
    gro
    eventdev
    efd
    distributor
    cryptodev
    compressdev
    cfgfile
    bitratestats
    bbdev
    acl
    timer
    hash
    metrics
    cmdline
    pci
    ethdev
    meter
    net
    mbuf
    mempool
    rcu
    ring
    eal
    telemetry
    kvargs)

# for collecting dpdk library targets, it will be used when defining dpdk::dpdk
set(_dpdk_libs)
# for list of dpdk library archive paths
set(dpdk_LIBRARIES "")
foreach(c ${components})
  set(dpdk_lib dpdk::${c})
  if(TARGET ${dpdk_lib})
    get_target_property(DPDK_rte_${c}_LIBRARY ${dpdk_lib} IMPORTED_LOCATION)
  else()
    find_library(
      DPDK_rte_${c}_LIBRARY rte_${c}
      HINTS ENV DPDK_DIR ${dpdk_LIBRARY_DIRS}
      PATH_SUFFIXES lib)
  endif()
  if(DPDK_rte_${c}_LIBRARY)
    if(NOT TARGET ${dpdk_lib})
      add_library(${dpdk_lib} UNKNOWN IMPORTED)
      set_target_properties(
        ${dpdk_lib}
        PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${dpdk_INCLUDE_DIRS}"
                   IMPORTED_LOCATION "${DPDK_rte_${c}_LIBRARY}")
      if(c STREQUAL pmd_mlx5)
        find_package(verbs QUIET)
        if(verbs_FOUND)
          target_link_libraries(${dpdk_lib} INTERFACE IBVerbs::verbs)
        endif()
      endif()
    endif()
    list(APPEND _dpdk_libs ${dpdk_lib})
    list(APPEND dpdk_LIBRARIES ${DPDK_rte_${c}_LIBRARY})
  endif()
endforeach()

mark_as_advanced(dpdk_INCLUDE_DIRS ${dpdk_LIBRARIES})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(dpdk DEFAULT_MSG dpdk_INCLUDE_DIRS
                                  dpdk_LIBRARIES)

if(dpdk_FOUND)
  if(NOT TARGET dpdk::cflags)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64|x86_64|AMD64")
      set(rte_cflags "-march=core2")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM")
      set(rte_cflags "-march=armv7-a")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|AARCH64")
      set(rte_cflags "-march=armv8-a+crc")
    endif()
    add_library(dpdk::cflags INTERFACE IMPORTED)
    if(rte_cflags)
      set_target_properties(dpdk::cflags PROPERTIES INTERFACE_COMPILE_OPTIONS
                                                    "${rte_cflags}")
    endif()
  endif()

  if(NOT TARGET dpdk::dpdk)
    add_library(dpdk::dpdk INTERFACE IMPORTED)
    find_package(Threads QUIET)
    list(APPEND _dpdk_libs Threads::Threads dpdk::cflags numa dl)
    set_target_properties(
      dpdk::dpdk
      PROPERTIES INTERFACE_LINK_LIBRARIES "${_dpdk_libs}"
                 INTERFACE_INCLUDE_DIRECTORIES "${dpdk_INCLUDE_DIRS}")
  endif()
endif()

unset(_dpdk_libs)
