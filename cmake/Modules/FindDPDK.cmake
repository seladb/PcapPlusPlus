# - Try to find DPDK include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(DPDK)
#
# Variables defined by this module:
#
#  DPDK_FOUND                System has DPDK include and library dirs found
#  DPDK_INCLUDE_DIRS         The DPDK include directories.
#  DPDK_LIBRARIES            The DPDK library

find_library(DPDK_LIBRART_RTE_PCI 
	rte_pci
	${DPDK_HOME}/lib
	${DPDK_HOME}/build
	${DPDK_HOME}/build/lib
)

find_library(DPDK_LIBRART_RTE_BUS_PCI 
	rte_bus_pci
	${DPDK_HOME}/lib
	${DPDK_HOME}/build
	${DPDK_HOME}/build/lib
)

find_library(DPDK_LIBRART_RTE_BUS_DEV
	rte_bus_vdev
	${DPDK_HOME}/lib
	${DPDK_HOME}/build
	${DPDK_HOME}/build/lib
)

find_library(DPDK_LIBRART_RTE_MEMPOOL_RING
	rte_mempool_ring
	${DPDK_HOME}/lib
	${DPDK_HOME}/build
	${DPDK_HOME}/build/lib
)

find_library(DPDK_LIBRART_RTE_BUS_VDEV
	rte_bus_vdev
	${DPDK_HOME}/lib
	${DPDK_HOME}/build
	${DPDK_HOME}/build/lib
)

find_library(DPDK_LIBRART_NUMA
	numa
	${DPDK_HOME}/lib
	${DPDK_HOME}/build
	${DPDK_HOME}/build/lib
)


find_path(DPDK_RTE_INCLUDE_DIR rte_version.h
	HINTS 
	${DPDK_HOME}/build
	${DPDK_HOME}/include
	${DPDK_HOME}/build/include
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DPDK
    REQUIRED_VARS 
		DPDK_LIBRART_RTE_PCI 
		DPDK_LIBRART_RTE_BUS_PCI 
		DPDK_LIBRART_RTE_BUS_DEV
		DPDK_LIBRART_RTE_MEMPOOL_RING
		DPDK_LIBRART_RTE_BUS_VDEV
		DPDK_INCLUDE_DIRS
    FAIL_MESSAGE 
		"DPDK not found! Please specify DPDK_HOME."
)

set(DPDK_LIBRARIES
	${DPDK_LIBRART_RTE_PCI}
	${DPDK_LIBRART_RTE_BUS_PCI}
	${DPDK_LIBRART_RTE_BUS_DEV}
	${DPDK_LIBRART_RTE_MEMPOOL_RING}
	${DPDK_LIBRART_RTE_BUS_VDEV}
	${DPDK_LIBRART_NUMA}
)
