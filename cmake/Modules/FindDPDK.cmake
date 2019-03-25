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

find_package(Threads)
find_package(NUMA)

find_library(DPDK_LIBRARIES dpdk
	HINTS
	${DPDK_HOME}/lib
	${DPDK_HOME}/build
	${DPDK_HOME}/build/lib
)

find_path(DPDK_INCLUDE_DIRS rte_version.h
	HINTS 
	${DPDK_HOME}/build
	${DPDK_HOME}/include
	${DPDK_HOME}/build/include
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DPDK
    REQUIRED_VARS 
		DPDK_LIBRARIES
		DPDK_INCLUDE_DIRS
    FAIL_MESSAGE 
		"DPDK not found! Please specify DPDK_HOME."
)

# NOTE(eteran): I wish I didn't need to do this globally, but the per-target verison requires bleeding edge cmake
get_filename_component(DPDK_LIBRARY_PATH ${DPDK_LIBRARIES} DIRECTORY)
link_directories(${DPDK_LIBRARY_PATH})

set(DPDK_LIBRARIES 
	${DPDK_LIBRARIES}
	${CMAKE_DL_LIBS}
	Threads::Threads
	NUMA::NUMA
)

if(DPDK_FOUND AND NOT TARGET DPDK::DPDK)
	add_library(DPDK::DPDK INTERFACE IMPORTED)

	#TODO(eteran): actually test which flags we need to add!
	set_property(TARGET DPDK::DPDK PROPERTY INTERFACE_COMPILE_OPTIONS -msse -msse2 -msse3 -mssse3)
	set_property(TARGET DPDK::DPDK PROPERTY INTERFACE_LINK_LIBRARIES "${DPDK_LIBRARIES}")
	set_property(TARGET DPDK::DPDK PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${DPDK_INCLUDE_DIRS}")
endif()


