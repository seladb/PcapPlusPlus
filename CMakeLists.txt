cmake_minimum_required (VERSION 3.0)
project (PcapPlusPlus)

enable_testing()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules/")

include(DetectCompiler)

find_package(PCAP REQUIRED)

# Build options
option(PCAPPP_BUILD_EXAMPLES               "Build Examples")
option(PCAPPP_BUILD_TESTS                  "Build Tests")
option(PCAPPP_ENABLE_CPP_FEATURE_DETECTION "Enable C++ Feature Detection")
option(PCAPPP_USE_DPDK                     "Setup PcapPlusPlus with DPDK. In this case you must also set DPDK_HOME")
option(PCAPPP_USE_PF_RING                  "Setup PcapPlusPlus with PF_RING. In this case you must also set PF_RING_HOME")

if(PCAPPP_ENABLE_CPP_FEATURE_DETECTION)
    add_definitions(-DPCAPPP_CPP_FEATURE_DETECTION)
endif()

if(PCAPP_USE_DPDK)
    add_definitions(-DUSE_DPDK)
    set(DPDK_HOME "" CACHE STRING "Sets DPDK home directoy." FORCE)
endif()

if(PCAPP_USE_PF_RING)
    add_definitions(-DUSE_PF_RING)
    set(PF_RING_HOME "" CACHE STRING "Sets PF_RING home directory." FORCE)
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

# some sensible default compiler options
# NOTE(eteran): I'd like to use -W -Wall -pedantic, but that has a LOT of warnings for now
if (TARGET_COMPILER_CLANG OR TARGET_COMPILER_GCC)
	add_compile_options(-Wall)
endif()

add_subdirectory(Packet++)
add_subdirectory(Pcap++)
add_subdirectory(Common++)
add_subdirectory(3rdParty)

if(PCAPPP_BUILD_TESTS)
    add_subdirectory(Tests)
endif()

if(PCAPPP_BUILD_EXAMPLES)
    add_subdirectory(Examples)
endif()

