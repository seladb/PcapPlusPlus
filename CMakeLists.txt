cmake_minimum_required (VERSION 3.0)
project (PcapPlusPlus)

enable_testing()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules/")

include(DetectCompiler)

find_package(PCAP REQUIRED)


option(PCAPPP_ENABLE_CPP_FEATURE_DETECTION "PCAPPP_ENABLE_CPP_FEATURE_DETECTION")
if(PCAPPP_ENABLE_CPP_FEATURE_DETECTION)
	add_definitions(-DPCAPPP_CPP_FEATURE_DETECTION)
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
add_subdirectory(Tests)
add_subdirectory(Examples)
