cmake_minimum_required (VERSION 3.0)
project (PcapPlusPlus)

enable_testing()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules/")

find_package(PCAP REQUIRED)

# NOTE(eteran): this was set in the original build, but I don't see
# it being used in the source code anywhere...
add_definitions(-DPCAPPP_CPP_FEATURE_DETECTION)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

# some sensible default compiler options
# TODO(eteran): only do this for compilers that support it...
add_compile_options(-Wall)

add_subdirectory(Packet++)
add_subdirectory(Pcap++)
add_subdirectory(Common++)
add_subdirectory(3rdParty)
add_subdirectory(Tests)
