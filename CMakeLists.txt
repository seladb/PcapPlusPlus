cmake_minimum_required (VERSION 3.0)
project (PcapPlusPlus)

enable_testing()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules/")

find_package(PCAP REQUIRED)

# NOTE(eteran): this was set in the original build, but I don't see
# it being used in the source code anywhere...
add_definitions(-DPCAPPP_CPP_FEATURE_DETECTION)

add_subdirectory(Packet++)
add_subdirectory(Pcap++)
add_subdirectory(Common++)
add_subdirectory(3rdParty)
add_subdirectory(Tests)
