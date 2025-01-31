add_library(EndianPortable INTERFACE)

target_include_directories(EndianPortable INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_sources(EndianPortable INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include/EndianPortable.h)
