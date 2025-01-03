add_library(Getopt-for-Visual-Studio INTERFACE)

target_include_directories(Getopt-for-Visual-Studio INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/)

target_sources(Getopt-for-Visual-Studio INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/getopt.h)
