add_library(dirent-for-Visual-Studio INTERFACE)

target_include_directories(dirent-for-Visual-Studio INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_sources(dirent-for-Visual-Studio INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include/dirent.h)
