cmake_minimum_required (VERSION 3.0)
project (debug-new CXX)

add_library (debug-new
    debug_new.cpp
    debug_new.h
)

target_include_directories(debug-new PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
