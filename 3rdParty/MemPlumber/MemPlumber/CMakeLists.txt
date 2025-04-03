cmake_minimum_required(VERSION 3.12)
project(memplumber CXX)

add_library(memplumber memplumber.cpp)

# MAIN_PROJECT CHECK
set(MEMPLUMBER_MAIN_PROJECT OFF)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(MEMPLUMBER_MAIN_PROJECT ON)
endif()

# Build options
option(MEMPLUMBER_COLLECT_STATIC_VAR_DATA "Collect data also on static variable memory allocation" OFF)
option(MEMPLUMBER_DISABLE_BACKTRACE "Disable backtrace" OFF)
option(MEMPLUMBER_BUILD_TESTS "Build Tests" ${MEMPLUMBER_MAIN_PROJECT})
option(MEMPLUMBER_BUILD_EXAMPLES "Build Examples" ${MEMPLUMBER_MAIN_PROJECT})

if(MEMPLUMBER_COLLECT_STATIC_VAR_DATA)
  add_definitions(-DCOLLECT_STATIC_VAR_DATA)
endif()

target_include_directories(memplumber PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# execinfo for backtraces. This is only required on FreeBSD/Alpine, as both Mac
# OS X and Linux include backtrace functions in libSystem / libc.
find_package(Backtrace)
if(NOT Backtrace_FOUND)
  message(STATUS "Backtrace not found or not supported!")
  set(MEMPLUMBER_DISABLE_BACKTRACE ON)
else()
  target_include_directories(memplumber PUBLIC ${Backtrace_INCLUDE_DIRS})
  target_link_libraries(memplumber PUBLIC ${Backtrace_LIBRARIES})
endif()

if(MEMPLUMBER_DISABLE_BACKTRACE)
  add_definitions(-DDISABLE_BACKTRACE)
endif()

if(MEMPLUMBER_BUILD_TESTS)
  enable_testing()
  add_subdirectory(Tests)
endif()

if(MEMPLUMBER_BUILD_EXAMPLES)
  add_subdirectory(Examples)
endif()
