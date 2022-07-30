cmake_minimum_required(VERSION 3.0)
project(memplumber CXX)

add_library(memplumber memplumber.cpp)

# Build options
option(COLLECT_STATIC_VAR_DATA
       "Collect data also on static variable memory allocation" OFF)
option(DISABLE_BACKTRACE "Disable backtrace" OFF)

if(COLLECT_STATIC_VAR_DATA)
  add_definitions(-DCOLLECT_STATIC_VAR_DATA)
endif()

target_include_directories(memplumber PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# execinfo for backtraces. This is only required on FreeBSD/Alpine, as both Mac
# OS X and Linux include backtrace functions in libSystem / libc.
find_package(Backtrace)
if(NOT Backtrace_FOUND)
  message(STATUS "Backtrace not found or not supported!")
  set(DISABLE_BACKTRACE ON)
else()
  target_include_directories(memplumber PUBLIC ${Backtrace_INCLUDE_DIRS})
  target_link_libraries(memplumber PUBLIC ${Backtrace_LIBRARIES})
endif()

if(DISABLE_BACKTRACE)
  add_definitions(-DDISABLE_BACKTRACE)
endif()

enable_testing()

add_subdirectory(Tests)

add_subdirectory(Examples)
