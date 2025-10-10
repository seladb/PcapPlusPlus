
include(FetchContent)

if(NOT (
    (CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL CMAKE_SYSTEM_PROCESSOR)
    AND (NOT MINGW)
    AND (NOT CMAKE_OSX_ARCHITECTURES OR (CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL CMAKE_OSX_ARCHITECTURES))
   )
)
    message(WARNING "Google Benchmark backend is not supported for cross-compilation")
    return()
endif()

# Fetch Google Benchmark
FetchContent_Declare(benchmark GIT_REPOSITORY https://github.com/google/benchmark.git GIT_TAG v1.9.0)

# Disable testing and installation for Google Benchmark
set(BENCHMARK_ENABLE_TESTING OFF)
set(BENCHMARK_ENABLE_INSTALL OFF)
FetchContent_MakeAvailable(benchmark)

# Add PcapPlusPlus benchmarks
add_subdirectory(Packet++Bench)
