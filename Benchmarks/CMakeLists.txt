cmake_minimum_required(VERSION 3.12)

project(PcapPlusPlusBenchmark)

set(CMAKE_PROJECT_HOMEPAGE_URL "https://pcapplusplus.github.io/")

# Set C++11
set(CMAKE_CXX_STANDARD 11)

if(TARGET Pcap++)
  # Are we building from the PcapPlusPlus project ??
  message(STATUS "Building benchmarks from PcapPlusPlus project")
  # Alias the project to make it compatible with imported package
  add_library(PcapPlusPlus::Pcap++ ALIAS Pcap++)
  add_library(PcapPlusPlus::Packet++ ALIAS Packet++)
else()
  find_package(PcapPlusPlus CONFIG REQUIRED)
  message(STATUS "Using Pcap++ ${PcapPlusPlus_VERSION}")
  message(STATUS "Include dir: ${PcapPlusPlus_INCLUDE_DIR}")
endif()

include(FetchContent)

# Fetch Google Benchmark
fetchcontent_declare(
  benchmark
  GIT_REPOSITORY https://github.com/google/benchmark.git
  GIT_TAG v1.9.0)

# Disable testing for benchmark
set(BENCHMARK_ENABLE_TESTING OFF)
fetchcontent_makeavailable(benchmark)

add_executable(PcppBenchmark benchmark.cpp)

target_link_libraries(PcppBenchmark PUBLIC PcapPlusPlus::Pcap++ PcapPlusPlus::Packet++ benchmark::benchmark)

set_property(TARGET PcppBenchmark PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET PcppBenchmark PROPERTY RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET PcppBenchmark PROPERTY RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
