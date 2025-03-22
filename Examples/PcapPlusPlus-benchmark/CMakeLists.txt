add_executable(BenchmarkExample benchmark.cpp)

target_link_libraries(BenchmarkExample PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(BenchmarkExample PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if("cxx_std_14" IN_LIST CMAKE_CXX_COMPILE_FEATURES)
  if(
    (CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL CMAKE_SYSTEM_PROCESSOR)
    AND (NOT MINGW)
    AND (NOT CMAKE_OSX_ARCHITECTURES OR (CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL CMAKE_OSX_ARCHITECTURES))
  )
    include(FetchContent)

    # Fetch Google Benchmark
    FetchContent_Declare(benchmark GIT_REPOSITORY https://github.com/google/benchmark.git GIT_TAG v1.9.0)

    # Disable testing and installation for Google Benchmark
    set(BENCHMARK_ENABLE_TESTING OFF)
    set(BENCHMARK_ENABLE_INSTALL OFF)
    FetchContent_MakeAvailable(benchmark)

    add_executable(BenchmarkExampleGoogle benchmark-google.cpp)

    target_link_libraries(BenchmarkExampleGoogle PUBLIC PcapPlusPlus::Pcap++ benchmark::benchmark)

    set_target_properties(BenchmarkExampleGoogle PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")
  else()
    message(WARNING "Google Benchmark backend is not supported for cross-compilation")
  endif()
else()
  message(WARNING "Google Benchmark backend requires C++14 support")
endif()

if(PCAPPP_INSTALL)
  install(TARGETS BenchmarkExample EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})

  if(TARGET BenchmarkExampleGoogle)
    install(TARGETS BenchmarkExampleGoogle EXPORT PcapPlusPlusTargets RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
  endif()
endif()
