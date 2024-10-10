add_executable(BenchmarkExample benchmark.cpp)

target_link_libraries(BenchmarkExample PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(BenchmarkExample PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(PCAPPP_USE_GOOGLEBENCHMARK)
  include(FetchContent)

  # Fetch Google Benchmark
  fetchcontent_declare(
    benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG v1.9.0)

  # Disable testing for benchmark
  set(BENCHMARK_ENABLE_TESTING OFF)
  fetchcontent_makeavailable(benchmark)

  add_executable(BenchmarkExampleGoogle benchmark-google.cpp)

  target_link_libraries(BenchmarkExampleGoogle PUBLIC PcapPlusPlus::Pcap++ benchmark::benchmark)

  set_target_properties(BenchmarkExampleGoogle PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS BenchmarkExample
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})

  if(PCAPPP_USE_GOOGLEBENCHMARK)
    install(
      TARGETS BenchmarkExampleGoogle
      EXPORT PcapPlusPlusTargets
      RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
  endif()
endif()
