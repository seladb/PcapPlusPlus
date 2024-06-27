find_package(benchmark REQUIRED)

add_executable(PcppBenchmark benchmark.cpp)

target_link_libraries(PcppBenchmark PUBLIC Pcap++ Packet++ benchmark::benchmark)

set_property(TARGET PcppBenchmark PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET PcppBenchmark PROPERTY RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET PcppBenchmark PROPERTY RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
