add_executable(benchmark benchmark.cpp)

target_link_libraries(benchmark PUBLIC PcapPlusPlus::PcapPP)

set_target_properties(benchmark PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                           "${CMAKE_BINARY_DIR}/examples_bin")
