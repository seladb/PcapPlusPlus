add_executable(DpdkTrafficFilter main.cpp)

target_link_libraries(DpdkTrafficFilter PUBLIC PcapPlusPlus::PcapPP)

set_target_properties(
  DpdkTrafficFilter PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                               "${CMAKE_BINARY_DIR}/examples_bin")
