add_executable(DpdkBridge main.cpp)

target_link_libraries(DpdkBridge PUBLIC PcapPlusPlus::PcapPP)

set_target_properties(DpdkBridge PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                            "${CMAKE_BINARY_DIR}/examples_bin")
