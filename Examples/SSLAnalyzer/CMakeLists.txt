add_executable(SSLAnalyzer main.cpp)

target_link_libraries(SSLAnalyzer PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(SSLAnalyzer PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(SSLAnalyzer PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                             "${CMAKE_BINARY_DIR}/examples_bin")
