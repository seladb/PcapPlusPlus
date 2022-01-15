add_executable(PcapSplitter main.cpp)

target_link_libraries(PcapSplitter PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(PcapSplitter PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(
  PcapSplitter PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                          "${PCAPPP_BINARY_EXAMPLES_DIR}")
