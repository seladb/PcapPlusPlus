add_executable(PcapPrinter main.cpp)

target_link_libraries(PcapPrinter PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(PcapPrinter PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(PcapPrinter PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                             "${PCAPPP_BINARY_EXAMPLES_DIR}")
