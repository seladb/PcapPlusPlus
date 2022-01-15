add_executable(ArpSpoofing main.cpp)

target_link_libraries(ArpSpoofing PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(ArpSpoofing PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(ArpSpoofing PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                             "${PCAPPP_BINARY_EXAMPLES_DIR}")
