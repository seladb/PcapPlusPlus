add_executable(DNSResolver main.cpp)

target_link_libraries(DNSResolver PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(DNSResolver PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(DNSResolver PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")
