add_executable(TLSFingerprinting main.cpp)

target_link_libraries(TLSFingerprinting PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(TLSFingerprinting PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(
  TLSFingerprinting
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}"
             RUNTIME_OUTPUT_NAME "TLSFingerprinting")
