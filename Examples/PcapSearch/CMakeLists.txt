add_executable(PcapSearch main.cpp)

target_link_libraries(PcapSearch PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h and dirent.h not available on VStudio
  target_link_libraries(PcapSearch PRIVATE dirent-for-Visual-Studio Getopt-for-Visual-Studio)
endif()

set_target_properties(PcapSearch PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")
