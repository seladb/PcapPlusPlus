add_executable(Arping main.cpp)

target_link_libraries(Arping PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(Arping PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(Arping PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                        "${PCAPPP_BINARY_EXAMPLES_DIR}")
