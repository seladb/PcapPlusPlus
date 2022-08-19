add_executable(IPDefragUtil main.cpp)

target_link_libraries(IPDefragUtil PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(IPDefragUtil PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(
  IPDefragUtil PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                          "${CMAKE_BINARY_DIR}/examples_bin")
