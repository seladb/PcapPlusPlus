add_executable(DNSResolver main.cpp)

target_link_libraries(DNSResolver PUBLIC PcapPlusPlus::PcapPP)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(DNSResolver PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(DNSResolver PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                             "${CMAKE_BINARY_DIR}/examples_bin")
