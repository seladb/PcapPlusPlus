add_executable(TcpReassembly main.cpp)

target_link_libraries(TcpReassembly PUBLIC PcapPlusPlus::PcapPP)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(TcpReassembly PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(
  TcpReassembly PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                           "${CMAKE_BINARY_DIR}/examples_bin")
