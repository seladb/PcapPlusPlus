add_executable(PfRingTrafficFilter main.cpp)

target_link_libraries(PfRingTrafficFilter PUBLIC PcapPlusPlus::PcapPP)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(PfRingTrafficFilter PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(
  PfRingTrafficFilter PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                 "${CMAKE_BINARY_DIR}/examples_bin")
