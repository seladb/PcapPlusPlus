add_executable(IPFragUtil main.cpp)

target_link_libraries(IPFragUtil PUBLIC PcapPlusPlus::PcapPP)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(IPFragUtil PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(IPFragUtil PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                            "${CMAKE_BINARY_DIR}/examples_bin")
