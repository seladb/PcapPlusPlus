add_executable(HttpAnalyzer main.cpp)

target_link_libraries(HttpAnalyzer PUBLIC PcapPlusPlus::PcapPP)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(HttpAnalyzer PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(
  HttpAnalyzer PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                          "${CMAKE_BINARY_DIR}/examples_bin")
