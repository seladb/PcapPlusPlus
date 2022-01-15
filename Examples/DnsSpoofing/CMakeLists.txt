add_executable(DnsSpoofing main.cpp)

target_link_libraries(DnsSpoofing PUBLIC PcapPlusPlus::PcapPP)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(DnsSpoofing PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(DnsSpoofing PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                             "${CMAKE_BINARY_DIR}/examples_bin")
