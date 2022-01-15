add_executable(TLSFingerprinting main.cpp)

target_link_libraries(TLSFingerprinting PUBLIC PcapPlusPlus::PcapPP)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(TLSFingerprinting PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(
  TLSFingerprinting
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples_bin"
             RUNTIME_OUTPUT_NAME "TLSFingerprinting")
