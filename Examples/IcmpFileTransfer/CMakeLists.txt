add_executable(IcmpFileTransfer-catcher Common.cpp IcmpFileTransfer-catcher.cpp)

target_link_libraries(IcmpFileTransfer-catcher PUBLIC PcapPlusPlus::PcapPP)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(IcmpFileTransfer-catcher
                        PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(
  IcmpFileTransfer-catcher PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                      "${CMAKE_BINARY_DIR}/examples_bin")

add_executable(IcmpFileTransfer-pitcher Common.cpp IcmpFileTransfer-pitcher.cpp)

target_link_libraries(IcmpFileTransfer-pitcher PUBLIC PcapPlusPlus::PcapPP)

if(MSVC)
  # This executable requires getopt.h not avaible on VStudio
  target_link_libraries(IcmpFileTransfer-pitcher
                        PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(
  IcmpFileTransfer-pitcher PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                      "${CMAKE_BINARY_DIR}/examples_bin")
