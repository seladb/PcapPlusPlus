add_executable(SSLAnalyzer main.cpp)

target_link_libraries(SSLAnalyzer PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(SSLAnalyzer PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(SSLAnalyzer PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS)
  add_custom_command(TARGET SSLAnalyzer POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:SSLAnalyzer> $<TARGET_FILE_DIR:SSLAnalyzer>
    COMMAND_EXPAND_LISTS
  )
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS SSLAnalyzer
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
  install(
      FILES $<TARGET_RUNTIME_DLLS:SSLAnalyzer>
      DESTINATION ${PCAPPP_INSTALL_BINDIR}
  )
endif()
