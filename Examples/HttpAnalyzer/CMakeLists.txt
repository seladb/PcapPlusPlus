add_executable(HttpAnalyzer main.cpp)

target_link_libraries(HttpAnalyzer PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(HttpAnalyzer PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(HttpAnalyzer PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS AND WIN32)
  add_custom_command(
    TARGET HttpAnalyzer
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:HttpAnalyzer> $<TARGET_FILE_DIR:HttpAnalyzer>
    COMMAND_EXPAND_LISTS)
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS HttpAnalyzer
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})

  if(BUILD_SHARED_LIBS AND WIN32)
    install(FILES $<TARGET_RUNTIME_DLLS:HttpAnalyzer> DESTINATION ${PCAPPP_INSTALL_BINDIR})
  endif()
endif()
