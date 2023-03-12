add_executable(PcapSplitter main.cpp)

target_link_libraries(PcapSplitter PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(PcapSplitter PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(PcapSplitter PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS AND WIN32)
  add_custom_command(TARGET PcapSplitter POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:PcapSplitter> $<TARGET_FILE_DIR:PcapSplitter>
    COMMAND_EXPAND_LISTS
  )
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS PcapSplitter
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})

  if(BUILD_SHARED_LIBS AND WIN32)
    install(
      FILES $<TARGET_RUNTIME_DLLS:PcapSplitter>
      DESTINATION ${PCAPPP_INSTALL_BINDIR}
    )
  endif()
endif()