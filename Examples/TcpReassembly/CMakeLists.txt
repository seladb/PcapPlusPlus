add_executable(TcpReassembly main.cpp)

target_link_libraries(TcpReassembly PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(TcpReassembly PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(TcpReassembly PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS AND WIN32)
  add_custom_command(TARGET TcpReassembly POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:TcpReassembly> $<TARGET_FILE_DIR:TcpReassembly>
    COMMAND_EXPAND_LISTS
  )
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS TcpReassembly
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})

  if(BUILD_SHARED_LIBS AND WIN32)
    install(
      FILES $<TARGET_RUNTIME_DLLS:TcpReassembly>
      DESTINATION ${PCAPPP_INSTALL_BINDIR}
    )
  endif()
endif()