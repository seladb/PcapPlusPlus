add_executable(IPDefragUtil main.cpp)

target_link_libraries(IPDefragUtil PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(IPDefragUtil PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(IPDefragUtil PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS AND WIN32)
  add_custom_command(
    TARGET IPDefragUtil
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:IPDefragUtil> $<TARGET_FILE_DIR:IPDefragUtil>
    COMMAND_EXPAND_LISTS)
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS IPDefragUtil
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})

  if(BUILD_SHARED_LIBS AND WIN32)
    install(FILES $<TARGET_RUNTIME_DLLS:IPDefragUtil> DESTINATION ${PCAPPP_INSTALL_BINDIR})
  endif()
endif()
