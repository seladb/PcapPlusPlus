add_executable(PcapPrinter main.cpp)

target_link_libraries(PcapPrinter PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(PcapPrinter PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(PcapPrinter PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS AND WIN32)
  add_custom_command(TARGET PcapPrinter POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:PcapPrinter> $<TARGET_FILE_DIR:PcapPrinter>
    COMMAND_EXPAND_LISTS
  )
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS PcapPrinter
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})

  if(BUILD_SHARED_LIBS AND WIN32)
    install(
      FILES $<TARGET_RUNTIME_DLLS:PcapPrinter>
      DESTINATION ${PCAPPP_INSTALL_BINDIR}
    )
  endif()
endif()
