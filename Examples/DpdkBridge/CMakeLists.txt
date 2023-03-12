add_executable(DpdkBridge main.cpp)

target_link_libraries(DpdkBridge PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(DpdkBridge PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS AND WIN32)
  add_custom_command(TARGET DpdkBridge POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:DpdkBridge> $<TARGET_FILE_DIR:DpdkBridge>
    COMMAND_EXPAND_LISTS
  )
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS DpdkBridge
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})

  if(BUILD_SHARED_LIBS AND WIN32)
    install(
      FILES $<TARGET_RUNTIME_DLLS:DpdkBridge>
      DESTINATION ${PCAPPP_INSTALL_BINDIR}
    )
  endif()
endif()
