add_executable(DpdkTrafficFilter main.cpp)

target_link_libraries(DpdkTrafficFilter PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(DpdkTrafficFilter PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS AND WIN32)
  add_custom_command(TARGET DpdkTrafficFilter POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:DpdkTrafficFilter> $<TARGET_FILE_DIR:DpdkTrafficFilter>
    COMMAND_EXPAND_LISTS
  )
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS DpdkTrafficFilter
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})

  if(BUILD_SHARED_LIBS AND WIN32)
    install(
      FILES $<TARGET_RUNTIME_DLLS:DpdkTrafficFilter>
      DESTINATION ${PCAPPP_INSTALL_BINDIR}
    )
  endif()
endif()