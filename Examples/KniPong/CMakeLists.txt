add_executable(KniPong main.cpp)

target_link_libraries(KniPong PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(KniPong PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS AND WIN32)
  add_custom_command(TARGET KniPong POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:KniPong> $<TARGET_FILE_DIR:KniPong>
    COMMAND_EXPAND_LISTS
  )
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS KniPong
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})

  if(BUILD_SHARED_LIBS AND WIN32)
    install(
      FILES $<TARGET_RUNTIME_DLLS:KniPong>
      DESTINATION ${PCAPPP_INSTALL_BINDIR}
    )
  endif()
endif()
