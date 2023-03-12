add_executable(TLSFingerprinting main.cpp)

target_link_libraries(TLSFingerprinting PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(TLSFingerprinting PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(TLSFingerprinting PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}"
  RUNTIME_OUTPUT_NAME "TLSFingerprinting")

if(BUILD_SHARED_LIBS)
  add_custom_command(TARGET TLSFingerprinting POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:TLSFingerprinting> $<TARGET_FILE_DIR:TLSFingerprinting>
    COMMAND_EXPAND_LISTS
  )
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS TLSFingerprinting
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
  install(
      FILES $<TARGET_RUNTIME_DLLS:TLSFingerprinting>
      DESTINATION ${PCAPPP_INSTALL_BINDIR}
  )
endif()
