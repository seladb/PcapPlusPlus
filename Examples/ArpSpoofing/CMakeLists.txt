add_executable(ArpSpoofing main.cpp)

target_link_libraries(ArpSpoofing PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(ArpSpoofing PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(ArpSpoofing PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS AND WIN32)
  add_custom_command(TARGET ArpSpoofing POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:ArpSpoofing> $<TARGET_FILE_DIR:ArpSpoofing>
    COMMAND_EXPAND_LISTS
  )
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS ArpSpoofing
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})

  if(BUILD_SHARED_LIBS AND WIN32)
    install(
      FILES $<TARGET_RUNTIME_DLLS:ArpSpoofing>
      DESTINATION ${PCAPPP_INSTALL_BINDIR}
    )
  endif()
endif()
