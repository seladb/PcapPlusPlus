add_executable(DnsSpoofing main.cpp)

target_link_libraries(DnsSpoofing PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(DnsSpoofing PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(DnsSpoofing PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS AND WIN32)
  add_custom_command(
    TARGET DnsSpoofing
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:DnsSpoofing> $<TARGET_FILE_DIR:DnsSpoofing>
    COMMAND_EXPAND_LISTS)
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS DnsSpoofing
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})

  if(BUILD_SHARED_LIBS AND WIN32)
    install(FILES $<TARGET_RUNTIME_DLLS:DnsSpoofing> DESTINATION ${PCAPPP_INSTALL_BINDIR})
  endif()
endif()
