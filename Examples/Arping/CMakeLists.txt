add_executable(Arping main.cpp)

target_link_libraries(Arping PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(Arping PRIVATE Getopt-for-Visual-Studio)
endif()

set_target_properties(Arping PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS)
  add_custom_command(TARGET Arping POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:Arping> $<TARGET_FILE_DIR:Arping>
    COMMAND_EXPAND_LISTS
  )
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS Arping
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
  install(
    FILES $<TARGET_RUNTIME_DLLS:Arping>
    DESTINATION ${PCAPPP_INSTALL_BINDIR}
  )
endif()
