add_executable(PcapSearch main.cpp)

target_link_libraries(PcapSearch PUBLIC PcapPlusPlus::Pcap++)

if(MSVC)
  # This executable requires getopt.h and dirent.h not available on VStudio
  add_subdirectory(dirent-for-Visual-Studio)
  target_link_libraries(PcapSearch PRIVATE dirent-for-Visual-Studio Getopt-for-Visual-Studio)
endif()

set_target_properties(PcapSearch PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS)
  add_custom_command(TARGET PcapSearch POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:PcapSearch> $<TARGET_FILE_DIR:PcapSearch>
    COMMAND_EXPAND_LISTS
  )
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS PcapSearch
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
  install(
      FILES $<TARGET_RUNTIME_DLLS:PcapSearch>
      DESTINATION ${PCAPPP_INSTALL_BINDIR}
  )
endif()
