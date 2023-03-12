add_executable(benchmark benchmark.cpp)

target_link_libraries(benchmark PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(benchmark PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS)
  add_custom_command(TARGET benchmark POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:benchmark> $<TARGET_FILE_DIR:benchmark>
    COMMAND_EXPAND_LISTS
  )
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS benchmark
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})
  install(
      FILES $<TARGET_RUNTIME_DLLS:benchmark>
      DESTINATION ${PCAPPP_INSTALL_BINDIR}
  )
endif()
