add_executable(PfRingTrafficFilter main.cpp)

target_link_libraries(PfRingTrafficFilter PUBLIC PcapPlusPlus::Pcap++)

set_target_properties(PfRingTrafficFilter PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_EXAMPLES_DIR}")

if(BUILD_SHARED_LIBS AND WIN32)
  add_custom_command(
    TARGET PfRingTrafficFilter
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:PfRingTrafficFilter>
            $<TARGET_FILE_DIR:PfRingTrafficFilter>
    COMMAND_EXPAND_LISTS)
endif()

if(PCAPPP_INSTALL)
  install(
    TARGETS PfRingTrafficFilter
    EXPORT PcapPlusPlusTargets
    RUNTIME DESTINATION ${PCAPPP_INSTALL_BINDIR})

  if(BUILD_SHARED_LIBS AND WIN32)
    install(FILES $<TARGET_RUNTIME_DLLS:PfRingTrafficFilter> DESTINATION ${PCAPPP_INSTALL_BINDIR})
  endif()
endif()
