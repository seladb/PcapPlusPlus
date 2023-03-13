add_executable(FuzzTarget FuzzTarget.cpp)

target_link_libraries(FuzzTarget PRIVATE Pcap++ -fsanitize=fuzzer)

if(BUILD_SHARED_LIBS AND WIN32)
    add_custom_command(
      TARGET FuzzTarget
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:FuzzTarget> $<TARGET_FILE_DIR:FuzzTarget>
      COMMAND_EXPAND_LISTS)
endif()
