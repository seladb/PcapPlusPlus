add_executable(Logger++Test main.cpp LoggerTests.cpp)

target_link_libraries(Logger++Test PUBLIC memplumber Common++ PcppTestFramework)

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(Logger++Test PRIVATE Getopt-for-Visual-Studio)
endif()

add_test(NAME Logger++Test COMMAND $<TARGET_FILE:Logger++Test> -n WORKING_DIRECTORY $<TARGET_FILE_DIR:Logger++Test>)
