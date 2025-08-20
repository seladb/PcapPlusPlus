cmake_minimum_required(VERSION 3.14)

add_executable(
  Common++Test
  "main.cpp"
  "Tests/GeneralUtilsTests.cpp"
  "Tests/IPAddressTests.cpp"
  "Tests/LoggerTests.cpp"
  "Tests/LRUListTests.cpp"
  "Tests/MacAddressTests.cpp"
  "Tests/ObjectPoolTests.cpp"
  "Tests/PointerVectorTests.cpp"
  "Tests/SystemUtilsTests.cpp"
  "Tests/TimespecTimevalTests.cpp"
  "Utils/MemoryLeakListener.cpp"
)

target_link_libraries(Common++Test PRIVATE Common++ memplumber gtest gmock)

target_include_directories(Common++Test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_precompile_headers(Common++Test PRIVATE "pch.h")

if(MSVC)
  # This executable requires getopt.h not available on VStudio
  target_link_libraries(Common++Test PRIVATE Getopt-for-Visual-Studio)
endif()

set_property(TARGET Common++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Common++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/Bin")
set_property(TARGET Common++Test PROPERTY RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/Bin")

enable_testing()

add_test(NAME Common++Test COMMAND $<TARGET_FILE:Common++Test> WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/)
