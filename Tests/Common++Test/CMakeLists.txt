cmake_minimum_required(VERSION 3.14)

include(FetchContent)

# TODO: This may have issues with brew as it doesn't allow the use of FetchContent.
FetchContent_Declare(googletest GIT_REPOSITORY https://github.com/google/googletest.git GIT_TAG v1.16.0)

if(WIN32)
  # Prevent overriding the parent project's compiler/linker settings.
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
endif()

FetchContent_MakeAvailable(googletest)

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
