cmake_minimum_required(VERSION 3.0)

# Build options
option(TEST_VERBOSE "Run tests in verbose mode" OFF)
option(MEM_CHECK_VERBOSE "Run mem check in verbose mode" OFF)

if(TEST_VERBOSE)
  add_definitions(-DTEST_VERBOSE)
endif()

if(MEM_CHECK_VERBOSE)
  add_definitions(-DMEM_CHECK_VERBOSE)
endif()

add_subdirectory(test-lib)

add_executable(basic-tests test-macros.h basic-tests.cpp)

add_executable(static-var-tests test-macros.h static-var-tests.cpp)

add_executable(inner-lib-tests test-macros.h inner-lib-tests.cpp)

add_executable(load-tests test-macros.h load-tests.cpp)

target_link_libraries(basic-tests PUBLIC memplumber)

target_link_libraries(static-var-tests PUBLIC memplumber)

target_link_libraries(inner-lib-tests PUBLIC memplumber TestLib)

target_link_libraries(load-tests PUBLIC memplumber TestLib)

add_test(NAME basic-tests COMMAND $<TARGET_FILE:basic-tests>)

add_test(NAME static-var-tests COMMAND $<TARGET_FILE:static-var-tests>)

add_test(NAME inner-lib-tests COMMAND $<TARGET_FILE:inner-lib-tests>)

add_test(NAME load-tests COMMAND $<TARGET_FILE:load-tests>)
