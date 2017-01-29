cmake_minimum_required (VERSION 2.8.11)
project (dirent)

enable_language (C)

# Only use the dirent file on windows systems
if (WIN32)
    include_directories (${CMAKE_SOURCE_DIR}/include)
    install (FILES include/dirent.h DESTINATION include)
else()
    cmake_policy(SET CMP0037 OLD) # Supress warnings about fake install
    add_custom_target(install) # Fake install target
endif()

# Build example programs
add_executable (find examples/find.c)
add_executable (ls examples/ls.c)
add_executable (locate examples/locate.c)
add_executable (updatedb examples/updatedb.c)

# Build test programs
include (CTest)
add_custom_target (check COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -C ${CMAKE_CFG_INTDIR})
function (add_test_executable TEST_NAME)
    add_executable (${TEST_NAME} EXCLUDE_FROM_ALL ${ARGN})
    add_test (NAME ${TEST_NAME} WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} COMMAND $<TARGET_FILE:${TEST_NAME}>)
    add_dependencies (check ${TEST_NAME})
endfunction (add_test_executable)

add_test_executable (t-compile tests/t-compile.c)
add_test_executable (t-dirent tests/t-dirent.c)

