cmake_minimum_required(VERSION 3.0)

add_executable(basic-example basic-example.cpp)

target_link_libraries(basic-example PUBLIC memplumber)

add_executable(static-example static-example.cpp)

target_link_libraries(static-example PUBLIC memplumber)

add_executable(dump-to-file-example dump-to-file-example.cpp)

target_link_libraries(dump-to-file-example PUBLIC memplumber)
