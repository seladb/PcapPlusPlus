cmake_minimum_required(VERSION 3.12)

project(hash-library LANGUAGES CXX)

add_library(hash-library OBJECT ./md5.cpp)

target_include_directories(hash-library PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/)
target_link_libraries(hash-library PRIVATE EndianPortable)

if(BUILD_SHARED_LIBS)
  set_property(TARGET hash-library PROPERTY POSITION_INDEPENDENT_CODE ON)
endif()
