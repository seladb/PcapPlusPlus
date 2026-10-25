add_library(PcppTestFramework INTERFACE)

if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.19)
  target_sources(PcppTestFramework PRIVATE "PcppTestFramework.h" "PcppTestFrameworkCommon.h" "PcppTestFrameworkRun.h")
endif()

target_include_directories(PcppTestFramework INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/)
