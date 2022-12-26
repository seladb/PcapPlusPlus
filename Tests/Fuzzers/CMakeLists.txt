cmake_minimum_required(VERSION 3.12)

project(PcapPlusPlusFuzzer)

set(CMAKE_PROJECT_HOMEPAGE_URL "https://pcapplusplus.github.io/")

if(TARGET Pcap++)
  # Are we building from the PcapPlusPlus project ??
  message(STATUS "Building Fuzzer from PcapPlusPlus project")
  # Alias the project to make it compatible with imported package
  add_library(PcapPlusPlus::Pcap++ ALIAS Pcap++)
else()
  find_package(PcapPlusPlus CONFIG REQUIRED)
  message(STATUS "Using Pcap++ ${PcapPlusPlus_VERSION}")
  message(STATUS "Include dir: ${PcapPlusPlus_INCLUDE_DIR}")
endif()

# Set C++11
set(CMAKE_CXX_STANDARD 11)
# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)

add_executable(Fuzzer FuzzTarget.cpp)

target_link_libraries(Fuzzer PUBLIC PcapPlusPlus::Pcap++)

# Compile and link with Fuzzer + ASAN
target_compile_options(Fuzzer PRIVATE -g -fsanitize=fuzzer,address)
target_link_options(
  Fuzzer
  PRIVATE
  -g
  -fsanitize=fuzzer,address)
