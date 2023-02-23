cmake_minimum_required(VERSION 3.12)
project(Tutorial-DpdkL2Fwd)

# Set C++11
set(CMAKE_CXX_STANDARD 11)
# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)

add_executable("${PROJECT_NAME}" main.cpp WorkerThread.cpp)

if(NOT TARGET PcapPlusPlus::Pcap++)
  message("Compiling Tutorial out of project")
  find_package(PcapPlusPlus REQUIRED)
  # We want to have the binary compiled in the same folder as the .cpp to be near the pcap file
  set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
else()
  set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PCAPPP_BINARY_TUTORIAL_DIR}")
endif()

target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)
