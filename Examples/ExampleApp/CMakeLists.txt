cmake_minimum_required(VERSION 3.12)
project(example-app)

# Set C++11
set(CMAKE_CXX_STANDARD 11)
# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)

find_package(PcapPlusPlus REQUIRED)

add_executable("${PROJECT_NAME}" main.cpp)
# We want to have the binary compiled in the same folder as the .cpp to be near the PCAP file
set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
# Link with Pcap++ libraries
target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)
