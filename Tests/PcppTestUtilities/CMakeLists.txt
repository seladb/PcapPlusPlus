cmake_minimum_required(VERSION 3.12)


add_library(PcppTestUtilities STATIC EXCLUDE_FROM_ALL
    "PacketFactory.cpp"
    "Resources.cpp"
)

target_include_directories(PcppTestUtilities PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/")
target_link_libraries(PcppTestUtilities PUBLIC Packet++)

