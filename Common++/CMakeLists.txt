cmake_minimum_required(VERSION 3.0)

add_library(CommonPP
	src/IpAddress.cpp
	src/IpUtils.cpp
	src/Logger.cpp
	src/MacAddress.cpp
	src/PcapPlusPlusVersion.cpp
	src/SystemUtils.cpp
	src/TablePrinter.cpp

	header/IpAddress.h
	header/IpUtils.h
	header/Logger.h
	header/LRUList.h
	header/MacAddress.h
	header/PcapPlusPlusVersion.h
	header/PlatformSpecificUtils.h
	header/PointerVector.h
	header/SystemUtils.h
	header/TablePrinter.h
)

target_include_directories(CommonPP
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/header
	PUBLIC ${PCAP_INCLUDE_DIR}
	PUBLIC /usr/include/netinet # NOTE(eteran): not a fan of this...
)

target_link_libraries(CommonPP LINK_PUBLIC

)

target_compile_definitions(CommonPP
	PUBLIC -DLINUX
)

set_property(TARGET CommonPP PROPERTY CXX_STANDARD 14)
set_property(TARGET CommonPP PROPERTY CXX_EXTENSIONS ON)
set_property(TARGET CommonPP PROPERTY ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set_property(TARGET CommonPP PROPERTY OUTPUT_NAME "Common++")
