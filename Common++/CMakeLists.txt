cmake_minimum_required(VERSION 3.0)

include(DetectOS)

add_library(CommonPP
	src/GeneralUtils.cpp
	src/IpAddress.cpp
	src/IpUtils.cpp
	src/Logger.cpp
	src/MacAddress.cpp
	src/PcapPlusPlusVersion.cpp
	src/SystemUtils.cpp
	src/TablePrinter.cpp

	header/GeneralUtils.h
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
	
	# NOTE(eteran): So, unix convention is to use #include <netinet/in.h>, not #include <in.h>
	# this allows us to avoid name collisions in include files by placing headers in a filesystem
	# namespace of sorts. I would prefer to eliminate this as anyone who uses PcapPlusPlus must also
	# add this to their build path (done by cmake because this is a public include path), but for now
	# i'll maintain the existing behavior
	PUBLIC /usr/include/netinet
)

target_link_libraries(CommonPP LINK_PUBLIC

)

if(TARGET_PLATFORM_LINUX)
	target_compile_definitions(CommonPP
		PUBLIC -DLINUX
	)
elseif(TARGET_PLATFORM_MACOS)
	target_compile_definitions(CommonPP
		PUBLIC -DMAC_OS_X
	)
elseif(TARGET_PLATFORM_WINDOWS)
	target_compile_definitions(CommonPP
	)
endif()

set_property(TARGET CommonPP PROPERTY CXX_STANDARD 11)
set_property(TARGET CommonPP PROPERTY CXX_EXTENSIONS OFF)
set_property(TARGET CommonPP PROPERTY ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set_property(TARGET CommonPP PROPERTY OUTPUT_NAME "Common++")
