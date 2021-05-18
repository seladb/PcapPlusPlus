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
)

target_include_directories(CommonPP
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/header
	PUBLIC ${PCAP_INCLUDE_DIR}
)

target_link_libraries(CommonPP PUBLIC
	EndianPortable
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
