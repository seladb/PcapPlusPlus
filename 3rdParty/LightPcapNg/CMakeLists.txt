cmake_minimum_required (VERSION 3.0)
project (light_pcapng C)

add_library (light_pcapng
	LightPcapNg/src/light_io.c
	LightPcapNg/src/light_pcapng.c
	LightPcapNg/src/light_pcapng_cont.c
	LightPcapNg/src/light_platform.c
	LightPcapNg/src/light_manipulate.c
	LightPcapNg/src/light_internal.c
	LightPcapNg/src/light_alloc.c
	LightPcapNg/src/light_advanced.c
	LightPcapNg/src/light_option.c
	LightPcapNg/src/light_pcapng_ext.c
	LightPcapNg/include/light_debug.h
	LightPcapNg/include/light_internal.h
	LightPcapNg/include/light_pcapng_ext.h
	LightPcapNg/include/light_pcapng.h
	LightPcapNg/include/light_platform.h
	LightPcapNg/include/light_special.h
	LightPcapNg/include/light_types.h
	LightPcapNg/include/light_util.h
 )


target_compile_definitions(light_pcapng
	PUBLIC -DUNIVERSAL
)

target_include_directories(light_pcapng PUBLIC
	${PROJECT_SOURCE_DIR}/LightPcapNg/include/
)

add_executable (test_read.test EXCLUDE_FROM_ALL
	LightPcapNg/src/tests/test_read.c
)

target_link_libraries(test_read.test light_pcapng)

add_executable (test_read_write.test EXCLUDE_FROM_ALL
	LightPcapNg/src/tests/test_read_write.c
)

target_link_libraries(test_read_write.test light_pcapng)

add_executable (test_mem.test EXCLUDE_FROM_ALL
    LightPcapNg/src/tests/test_mem.c
    )
target_link_libraries(test_mem.test light_pcapng)

add_executable (test_histogram.test EXCLUDE_FROM_ALL
    LightPcapNg/src/tests/test_histogram.c
    )
target_link_libraries(test_histogram.test light_pcapng)

add_executable (test_subcapture.test EXCLUDE_FROM_ALL
    LightPcapNg/src/tests/test_subcapture.c
    )
target_link_libraries(test_subcapture.test light_pcapng)

add_executable (test_feature.test EXCLUDE_FROM_ALL
    LightPcapNg/src/tests/test_feature.c
    )
target_link_libraries(test_feature.test light_pcapng)

add_executable (test_flow.test EXCLUDE_FROM_ALL
    LightPcapNg/src/tests/test_flow.c
    )
target_link_libraries(test_flow.test light_pcapng)

add_executable (test_feature_advanced.test EXCLUDE_FROM_ALL
    LightPcapNg/src/tests/test_feature_advanced.c
    )
target_link_libraries(test_feature_advanced.test light_pcapng dl)

add_executable (test_read_packets.test EXCLUDE_FROM_ALL
    LightPcapNg/src/tests/test_read_packets.c
    )
target_link_libraries(test_read_packets.test light_pcapng)

add_executable (test_read_write_packets.test EXCLUDE_FROM_ALL
    LightPcapNg/src/tests/test_read_write_packets.c
    )
target_link_libraries(test_read_write_packets.test light_pcapng)
