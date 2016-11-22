cmake_minimum_required (VERSION 2.6)
project (light_pcapng C)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}/include/ -Wall -O2 -fPIC -DUNIVERSAL -g")

add_library (light_pcapng SHARED
    src/light_io.c
    src/light_pcapng.c
    src/light_pcapng_cont.c
    src/light_platform.c
    src/light_manipulate.c
    src/light_internal.c
    src/light_alloc.c
    src/light_advanced.c
    src/light_option.c
    src/light_pcapng_ext.c
    )

add_library (light_pcapng_static STATIC
    src/light_io.c
    src/light_pcapng.c
    src/light_pcapng_cont.c
    src/light_platform.c
    src/light_manipulate.c
    src/light_internal.c
    src/light_alloc.c
    src/light_advanced.c
    src/light_option.c
    src/light_pcapng_ext.c
    )

add_executable (test_read.test
    src/tests/test_read.c
    )
target_link_libraries(test_read.test light_pcapng_static)

add_executable (test_read_write.test
    src/tests/test_read_write.c
    )
target_link_libraries(test_read_write.test light_pcapng_static)

add_executable (test_mem.test
    src/tests/test_mem.c
    )
target_link_libraries(test_mem.test light_pcapng_static)

add_executable (test_histogram.test
    src/tests/test_histogram.c
    )
target_link_libraries(test_histogram.test light_pcapng_static)

add_executable (test_subcapture.test
    src/tests/test_subcapture.c
    )
target_link_libraries(test_subcapture.test light_pcapng_static)

add_executable (test_feature.test
    src/tests/test_feature.c
    )
target_link_libraries(test_feature.test light_pcapng_static)

add_executable (test_flow.test
    src/tests/test_flow.c
    )
target_link_libraries(test_flow.test light_pcapng_static)

add_executable (test_feature_advanced.test
    src/tests/test_feature_advanced.c
    )
target_link_libraries(test_feature_advanced.test light_pcapng_static dl)

add_executable (test_read_packets.test
    src/tests/test_read_packets.c
    )
target_link_libraries(test_read_packets.test light_pcapng_static)

add_executable (test_read_write_packets.test
    src/tests/test_read_write_packets.c
    )
target_link_libraries(test_read_write_packets.test light_pcapng_static)
