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
	LightPcapNg/src/light_compression.c
	LightPcapNg/src/light_zstd_compression.c
	LightPcapNg/src/light_null_compression.c
)

target_compile_definitions(light_pcapng
	PUBLIC -DUNIVERSAL
)

target_include_directories(light_pcapng PUBLIC
	${PROJECT_SOURCE_DIR}/LightPcapNg/include/
)
