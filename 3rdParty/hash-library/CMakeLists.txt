add_library (hash-library
	./md5.cpp
)

target_include_directories(hash-library PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/
)

target_link_libraries(hash-library PUBLIC
	EndianPortable
)
