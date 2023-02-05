add_library(OUIDataset INTERFACE)

target_include_directories(OUIDataset INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_sources(OUIDataset INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include/PCPP_OUIDataset.hpp)
