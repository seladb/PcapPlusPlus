add_library(PcppTestFramework INTERFACE)

target_sources(PcppTestFramework PRIVATE
	"PcppTestFramework.h"
	"PcppTestFrameworkCommon.h"
	"PcppTestFrameworkRun.h"
)

target_include_directories(PcppTestFramework INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/)
