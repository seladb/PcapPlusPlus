# - Try to find MacOS libraries
#
# Usage of this module as follows:
#
#     find_package(MACOS)
#
# Variables defined by this module:
#
#  MACOS_FOUND                            System has MACOS library dirs found
#  MACOS_CORE_FOUNDATION_LIBRARY          MacOS CoreFoundation library
#  MACOS_SYSTEM_CONFIGURATION_LIBRARY     MacOS SystemConfiguration library

find_library(MACOS_CORE_FOUNDATION_LIBRARY CoreFoundation)
find_library(MACOS_SYSTEM_CONFIGURATION_LIBRARY SystemConfiguration)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MACOS
    REQUIRED_VARS 
		MACOS_CORE_FOUNDATION_LIBRARY 
		MACOS_SYSTEM_CONFIGURATION_LIBRARY 
    FAIL_MESSAGE 
		"MacOS required libraries CoreFoundation and SystemConfiguration not found!"
)