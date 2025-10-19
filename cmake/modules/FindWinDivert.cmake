# FindWinDivert.cmake
#
# Module to locate the WinDivert library, header, and driver files.
#
# This module defines the following variables:
#
#   WinDivert_FOUND           - TRUE if both the library and header were found
#   WinDivert_INCLUDE_DIR     - Directory containing windivert.h
#   WinDivert_INCLUDE_DIRS    - Same as above (for compatibility with other modules)
#   WinDivert_LIBRARY         - Path to WinDivert.lib
#   WinDivert_LIBRARIES       - Same as above (for compatibility with target_link_libraries)
#   WinDivert_SYS_FILE        - (Optional) Path to the WinDivertXX.sys driver file
#   WinDivert_DLL_FILE        - (Optional) Path to WinDivert.dll (for dynamic linking or redistribution)
#
# You can provide a hint to the search location using either:
#   - The CMake variable WINDIVERT_ROOT
#   - The environment variable WINDIVERT_ROOT
#
# Expected directory structure:
#
#   WinDivert/
#   ├── include/
#   │   └── windivert.h
#   ├── x64/
#   │   ├── WinDivert.lib
#   │   ├── WinDivert.dll
#   │   └── WinDivert64.sys
#   └── x86/
#       ├── WinDivert.lib
#       ├── WinDivert.dll
#       └── WinDivert32.sys

if(NOT WIN32)
    if(NOT WinDivert_FIND_QUIETLY)
        message(FATAL_ERROR "WinDivert is only available on Windows")
    endif()
    return()
endif()

# Detect 64-bit vs 32-bit
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_WinDivert_ARCH_DIR "x64")
    set(_WinDivert_SYS_NAME "WinDivert64.sys")
else()
    set(_WinDivert_ARCH_DIR "x86")
    set(_WinDivert_SYS_NAME "WinDivert32.sys")
endif()

# Normalize user-provided root path
if(DEFINED WINDIVERT_ROOT)
    file(TO_CMAKE_PATH "${WINDIVERT_ROOT}" _WinDivert_ROOT_HINT)
elseif(DEFINED ENV{WINDIVERT_ROOT})
    file(TO_CMAKE_PATH "$ENV{WINDIVERT_ROOT}" _WinDivert_ROOT_HINT)
else()
    set(_WinDivert_ROOT_HINT "")
endif()

if(NOT WinDivert_FIND_QUIETLY)
    message(STATUS "WinDivert root hint: ${_WinDivert_ROOT_HINT}")
    message(STATUS "Looking in arch dir: ${_WinDivert_ARCH_DIR}")
endif()

# Look for header
find_path(WinDivert_INCLUDE_DIR
        NAMES windivert.h
        PATHS
        "${_WinDivert_ROOT_HINT}"
        "C:/Program Files/WinDivert"
        "C:/WinDivert"
        PATH_SUFFIXES include
)

# Look for library
find_library(WinDivert_LIBRARY
        NAMES WinDivert
        PATHS
        "${_WinDivert_ROOT_HINT}"
        "C:/Program Files/WinDivert"
        "C:/WinDivert"
        PATH_SUFFIXES ${_WinDivert_ARCH_DIR}
)

# Look for .sys file (optional)
find_file(WinDivert_SYS
        NAMES ${_WinDivert_SYS_NAME}
        PATHS
        "${_WinDivert_ROOT_HINT}"
        "C:/Program Files/WinDivert"
        "C:/WinDivert"
        PATH_SUFFIXES ${_WinDivert_ARCH_DIR}
)

# Look for .dll file (optional)
find_file(WinDivert_DLL
        NAMES WinDivert.dll
        PATHS
        "${_WinDivert_ROOT_HINT}"
        "C:/Program Files/WinDivert"
        "C:/WinDivert"
        PATH_SUFFIXES ${_WinDivert_ARCH_DIR}
)

# Handle REQUIRED + FOUND logic
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WinDivert
        REQUIRED_VARS WinDivert_INCLUDE_DIR WinDivert_LIBRARY
)

# Print results if not quiet
if(NOT WinDivert_FIND_QUIETLY)
    message(STATUS "WinDivert_INCLUDE_DIR: ${WinDivert_INCLUDE_DIR}")
    message(STATUS "WinDivert_LIBRARY: ${WinDivert_LIBRARY}")
    message(STATUS "WinDivert_SYS: ${WinDivert_SYS}")
    message(STATUS "WinDivert_DLL: ${WinDivert_DLL}")
endif()

# Compatibility variables (set AFTER discovery)
set(WinDivert_INCLUDE_DIRS ${WinDivert_INCLUDE_DIR})
set(WinDivert_LIBRARIES ${WinDivert_LIBRARY})
set(WinDivert_SYS_FILE ${WinDivert_SYS})
set(WinDivert_DLL_FILE ${WinDivert_DLL})

# Create imported target
if(WinDivert_FOUND AND NOT TARGET WinDivert::WinDivert)
    add_library(WinDivert::WinDivert STATIC IMPORTED)
    set_target_properties(WinDivert::WinDivert PROPERTIES
            IMPORTED_LOCATION "${WinDivert_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${WinDivert_INCLUDE_DIR}"
    )
endif()
