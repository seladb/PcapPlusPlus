# ~~~
# - Try to find libpcap include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(PCAP)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
# Imported Targets:
#  PCAP::PCAP                The libpcap library, if found
#
# Variables defined by this module:
#
#  PCAP_FOUND                    System has libpcap, include and library dirs found
#  PCAP_INCLUDE_DIR              The libpcap include directories.
#  PCAP_LIBRARY                  The libpcap library (possibly includes a thread
#                                library e.g. required by pf_ring's libpcap)
#  HAVE_PCAP_IMMEDIATE_MODE      If the version of libpcap found supports immediate mode
#  HAVE_PCAP_TIMESTAMP_TYPES     If the version of libpcap found support for setting timestamp types
#  HAVE_PCAP_TIMESTAMP_PRECISION If the version of libpcap found support for setting timestamp precision
#
# Hints and Backward Compatibility
# ================================
#
# To tell this module where to look, a user may set the environment variable
# PCAP_ROOT to point cmake to the *root* of a directory with include and lib
# subdirectories for packet.dll (e.g WpdPack or npcap-sdk). Alternatively,
# PCAP_ROOT may also be set from cmake command line or GUI (e.g cmake
# -DPCAP_ROOT=C:\path\to\packet [...])
# ~~~

find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h pcap.h PATH_SUFFIXES include Include)

# The 64-bit Wpcap.lib is located under /x64
if(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 8)
  #
  # For the WinPcap and Npcap SDKs, the Lib subdirectory of the top-level directory contains 32-bit libraries. The
  # 64-bit libraries are in the Lib/x64 directory.
  #
  # The only way to *FORCE* CMake to look in the Lib/x64 directory without searching in the Lib directory first appears
  # to be to set CMAKE_LIBRARY_ARCHITECTURE to "x64".
  #
  set(CMAKE_LIBRARY_ARCHITECTURE "x64")
endif()

find_library(PCAP_LIBRARY NAMES pcap wpcap)

# If Pcap is not found as this level no need to continue
if(NOT PCAP_LIBRARY OR NOT PCAP_INCLUDE_DIR)
  return()
endif()

include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY})
check_cxx_source_compiles("int main() { return 0; }" PCAP_LINKS_SOLO)
set(CMAKE_REQUIRED_LIBRARIES)

# check if linking against libpcap also needs to link against a thread library
if(NOT PCAP_LINKS_SOLO)
  find_package(Threads)
  if(THREADS_FOUND)
    set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
    check_cxx_source_compiles("int main() { return 0; }" PCAP_NEEDS_THREADS)
    set(CMAKE_REQUIRED_LIBRARIES)
  endif(THREADS_FOUND)
  if(THREADS_FOUND AND PCAP_NEEDS_THREADS)
    set(_tmp ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
    list(REMOVE_DUPLICATES _tmp)
    set(PCAP_LIBRARY ${_tmp} CACHE STRING "Libraries needed to link against libpcap" FORCE)
  else(THREADS_FOUND AND PCAP_NEEDS_THREADS)
    message(FATAL_ERROR "Couldn't determine how to link against libpcap")
  endif(THREADS_FOUND AND PCAP_NEEDS_THREADS)
endif(NOT PCAP_LINKS_SOLO)

include(CheckFunctionExists)
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY})
check_function_exists(pcap_set_immediate_mode HAVE_PCAP_IMMEDIATE_MODE)
check_function_exists(pcap_list_tstamp_types HAVE_PCAP_TIMESTAMP_TYPES)
check_function_exists(pcap_set_tstamp_precision HAVE_PCAP_TIMESTAMP_PRECISION)
set(CMAKE_REQUIRED_LIBRARIES)

# Check libPCAP version
if(NOT CMAKE_CROSSCOMPILING)
  # Simple C code to extract the libpcap version
  set(
    PCAP_VERSION_CODE
    "
  #include <cstdio>
  #include <cstring>
  #include <pcap/pcap.h>

  int main() {
    const char* version = pcap_lib_version();
    const char* prefix = \"libpcap version \";
    if (strncmp(version, prefix, strlen(prefix)) == 0) {
        version += strlen(prefix);
    }
    printf(\"%s\", version);
    return 0;
  }
  "
  )

  # Write the code to a temporary file
  set(detect_pcap_version_file "${PROJECT_BINARY_DIR}/detect_pcap_version.cpp")
  file(WRITE "${detect_pcap_version_file}" "${PCAP_VERSION_CODE}")

  # Try to compile and run the program
  try_run(
    RUN_RESULT_VAR
    COMPILE_RESULT_VAR
    "${CMAKE_BINARY_DIR}"
    "${detect_pcap_version_file}"
    CMAKE_FLAGS "-DINCLUDE_DIRECTORIES=${PCAP_INCLUDE_DIR}"
    LINK_LIBRARIES ${PCAP_LIBRARY}
    RUN_OUTPUT_VARIABLE PCAP_VERSION_OUTPUT
  )

  # If successful, parse the output to get the version string
  if(COMPILE_RESULT_VAR AND RUN_RESULT_VAR EQUAL 0)
    set(PCAP_VERSION ${PCAP_VERSION_OUTPUT})
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP REQUIRED_VARS PCAP_LIBRARY PCAP_INCLUDE_DIR VERSION_VAR PCAP_VERSION)

# create IMPORTED target for libpcap dependency
if(NOT TARGET PCAP::PCAP)
  add_library(PCAP::PCAP IMPORTED SHARED)
  set_target_properties(
    PCAP::PCAP
    PROPERTIES
      IMPORTED_LOCATION ${PCAP_LIBRARY}
      IMPORTED_IMPLIB ${PCAP_LIBRARY}
      INTERFACE_INCLUDE_DIRECTORIES ${PCAP_INCLUDE_DIR}
  )
endif()

mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY)
