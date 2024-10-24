# We need 3.12 or later, so that we can set policy CMP0074; see below.
cmake_minimum_required(VERSION 3.12)

set(PCAPPP_VERSION "24.09+")

# MAIN_PROJECT CHECK
set(PCAPPP_MAIN_PROJECT OFF)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(PCAPPP_MAIN_PROJECT ON)
endif()

project(
  PcapPlusPlus
  DESCRIPTION "PcapPlusPlus is a multiplatform C++ library for capturing, parsing and crafting of network packets."
  LANGUAGES CXX
  HOMEPAGE_URL "https://pcapplusplus.github.io/")

# Include our custom CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/")
include(CMakeDependentOption)
include(CMakePackageConfigHelpers)
include(PcapPlusPlusUtils)
include(GNUInstallDirs)
include(TargetArch)

# Setup CMake
pcapp_detect_compiler(PCAPPP_TARGET)

# Get architecture
target_architecture(PCAPP_TARGET_ARCHITECTURE)

# Use Ccache if available
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  message(STATUS "Ccache found!")
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK "${CCACHE_PROGRAM}")
else()
  message(STATUS "Ccache not found!")
endif()

# LINUX is set Only since 3.25 see: https://cmake.org/cmake/help/latest/variable/LINUX.html
if(UNIX
   AND NOT APPLE
   AND NOT CYGWIN
   AND NOT ANDROID)
  set(LINUX True)
endif()

# Declare install folders location
set(PCAPPP_INSTALL_BINDIR ${CMAKE_INSTALL_BINDIR})
set(PCAPPP_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/pcapplusplus)
set(PCAPPP_INSTALL_INCLUDEDIR ${CMAKE_INSTALL_INCLUDEDIR}/pcapplusplus)
set(PCAPPP_INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR})

# Build options enable sanitizers
set(PCAPPP_ALLOWED_SANITIZERS
    ""
    "AddressSanitizer"
    "MemorySanitizer"
    "ThreadSanitizer"
    "UndefinedBehaviorSanitizer")
set(PCAPPP_USE_SANITIZER
    ""
    CACHE STRING "Compile with a sanitizer")
set_property(CACHE PCAPPP_USE_SANITIZER PROPERTY STRINGS ${PCAPPP_ALLOWED_SANITIZERS})

if(NOT
   PCAPPP_USE_SANITIZER
   IN_LIST
   PCAPPP_ALLOWED_SANITIZERS)
  message(FATAL_ERROR "PCAPPP_USE_SANITIZER must be one of ${PCAPPP_ALLOWED_SANITIZERS}")
endif()

if(PCAPPP_USE_SANITIZER)
  add_compile_options("-fno-omit-frame-pointer")
  add_compile_options("-O1")
  if(PCAPPP_USE_SANITIZER STREQUAL "AddressSanitizer")
    add_compile_options("-fsanitize=address")
    add_link_options("-fsanitize=address")
  elseif(PCAPPP_USE_SANITIZER STREQUAL "MemorySanitizer")
    add_compile_options("-fsanitize=memory")
    add_link_options("-fsanitize=memory")
  elseif(PCAPPP_USE_SANITIZER STREQUAL "ThreadSanitizer")
    add_compile_options("-fsanitize=thread")
    add_link_options("-fsanitize=thread")
  elseif(PCAPPP_USE_SANITIZER STREQUAL "UndefinedBehaviorSanitizer")
    add_compile_options("-fsanitize=undefined")
    add_link_options("-fsanitize=undefined")
  endif()
endif()

# Build options (Turn on Examples and Tests if it's the main project)
option(PCAPPP_BUILD_EXAMPLES "Build Examples" ${PCAPPP_MAIN_PROJECT})
cmake_dependent_option(
  PCAPPP_BUILD_TUTORIALS
  "Build Tutorials"
  OFF
  "PCAPPP_BUILD_EXAMPLES"
  OFF)
option(PCAPPP_BUILD_TESTS "Build Tests" ${PCAPPP_MAIN_PROJECT})
option(PCAPPP_BUILD_COVERAGE "Generate Coverage Report" OFF)
option(PCAPPP_BUILD_FUZZERS "Build Fuzzers binaries" OFF)
option(PCAPPP_BUILD_REPRODUCIBLE "Build a reproducible version" OFF)

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)

option(PCAPPP_USE_DPDK "Setup PcapPlusPlus with DPDK. In this case you must also set DPDK_ROOT")
cmake_dependent_option(
  PCAPPP_USE_DPDK_KNI
  "Add KNI Support to Pcap++"
  OFF
  "PCAPPP_USE_DPDK"
  OFF)
option(PCAPPP_USE_PF_RING "Setup PcapPlusPlus with PF_RING. In this case you must also set PF_RING_ROOT")
option(PCAPPP_USE_XDP "Setup PcapPlusPlus with XDP")
option(PCAPPP_INSTALL "Install Pcap++" ${PCAPPP_MAIN_PROJECT})
option(PCAPPP_PACKAGE "Package Pcap++ could require a recent version of CMake" OFF)

# Set C++11
set(CMAKE_CXX_STANDARD 11)
# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)
# Set Position Independent Code for static libraries
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
# Export compile commands for external tools
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Usually on Windows PCAP_ROOT and Packet_ROOT are at the same location
if(WIN32
   AND PCAP_ROOT
   AND NOT Packet_ROOT)
  set(Packet_ROOT ${PCAP_ROOT})
endif()

find_package(PCAP)
if(NOT PCAP_FOUND)
  if(WIN32)
    message(FATAL_ERROR "Please specify Npcap/WinPcap SDK directory with -DPCAP_ROOT=<PCAP_SDK_PATH>")
  else()
    message(FATAL_ERROR "PCAP library not found!")
  endif()
endif()

# Look for Packet
if(WIN32)
  find_package(Packet)
  if(NOT Packet_FOUND)
    message(FATAL_ERROR "Please specify Packet library -DPacket_ROOT=<NPCAP_SDK_PATH>")
  endif()
endif()

# Enable the option if it's available
option(PCAPPP_ENABLE_PCAP_IMMEDIATE_MODE "Enable PCAP immediate Mode (supported on libpcap>=1.5)" OFF)

# Check in case user force it but it's not available
if(PCAPPP_ENABLE_PCAP_IMMEDIATE_MODE)
  if(NOT HAVE_PCAP_IMMEDIATE_MODE)
    message(FATAL_ERROR "PCAP library doesn't have Immediate Mode support!")
  endif()
  add_definitions(-DHAS_PCAP_IMMEDIATE_MODE)
endif()

# Enable the option if it's available
option(PCAPPP_ENABLE_PCAP_SET_DIRECTION
       "Enable set direction for capturing incoming or outgoing packets (supported on libpcap>=0.9.1)" OFF)

# Check in case user force it but it's not available
if(PCAPPP_ENABLE_PCAP_SET_DIRECTION)
  if(NOT HAVE_PCAP_DIRECTION)
    message(FATAL_ERROR "PCAP library doesn't have Direction support!")
  endif()
  add_definitions(-DHAS_SET_DIRECTION_ENABLED)
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
if(MSVC)
  # Other hacks for VStudio
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
  if(NOT CMAKE_USE_PTHREADS_INIT)
    message(FATAL_ERROR "Pthreads not found!")
  endif()
endif()

if(PCAPPP_USE_DPDK)
  find_package(DPDK)
  if(NOT DPDK_FOUND)
    message(FATAL_ERROR "Specify DPDK Library with -DDPDK_ROOT=<DPDK_PATH>")
  endif()
  add_definitions(-DUSE_DPDK)

  # Check in case user force KNI but it's not available
  if(PCAPPP_USE_DPDK_KNI)
    if(NOT HAVE_DPDK_RTE_KNI)
      message(FATAL_ERROR "DPDK library doesn't have KNI support!")
    endif()
    add_definitions(-DUSE_DPDK_KNI)
  endif()

  # Disable deprecated warnings when DPDK enabled since warnings are treated as errors
  add_definitions("-Wno-deprecated-declarations")
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/setup_dpdk.py" "${CMAKE_CURRENT_BINARY_DIR}" COPYONLY)
endif()

# Git Commit and Branch
find_package(Git)
if(Git_FOUND)
  execute_process(
    COMMAND ${GIT_EXECUTABLE} log -1 --format=%h
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE PCAPPP_GIT_COMMIT)
  string(STRIP "${PCAPPP_GIT_COMMIT}" PCAPPP_GIT_COMMIT)
  execute_process(
    COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE PCAPPP_GIT_BRANCH)
  string(STRIP "${PCAPPP_GIT_BRANCH}" PCAPPP_GIT_BRANCH)
  message(STATUS "Building from commit:${PCAPPP_GIT_COMMIT} on branch:${PCAPPP_GIT_BRANCH}")
  add_compile_definitions(GIT_COMMIT="${PCAPPP_GIT_COMMIT}")
  add_compile_definitions(GIT_BRANCH="${PCAPPP_GIT_BRANCH}")
endif()

if(PCAPPP_USE_PF_RING)
  find_package(PF_RING)
  if(NOT PF_RING_FOUND)
    message(FATAL_ERROR "Specify PF_RING Library with -DPF_RING_ROOT=<PF_RING_PATH>")
  endif()
  add_definitions(-DUSE_PF_RING)
endif()

if(PCAPPP_USE_XDP)
  find_package(BPF)
  if(NOT BPF_FOUND)
    message(FATAL_ERROR "libbpf not found!")
  endif()
  add_definitions(-DUSE_XDP)
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE
      "Release"
      CACHE STRING "Choose the type of build." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")
endif()

if(PCAPPP_TARGET_COMPILER_CLANG
   OR PCAPPP_TARGET_COMPILER_GCC
   OR PCAPPP_TARGET_COMPILER_INTEL)
  add_compile_options(-Wall)
endif()

if(PCAPPP_BUILD_REPRODUCIBLE)
  add_definitions(-DPCAPPP_BUILD_REPRODUCIBLE)
  if(APPLE)
    if(NOT $ENV{ZERO_AR_DATE})
      message(FATAL_ERROR "You need to set `export ZERO_AR_DATE=1`")
    endif()
  elseif(MSVC)
    message(FATAL_ERROR "Unsupported with MSVC compiler")
    # Try to build a reproducible static library with MSVC doesn't work but this option should make it work for shared
    # libraries or executables. add_compile_options(/Brepro) add_compile_options(/experimental:deterministic)
    # add_link_options(/Brepro) add_link_options(/experimental:deterministic) add_link_options(/INCREMENTAL:NO)
  else()
    # We should not use __DATE__ nor __TIME__ in case of reproducible build
    add_compile_options(-Wdate-time)
  endif()
endif()

if(PCAPPP_BUILD_FUZZERS)
  add_compile_options(-w)
endif()

# Static linking GCC/Threads for minGW (Windows + GNU)
if(MINGW)
  add_link_options(-static-libgcc -static-libstdc++)
  add_link_options(-static)
endif()

if(PCAPPP_TARGET_COMPILER_MSVC)
  # Disable VS warnings: Unknown pragma (4068), Zero-sized array in struct/union (4200), Possible loss of data (4244),
  # Possible loss of data (4267), Character may not be represented (4819)
  add_definitions("/wd4068 /wd4200 /wd4244 /wd4267 /wd4819")
endif()

if(PCAPPP_BUILD_COVERAGE)
  add_compile_options(--coverage)
  add_link_options(--coverage)
  set(_PCAPPP_FIND_COVERAGE "find_dependency(Coverage)\n")
endif()

add_subdirectory(3rdParty)
add_subdirectory(Packet++)
add_subdirectory(Pcap++)
add_subdirectory(Common++)

if(PCAPPP_BUILD_EXAMPLES)
  set(PCAPPP_BINARY_EXAMPLES_DIR ${CMAKE_BINARY_DIR}/examples_bin)
  add_subdirectory(Examples)
endif()

if(PCAPPP_BUILD_TESTS
   OR PCAPPP_BUILD_FUZZERS
   OR PCAPPP_BUILD_EXAMPLES)
  include(CTest)
  add_subdirectory(Tests)
endif()

if(PCAPPP_INSTALL)
  # Generate PKG-Config for non WIN32 system
  if(NOT WIN32)
    if(APPLE)
      # Add System and CoreFoundation libs on MacOS
      set(PCAPPP_PKGCONFIG_EXTRA_LIBS "-framework SystemConfiguration -framework CoreFoundation")
    endif()
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/PcapPlusPlus.pc.in" "${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlus.pc"
                   @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlus.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
  endif()

  # CMake helpers to compile Pcap++ with CMake
  pcapp_install_cmake_module(PCAP)
  if(WIN32)
    pcapp_install_cmake_module(Packet)
  endif()

  if(PCAPPP_USE_PF_RING)
    pcapp_install_cmake_module(PF_RING)
  endif()

  if(PCAPPP_USE_DPDK)
    pcapp_install_cmake_module(DPDK)
    pcapp_install_cmake_module(NUMA)
  endif()

  if(LIGHT_PCAPNG_ZSTD)
    pcapp_install_cmake_module(ZSTD)
  endif()

  install(
    EXPORT PcapPlusPlusTargets
    DESTINATION ${PCAPPP_INSTALL_CMAKEDIR}
    NAMESPACE PcapPlusPlus::)

  configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PcapPlusPlusConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlusConfig.cmake" INSTALL_DESTINATION "${PCAPPP_INSTALL_CMAKEDIR}")

  write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlusConfigVersion.cmake"
    VERSION ${PCAPPP_VERSION}
    COMPATIBILITY AnyNewerVersion)

  # CMake helpers to compile Pcap++ with CMake
  install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlusConfig.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlusConfigVersion.cmake"
    COMPONENT devel
    DESTINATION "${PCAPPP_INSTALL_CMAKEDIR}")
endif()

if(PCAPPP_PACKAGE)
  if(NOT PCAPPP_INSTALL)
    message(SEND_ERROR "Packaging depends on PCAPP_INSTALL")
  endif()

  set(CPACK_PACKAGE_NAME "pcapplusplus")
  set(CPACK_PACKAGE_VERSION "${PCAPPP_VERSION}")
  set(CPACK_PACKAGE_MAINTAINER "seladb")
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER "${CPACK_PACKAGE_MAINTAINER}")
  set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
      "PcapPlusPlus is a multiplatform C++ library for capturing, parsing and crafting of network packets. It is designed to be efficient, powerful and easy to use."
  )

  # Default output a .tar.gz
  set(CPACK_GENERATOR "TGZ")

  # Remove the tweak for Compiler Version
  string(
    REPLACE "."
            ";"
            VERSION_LIST
            ${CMAKE_CXX_COMPILER_VERSION})
  list(LENGTH VERSION_LIST CMAKE_CXX_COMPILER_VERSION_LENGTH)
  if(${CMAKE_CXX_COMPILER_VERSION_LENGTH} GREATER 3)
    list(POP_BACK VERSION_LIST)
  endif()
  list(
    JOIN
    VERSION_LIST
    "."
    PCAPP_CXX_COMPILER_VERSION)

  set(_PCAPPP_PACKAGE_README_PATH "${CMAKE_SOURCE_DIR}/cmake/package/READMEs")
  set(_PCAPPP_PACKAGE_README_OUTFILE "${CMAKE_BINARY_DIR}/README.release.md")

  if(ANDROID)
    set(CPACK_SYSTEM_NAME "android-${ANDROID_ABI}-${ANDROID_PLATFORM}")
    set(_PCAPPP_PACKAGE_README_CUSTOM_PATH "${_PCAPPP_PACKAGE_README_PATH}/README.release.android")
  elseif(APPLE)
    # set(CPACK_GENERATOR ${CPACK_GENERATOR};productbuild)
    set(CPACK_SYSTEM_NAME "macos-${CMAKE_OSX_ARCHITECTURES}-${PCAPPP_TARGET_COMPILER}-${PCAPP_CXX_COMPILER_VERSION}")
    set(_PCAPPP_PACKAGE_README_CUSTOM_PATH "${_PCAPPP_PACKAGE_README_PATH}/README.release.macos")
  elseif(LINUX)
    # Easier for Packing but requires CMake 3.22
    cmake_minimum_required(VERSION 3.22)
    cmake_host_system_information(RESULT DISTRO_ID QUERY DISTRIB_ID)
    cmake_host_system_information(RESULT DISTRO_VERSION_ID QUERY DISTRIB_VERSION_ID)
    set(_PCAPPP_PACKAGE_README_CUSTOM_PATH "${_PCAPPP_PACKAGE_README_PATH}/README.release.linux")
    if("${DISTRO_ID}" STREQUAL "ubuntu")
      # set(CPACK_GENERATOR ${CPACK_GENERATOR};DEB)
    elseif("${DISTRO_ID}" STREQUAL "centos" OR "${DISTRO_ID}" STREQUAL "rhel")
      # set(CPACK_GENERATOR ${CPACK_GENERATOR};RPM)
    elseif("${DISTRO_ID}" STREQUAL "freebsd")
      set(_PCAPPP_PACKAGE_README_CUSTOM_PATH "${_PCAPPP_PACKAGE_README_PATH}/README.release.freebsd")
    endif()
    set(CPACK_SYSTEM_NAME
        "${DISTRO_ID}-${DISTRO_VERSION_ID}-${PCAPPP_TARGET_COMPILER}-${PCAPP_CXX_COMPILER_VERSION}-${CMAKE_SYSTEM_PROCESSOR}"
    )
  elseif(MINGW)
    # Check MinGW before WIN32 as MinGW defines both
    set(CPACK_GENERATOR "ZIP")
    set(CPACK_SYSTEM_NAME
        "windows-mingw64-${PCAPP_TARGET_ARCHITECTURE}-${PCAPPP_TARGET_COMPILER}-${PCAPP_CXX_COMPILER_VERSION}")
    set(_PCAPPP_PACKAGE_README_CUSTOM_PATH "${_PCAPPP_PACKAGE_README_PATH}/README.release.win.mingw")
  elseif(WIN32)
    set(CPACK_GENERATOR "ZIP")
    string(TOLOWER ${CMAKE_BUILD_TYPE} BUILD_TYPE_LOWER)
    string(TOLOWER ${CMAKE_VS_PLATFORM_NAME} PLATFORM_LOWER)
    set(CPACK_SYSTEM_NAME "windows-vs${MSVC_YEAR}-${PLATFORM_LOWER}-${BUILD_TYPE_LOWER}")
    set(_PCAPPP_PACKAGE_README_CUSTOM_PATH "${_PCAPPP_PACKAGE_README_PATH}/README.release.win.vs")
  endif()

  # Generate output README
  file(READ "${_PCAPPP_PACKAGE_README_PATH}/README.release.header" _CONTENT)
  file(APPEND ${_PCAPPP_PACKAGE_README_OUTFILE} "${_CONTENT}")

  if(_PCAPPP_PACKAGE_README_CUSTOM_PATH)
    file(READ ${_PCAPPP_PACKAGE_README_CUSTOM_PATH} _CONTENT)
    file(APPEND ${_PCAPPP_PACKAGE_README_OUTFILE} "${_CONTENT}\n")
  endif()

  file(READ "${_PCAPPP_PACKAGE_README_PATH}/release_notes.txt" _CONTENT)
  file(APPEND ${_PCAPPP_PACKAGE_README_OUTFILE} "${_CONTENT}")

  # As we only generate .TGZ for the moment keep it to False
  if(FALSE)
    # Apple productbuild cannot handle .md or file without extension Use textutil to convert them to HTML
    find_program(CONVERTER textutil)
    if(NOT CONVERTER)
      message(FATAL_ERROR "textutil executable not found")
    endif()
    execute_process(COMMAND ${CONVERTER} -convert html "${CMAKE_SOURCE_DIR}/LICENSE" -output
                            "${CMAKE_BINARY_DIR}/LICENSE.html")
    execute_process(COMMAND ${CONVERTER} -convert html "${_PCAPPP_PACKAGE_README_OUTFILE}" -output
                            "${CMAKE_BINARY_DIR}/README.html")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_BINARY_DIR}/LICENSE.html")
    set(CPACK_RESOURCE_FILE_README "${CMAKE_BINARY_DIR}/README.html")
  else()
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
    set(CPACK_RESOURCE_FILE_README "${_PCAPPP_PACKAGE_README_OUTFILE}")
  endif()

  # used in CPackAdditionalInstall.cmake
  set(CPACK_ADDITIONAL_INSTALL_RESOURCES "${CPACK_RESOURCE_FILE_LICENSE}" "${CPACK_RESOURCE_FILE_README}")
  set(CPACK_ADDITIONAL_EXAMPLE_APP
      "${CMAKE_SOURCE_DIR}/Examples/ExampleApp/1_packet.pcap"
      "${CMAKE_SOURCE_DIR}/Examples/ExampleApp/CMakeLists.txt"
      "${CMAKE_SOURCE_DIR}/Examples/ExampleApp/main.cpp"
      "${CMAKE_SOURCE_DIR}/Examples/ExampleApp/README.md")
  set(CPACK_INSTALL_SCRIPT "${CMAKE_SOURCE_DIR}/cmake/CPackAdditionalInstall.cmake")

  include(CPack)
endif()

# uninstall target
if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/PcapPlusPlusUninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlusUninstall.cmake"
    IMMEDIATE
    @ONLY)

  add_custom_target(uninstall COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlusUninstall.cmake")
endif()
