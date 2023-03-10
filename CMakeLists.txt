# We need 3.12 or later, so that we can set policy CMP0074; see below.
cmake_minimum_required(VERSION 3.12)

set(PCAPPP_VERSION "22.11+")

# MAIN_PROJECT CHECK
set(PCAPPP_MAIN_PROJECT OFF)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(PCAPPP_MAIN_PROJECT ON)
endif()

project(
  PcapPlusPlus
  DESCRIPTION "PcapPlusPlus is a multiplatform C++ library for capturing, parsing and crafting of network packets."
  HOMEPAGE_URL "https://pcapplusplus.github.io/")

# Include our custom CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/")
include(CMakeDependentOption)
include(CMakePackageConfigHelpers)
include(DetectCompiler)
include(GNUInstallDirs)
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
cmake_dependent_option(
  PCAPPP_BUILD_FUZZERS
  "Build Fuzzers binaries"
  OFF
  "PCAPPP_BUILD_TESTS"
  OFF)

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)

option(PCAPPP_USE_DPDK "Setup PcapPlusPlus with DPDK. In this case you must also set DPDK_ROOT")
option(PCAPPP_USE_PF_RING "Setup PcapPlusPlus with PF_RING. In this case you must also set PF_RING_ROOT")
option(PCAPPP_INSTALL "Install Pcap++" ${PCAPPP_MAIN_PROJECT})

# Set C++11
set(CMAKE_CXX_STANDARD 11)
# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)

# Usually on Windows PCAP_ROOT and Packet_ROOT are at the same location
if(WIN32)
  if(NOT PCAP_ROOT)
    message(FATAL_ERROR "Please specify Npcap/WinPcap SDK directory with -DPCAP_ROOT=<PCAP_SDK_PATH>")
  endif()
  if(NOT Packet_ROOT)
    set(Packet_ROOT ${PCAP_ROOT})
  endif()
endif()

# Do we need Packet Packages on Windows ?
if(WIN32)
  find_package(Packet)
  if(NOT Packet_FOUND)
    message(FATAL_ERROR "Please specify Packet library -DPacket_ROOT=<NPCAP_SDK_PATH>")
  endif()
endif()

find_package(PCAP)
if(NOT PCAP_FOUND)
  if(WIN32)
    message(FATAL_ERROR "Please specify Npcap/WinPcap SDK directory with -DPCAP_ROOT=<PCAP_SDK_PATH>")
  else()
    message(FATAL_ERROR "PCAP library not found!")
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

option(PCAPPP_ENABLE_CLANG_TIDY "Run Clang-Tidy static analysis during build" OFF)

if(PCAPPP_ENABLE_CLANG_TIDY)
  find_program(CLANG_TIDY_EXE NAMES "clang-tidy" REQUIRED)
  set(CLANG_TIDY_COMMAND "${CLANG_TIDY_EXE}" "--fix"
                         "--checks=modernize-use-nullptr,modernize-use-override,performance-unnecessary-value-param")
  set(CMAKE_CXX_CLANG_TIDY ${CLANG_TIDY_COMMAND})
  # Force to recompile all files with clang-tidy by setting a dummy definition variable
  add_definitions(-DUSE_CLANG_TIDY)
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
  # Disable deprecated warnings when DPDK enabled since warnings are treated as errors
  add_definitions("-Wno-deprecated-declarations")
  set(_PCAPPP_FIND_DPDK "find_dependency(DPDK)\n")
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/setup_dpdk.py" "${CMAKE_CURRENT_BINARY_DIR}" COPYONLY)
endif()

# Git Commit and Branch
add_compile_definitions(GIT_COMMIT="${GIT_HASH}")
add_compile_definitions(GIT_BRANCH="${GIT_BRANCH}")

if(PCAPPP_USE_PF_RING)
  find_package(PF_RING)
  if(NOT PF_RING_FOUND)
    message(FATAL_ERROR "Packet library -DPF_RING_ROOT=<PF_RING_PATH>")
  endif()
  add_definitions(-DUSE_PF_RING)
  set(_PCAPPP_FIND_PF_RING "find_dependency(PF_RING)\n")
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

# Disabled Android for now because ToyVPN build fails with coverage flags
if(PCAPPP_BUILD_COVERAGE AND NOT ANDROID)
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

if(PCAPPP_BUILD_TESTS)
  include(CTest)
  add_subdirectory(Tests)
endif()

if(PCAPPP_INSTALL)
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER "seladb")
  set(CPACK_PACKAGE_FILE_NAME PcapPlusPlus-${PCAPPP_VERSION})

  include(CPack)

  # Generate PKG-Config
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/PcapPlusPlus.pc.in" "${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlus.pc"
                 @ONLY)
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlus.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

  # CMake helpers to compile Pcap++ with CMake
  if(LIGHT_PCAPNG_ZSTD)
    set(_PCAPPP_FIND_ZSTD "if(NOT ZSTD_FOUND)\n  find_dependency(ZSTD)\nendif()")
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
    DIRECTORY "${PROJECT_SOURCE_DIR}/cmake/modules"
    COMPONENT devel
    DESTINATION "${PCAPPP_INSTALL_CMAKEDIR}")
  install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlusConfig.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlusConfigVersion.cmake"
          "${CMAKE_CURRENT_SOURCE_DIR}/3rdParty/LightPcapNg/LightPcapNg/cmake/FindZSTD.cmake"
    COMPONENT devel
    DESTINATION "${PCAPPP_INSTALL_CMAKEDIR}")
endif()
