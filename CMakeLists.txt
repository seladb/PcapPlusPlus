# We need 3.12 or later, so that we can set policy CMP0074; see below.
cmake_minimum_required(VERSION 3.12)

# We want find_path() and find_library() to honor {packagename}_ROOT
if(POLICY CMP0074)
  cmake_policy(SET CMP0074 NEW)
endif()

if(POLICY CMP0111)
  cmake_policy(SET CMP0111 NEW)
endif()

# MAIN_PROJECT CHECK
set(MAIN_PROJECT OFF)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(MAIN_PROJECT ON)
endif()

# Include git module required for version
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/")
include(VersionFromGit)

# Get the git version
version_from_git(LOG ON TIMESTAMP "%Y%m%d%H%M%S")

project(
  PcapPlusPlus
  DESCRIPTION
    "PcapPlusPlus is a multiplatform C++ library for capturing, parsing and crafting of network packets."
  VERSION ${VERSION})
set(CMAKE_PROJECT_HOMEPAGE_URL "https://pcapplusplus.github.io/")

# Include the other modules
include(CMakePackageConfigHelpers)
include(DetectCompiler)
include(DetectOS)
include(GNUInstallDirs)

# Build options
option(PCAPPP_BUILD_EXAMPLES "Build Examples")
option(PCAPPP_BUILD_TESTS "Build Tests" ${MAIN_PROJECT})
option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)

option(PCAPPP_USE_DPDK
       "Setup PcapPlusPlus with DPDK. In this case you must also set DPDK_HOME")
option(
  PCAPPP_USE_PF_RING
  "Setup PcapPlusPlus with PF_RING. In this case you must also set PF_RING_HOME"
)
option(PCAPPP_INSTALL "Install Pcap++" ${MAIN_PROJECT})

# Set C++11
set(CMAKE_CXX_STANDARD 11)
# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)

# Do we need Packet Packages on Windows ?
if(TARGET_PLATFORM_WINDOWS)
  find_package(Packet)
  if(NOT Packet_FOUND)
    message(FATAL_ERROR "Packet library -DPacket_ROOT=<NPCAP_SDK_PATH>")
  endif()
endif()

find_package(PCAP)
if(NOT PCAP_FOUND)
  if(TARGET_PLATFORM_WINDOWS)
    message("Specify NPCAP Library with -DPCAP_ROOT=<NPCAP_SDK_PATH>")
  else()
    message(FATAL_ERROR "PCAP library not found!")
  endif()
endif()

# Enable the option if it's available
option(PCAPPP_HAS_PCAP_IMMEDIATE_MODE
       "Enable Pcap Has Immediate Mode (supported on libpcap>=1.5)"
       ${HAVE_PCAP_IMMEDIATE_MODE})

# Check in case user force it but it's not available
if(PCAPPP_HAS_PCAP_IMMEDIATE_MODE)
  if(NOT HAVE_PCAP_IMMEDIATE_MODE)
    message(FATAL_ERROR "PCAP library doesn't have Immediate Mode support!")
  endif()
  add_definitions(-DHAS_PCAP_IMMEDIATE_MODE)
endif()

# Enable the option if it's available
option(PCAPPP_HAS_PCAP_SET_DIRECTION "Enable Pcap Direction catpure"
       ${HAVE_PCAP_DIRECTION})

# Check in case user force it but it's not available
if(PCAPPP_HAS_PCAP_SET_DIRECTION)
  if(NOT HAVE_PCAP_DIRECTION)
    message(FATAL_ERROR "PCAP library doesn't have Direction support!")
  endif()
  add_definitions(-DHAS_SET_DIRECTION_ENABLED)
endif()

if(TARGET_PLATFORM_WINDOWS AND TARGET_COMPILER_MSVC)
  # Other hacks for VStudio
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)
  if(NOT CMAKE_USE_PTHREADS_INIT)
    message(FATAL_ERROR "Pthreads not found!")
  endif()
  set(_PCAPP_THREADS Threads::Threads)
endif()

if(PCAPPP_USE_DPDK)
  add_definitions(-DUSE_DPDK)
  find_package(dpdk)
  if(NOT dpdk_FOUND)
    message(FATAL_ERROR "Specify DPDK Library with env DPDK_DIR=<DPDK_PATH>")
  endif()
endif()

# Git Commit and Branch
add_compile_definitions(GIT_COMMIT="${GIT_HASH}")
add_compile_definitions(GIT_BRANCH="${GIT_BRANCH}")

if(PCAPPP_USE_PF_RING)
  add_definitions(-DUSE_PF_RING)
  set(PF_RING_HOME
      ""
      CACHE STRING "Sets PF_RING home directory.")
  find_package(PF_RING REQUIRED)
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE
      "Release"
      CACHE STRING "Choose the type of build." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")
endif()

if(TARGET_COMPILER_CLANG OR TARGET_COMPILER_GCC)
  add_compile_options(-Wall)
endif()

add_subdirectory(3rdParty)

if(PCAPPP_INSTALL)
  install(
    TARGETS light_pcapng
    EXPORT PcapPlusPlusTargets
    LIBRARY
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/pcapplusplus)
endif()

add_subdirectory(Packet++)
add_subdirectory(Pcap++)
add_subdirectory(Common++)

if(PCAPPP_BUILD_TESTS)
  include(CTest)

  add_subdirectory(Tests)
endif()

if(PCAPPP_BUILD_EXAMPLES)
  add_subdirectory(Examples)
endif()

if(PCAPPP_INSTALL)
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER "seladb")
  set(CPACK_PACKAGE_FILE_NAME PcapPlusPlus-v${SEMVER})

  include(CPack)

  # Generate PKG-Config
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/PcapPlusPlus.pc.in
                 ${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlus.pc @ONLY)
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlus.pc"
          DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

  # CMake helpers to compile Pcap++ with CMake
  if(LIGHT_PCAPNG_ZSTD)
    set(_PCAPPP_FIND_ZSTD "if(NOT ZSTD_FOUND)\n  find_package(ZSTD)\nendif()")
  endif()

  install(
    EXPORT PcapPlusPlusTargets
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PcapPlusPlus
    NAMESPACE PcapPlusPlus::)

  configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/PcapPlusPlusConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlusConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PcapPlusPlus)

  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlusConfigVersion.cmake
    VERSION ${VERSION}
    COMPATIBILITY AnyNewerVersion)

  # CMake helpers to compile Pcap++ with CMake
  install(
    FILES
      ${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlusConfig.cmake
      ${CMAKE_CURRENT_BINARY_DIR}/PcapPlusPlusConfigVersion.cmake
      ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/FindPCAP.cmake
      ${CMAKE_CURRENT_SOURCE_DIR}/3rdParty/LightPcapNg/LightPcapNg/cmake/FindZSTD.cmake
    COMPONENT dev
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PcapPlusPlus)
endif()
