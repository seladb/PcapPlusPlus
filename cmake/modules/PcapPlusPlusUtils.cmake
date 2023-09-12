function(pcapp_detect_compiler TARGET)
  if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    set(${TARGET}_COMPILER_MSVC
        1
        PARENT_SCOPE)
    set(${TARGET}_COMPILER
        "msvc"
        PARENT_SCOPE)
    if(MSVC_TOOLSET_VERSION EQUAL 80)
      set(MSVC_YEAR
          "2005"
          PARENT_SCOPE)
    elseif(MSVC_TOOLSET_VERSION EQUAL 90)
      set(MSVC_YEAR
          "2008"
          PARENT_SCOPE)
    elseif(MSVC_TOOLSET_VERSION EQUAL 100)
      set(MSVC_YEAR
          "2010"
          PARENT_SCOPE)
    elseif(MSVC_TOOLSET_VERSION EQUAL 110)
      set(MSVC_YEAR
          "2012"
          PARENT_SCOPE)
    elseif(MSVC_TOOLSET_VERSION EQUAL 120)
      set(MSVC_YEAR
          "2013"
          PARENT_SCOPE)
    elseif(MSVC_TOOLSET_VERSION EQUAL 140)
      set(MSVC_YEAR
          "2015"
          PARENT_SCOPE)
    elseif(MSVC_TOOLSET_VERSION EQUAL 141)
      set(MSVC_YEAR
          "2017"
          PARENT_SCOPE)
    elseif(MSVC_TOOLSET_VERSION EQUAL 142)
      set(MSVC_YEAR
          "2019"
          PARENT_SCOPE)
    elseif(MSVC_TOOLSET_VERSION EQUAL 143)
      set(MSVC_YEAR
          "2022"
          PARENT_SCOPE)
    else()
      message(WARNING "Unsupported MSVC_TOOLSET_VERSION: ${MSVC_TOOLSET_VERSION}")
      set(MSVC_YEAR
          "2099"
          PARENT_SCOPE)
    endif()
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
    set(${TARGET}_COMPILER_CLANG
        1
        PARENT_SCOPE)
    set(${TARGET}_COMPILER
        "xcode"
        PARENT_SCOPE)
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(${TARGET}_COMPILER_CLANG
        1
        PARENT_SCOPE)
    set(${TARGET}_COMPILER
        "clang"
        PARENT_SCOPE)
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    set(${TARGET}_COMPILER_GCC
        1
        PARENT_SCOPE)
    set(${TARGET}_COMPILER
        "gcc"
        PARENT_SCOPE)
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "Intel")
    set(${TARGET}_COMPILER_INTEL
        1
        PARENT_SCOPE)
    set(${TARGET}_COMPILER
        "intel"
        PARENT_SCOPE)
  else()
    message(FATAL_ERROR "Unsupported Compiler: ${CMAKE_CXX_COMPILER_ID}")
  endif()
endfunction()

function(pcapp_install_cmake_module MODULE)
  set(_PCAPPP_CONFIG_DEPENDENCY
      "${_PCAPPP_CONFIG_DEPENDENCY}if(NOT ${MODULE}_FOUND)\nfind_dependency(${MODULE})\nendif()\n"
      PARENT_SCOPE)
  install(
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/Find${MODULE}.cmake"
    COMPONENT devel
    DESTINATION "${PCAPPP_INSTALL_CMAKEDIR}")
endfunction()
