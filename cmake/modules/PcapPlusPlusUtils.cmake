function(pcapp_detect_compiler TARGET)
  if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    set(${TARGET}_COMPILER_MSVC
        1
        PARENT_SCOPE)
    set(${TARGET}_COMPILER
        "msvc"
        PARENT_SCOPE)
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
  install(
    FILES "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/Find${MODULE}.cmake"
    COMPONENT devel
    DESTINATION "${PCAPPP_INSTALL_CMAKEDIR}")
endfunction()
