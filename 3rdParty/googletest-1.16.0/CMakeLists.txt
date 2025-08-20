cmake_minimum_required(VERSION 3.14)

if(WIN32)
  # Prevent overriding the parent project's compiler/linker settings.
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
endif()

# Disable installation of googletest
set(INSTALL_GTEST OFF)

add_subdirectory(googletest)
