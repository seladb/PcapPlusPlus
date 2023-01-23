# ~~~
# - Try to find Fuzzer libraries
#
# Usage of this module as follows:
#
#     find_package(Fuzzer)
#
# Variables defined by this module:
#
#  Fuzzer_FOUND                System has Fuzzer include and library dirs found
#  Fuzzer_LIBRARY              The Fuzzer library
# ~~~

# OSS Fuzz provides its own fuzzing library libFuzzingEngine.a in the path defined by LIB_FUZZING_ENGINE environment
# variable. For local fuzzing, search for the libFuzzer.a library that was manually built.
find_library(
  Fuzzer_LIBRARY
  NAMES FuzzingEngine Fuzzer
  HINTS $ENV{LIB_FUZZING_ENGINE})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  Fuzzer
  REQUIRED_VARS Fuzzer_LIBRARY
  FAIL_MESSAGE "Fuzzer not found!")

if(Fuzzer_FOUND AND NOT TARGET Fuzzer::Fuzzer)
  add_library(Fuzzer::Fuzzer INTERFACE IMPORTED)
  set_property(TARGET Fuzzer::Fuzzer PROPERTY INTERFACE_LINK_LIBRARIES "${Fuzzer_LIBRARY}")
endif()
