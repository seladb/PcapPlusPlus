find_package(
  Python
  COMPONENTS Interpreter
  REQUIRED)

add_test(
  NAME ExamplesTest
  COMMAND ${Python_EXECUTABLE} -m pytest "${CMAKE_CURRENT_SOURCE_DIR}" --root-path "${PCAPPP_BINARY_EXAMPLES_DIR}"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
